#ifndef SNMPIO_CLIENT_HPP
#define SNMPIO_CLIENT_HPP

#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <snmpio/Oid.hpp>
#include <snmpio/Pdu.hpp>
#include <snmpio/Target.hpp>
#include <snmpio/Usm.hpp>
#include <snmpio/V3Message.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/detail/Net.hpp>

namespace snmpio {

// What a completed request hands back.
struct Response {
  std::vector<Varbind> varbinds;
  // 1-based index of the Varbind the Agent objected to, and only meaningful when the completion's
  // ErrorCode is in the snmp-agent category (i.e. came from an ErrorStatus). Zero otherwise.
  std::int32_t errorIndex = 0;
};

// The SNMPv2c Command Generator.
//
// One Client owns the transport and the caches; there is no session type, and ADR-0003 explains
// at length why not. Everything internal lives on the Client's own strand -- all but the flag
// Stopping sets, an atomic (ADR-0009) -- so initiating an operation from any thread is safe and
// none of the state needs locking.
//
// Completion follows the Asio convention throughout: every operation takes a completion token and
// reports failure as an ErrorCode. Three categories can show up there -- the system's, for socket
// faults; snmpio's, for timeouts and malformed Responses; and snmp-agent's, for an error-status
// the Agent itself returned.
//
// Cancellation means one thing for a request, whichever wait it happens to be sitting in --
// awaiting a reply, between retransmissions, or queued behind an Engine Discovery. A `terminal`
// signal drops it at once, reply in hand or not; a `total` one stops it cleanly, retransmitting no
// further but still taking a reply already on its way, which means waiting out the deadline of the
// exchange in flight. Both complete with `operation_aborted` where no reply counted, never with
// Errc::Timeout -- the Target's silence is not why the request ended.
// Cancelling one request queued behind a discovery leaves the discovery and its other waiters
// running (ADR-0003). A Walk reads `total` differently, and ADR-0004 says why -- see asyncWalk.
//
// Lifetime follows Asio's own I/O objects (ADR-0009): a Client may be destroyed with operations
// outstanding, from any thread, including from inside one of its own completion handlers.
// Destroying it stops it, so each outstanding operation still completes, exactly once, with
// Errc::ClientStopped. The only rule left to the caller is Asio's: the io_context must outlive the
// work scheduled on it, which includes this Client's.
//
// Two consequences follow, the same ones a socket has. Completion handlers run *after* the
// destructor has returned, so a handler must not reach back into the Client or into an owner that
// went with it. And "exactly once" holds while the io_context runs: one destroyed without being
// run destroys the handlers it holds instead of invoking them.
class Client {
 public:
  // Receives each batch of a streaming Walk. Returning false stops the Walk, which then completes
  // with Errc::WalkIncomplete -- a partially consumed Walk must never look like a whole one
  // (ADR-0004). Called on the Client's strand, and never once Stopping has begun there: a stop()
  // or a destruction on the strand -- from inside a handler bound to it, say -- or one that
  // happens-before the strand reaches the batch. One on another thread can race a batch the
  // strand is already delivering, and ~Client does not wait for it (ADR-0009), so a handler must
  // not capture state that thread frees straight after destroying the Client.
  using BatchHandler = std::function<bool(std::span<const Varbind>)>;

  explicit Client(const net::Executor& ex);
  // Stops the Client (see stop()) and returns without waiting for anything: the outstanding
  // operations complete later, on their own executors.
  ~Client();

  // Neither copyable nor movable (ADR-0009). A caller who needs to move one holds a
  // std::unique_ptr<Client>.
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;
  Client(Client&&) = delete;
  Client& operator=(Client&&) = delete;

  [[nodiscard]] net::Executor getExecutor() const { return m_strand; }

  // Stopping: refuses new work, closes the sockets and fails every outstanding operation with
  // Errc::ClientStopped. Idempotent, safe from any thread, and harmless before the destructor,
  // which does the same. An operation initiated afterwards completes with Errc::ClientStopped too.
  // The Client also stops itself when a receive loop throws, before the exception leaves
  // io_context::run(): that loop serves every Target on its socket (ADR-0009's amendment).
  void stop();

  // GET: fetch each named instance. Completion: void(ErrorCode, Response).
  template <typename Token>
  auto asyncGet(Target target, Community community, std::vector<Oid> oids, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), Auth{std::move(community)},
                  makePdu(PduType::Get, toVarbinds(std::move(oids)))),
        std::forward<Token>(token));
  }

  // GETNEXT: the lexicographic successor of each named OID. Completion: void(ErrorCode, Response).
  template <typename Token>
  auto asyncGetNext(Target target, Community community, std::vector<Oid> oids, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), Auth{std::move(community)},
                  makePdu(PduType::GetNext, toVarbinds(std::move(oids)))),
        std::forward<Token>(token));
  }

  // GETBULK: the first nonRepeaters OIDs get one successor each, the rest get maxRepetitions of
  // them. Completion: void(ErrorCode, Response).
  template <typename Token>
  auto asyncGetBulk(Target target, Community community, std::vector<Oid> oids,
                    std::int32_t nonRepeaters, std::int32_t maxRepetitions, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), Auth{std::move(community)},
                  makeBulkPdu(toVarbinds(std::move(oids)), nonRepeaters, maxRepetitions)),
        std::forward<Token>(token));
  }

  // SET. Completion: void(ErrorCode, Response); on rejection the ErrorCode is the Agent's
  // error-status and Response::errorIndex names the Varbind it objected to.
  template <typename Token>
  auto asyncSet(Target target, Community community, std::vector<Varbind> varbinds, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), Auth{std::move(community)},
                  makePdu(PduType::Set, std::move(varbinds))),
        std::forward<Token>(token));
  }

  // Walk a Subtree, delivering each batch to onBatch as it arrives (ADR-0004: streaming is the
  // core, collecting is the wrapper -- a Walk has no bounded size). Completion: void(ErrorCode).
  //
  // Cancellation is split: a `total` signal finishes the in-flight batch and completes with
  // Errc::WalkIncomplete; a `terminal` one drops everything immediately.
  template <typename Token>
  auto asyncWalk(Target target, Community community, Oid base, WalkOptions options,
                 BatchHandler onBatch, Token&& token) {
    return spawn<void(net::ErrorCode)>(doWalk(std::move(target), Auth{std::move(community)},
                                              std::move(base), options, std::move(onBatch)),
                                       std::forward<Token>(token));
  }

  // The buffering convenience over asyncWalk. Completion: void(ErrorCode, std::vector<Varbind>).
  // An incomplete Walk still hands back what it collected, alongside Errc::WalkIncomplete.
  template <typename Token>
  auto asyncWalkCollect(Target target, Community community, Oid base, WalkOptions options,
                        Token&& token) {
    return spawn<void(net::ErrorCode, std::vector<Varbind>)>(
        doWalkCollect(std::move(target), Auth{std::move(community)}, std::move(base), options),
        std::forward<Token>(token));
  }

  // The same six operations over SNMPv3. `Credentials` in place of a `Community` is the whole of
  // the difference at the call site: same completion signatures, same three error categories.
  //
  // Engine Discovery, time synchronisation and Report routing happen underneath and never surface.
  // The first request against an unknown Engine simply costs extra round trips, and requests
  // issued while that is in flight queue behind it rather than each probing separately.
  //
  // At authPriv the Credentials name the privacy protocol as well; an authPriv level with none
  // named fails with Errc::UnsupportedPrivProtocol rather than being sent in the clear.
  //
  // Cancelling a request while it is queued behind a discovery means exactly what cancelling it
  // in any other wait means -- see the rule above -- and leaves the discovery and everything else
  // waiting on it running (ADR-0003).
  template <typename Token>
  auto asyncGet(Target target, Credentials credentials, std::vector<Oid> oids, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), Auth{std::move(credentials)},
                  makePdu(PduType::Get, toVarbinds(std::move(oids)))),
        std::forward<Token>(token));
  }

  template <typename Token>
  auto asyncGetNext(Target target, Credentials credentials, std::vector<Oid> oids, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), Auth{std::move(credentials)},
                  makePdu(PduType::GetNext, toVarbinds(std::move(oids)))),
        std::forward<Token>(token));
  }

  template <typename Token>
  auto asyncGetBulk(Target target, Credentials credentials, std::vector<Oid> oids,
                    std::int32_t nonRepeaters, std::int32_t maxRepetitions, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), Auth{std::move(credentials)},
                  makeBulkPdu(toVarbinds(std::move(oids)), nonRepeaters, maxRepetitions)),
        std::forward<Token>(token));
  }

  template <typename Token>
  auto asyncSet(Target target, Credentials credentials, std::vector<Varbind> varbinds,
                Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), Auth{std::move(credentials)},
                  makePdu(PduType::Set, std::move(varbinds))),
        std::forward<Token>(token));
  }

  template <typename Token>
  auto asyncWalk(Target target, Credentials credentials, Oid base, WalkOptions options,
                 BatchHandler onBatch, Token&& token) {
    return spawn<void(net::ErrorCode)>(doWalk(std::move(target), Auth{std::move(credentials)},
                                              std::move(base), options, std::move(onBatch)),
                                       std::forward<Token>(token));
  }

  template <typename Token>
  auto asyncWalkCollect(Target target, Credentials credentials, Oid base, WalkOptions options,
                        Token&& token) {
    return spawn<void(net::ErrorCode, std::vector<Varbind>)>(
        doWalkCollect(std::move(target), Auth{std::move(credentials)}, std::move(base), options),
        std::forward<Token>(token));
  }

 private:
  // Which Credentials a request travels under. A variant rather than two parallel stacks: from the
  // retransmission loop down the two protocols are identical, and the only places that care are
  // where the datagram is built and where a reply is matched to it.
  using Auth = std::variant<Community, Credentials>;

  // Named because a coroutine's co_return cannot deduce a braced tuple.
  using RequestResult = std::tuple<net::ErrorCode, Response>;
  using WalkResult = std::tuple<net::ErrorCode>;
  using CollectResult = std::tuple<net::ErrorCode, std::vector<Varbind>>;

  static std::vector<Varbind> toVarbinds(std::vector<Oid> oids);
  static Pdu makePdu(PduType type, std::vector<Varbind> varbinds);
  static Pdu makeBulkPdu(std::vector<Varbind> varbinds, std::int32_t nonRepeaters,
                         std::int32_t maxRepetitions);

  // Not coroutines themselves: each hands back one of Impl's, which owns a share of the state, so
  // nothing that runs later holds a pointer to this Client.
  net::Awaitable<RequestResult> doRequest(Target target, Auth auth, Pdu pdu);
  net::Awaitable<WalkResult> doWalk(Target target, Auth auth, Oid base, WalkOptions options,
                                    BatchHandler onBatch);
  net::Awaitable<CollectResult> doWalkCollect(Target target, Auth auth, Oid base,
                                              WalkOptions options);

  // Runs coro on the strand and delivers its result tuple through the completion token, on the
  // token's own executor rather than ours -- which is the whole reason this is not a bare
  // co_spawn at each call site.
  // Token by value, not by forwarding reference: async_initiate binds it as an lvalue.
  //
  // The initiation holds the strand by value and never `this`: a deferred token may initiate after
  // the Client is gone, and the coroutine owns everything else it needs.
  template <typename Signature, typename Result, typename Token>
  auto spawn(net::Awaitable<Result> coro, Token token) {
    return net::asio::async_initiate<Token, Signature>(
        [strand = m_strand](auto handler, net::Awaitable<Result> c) {
          const auto ex = net::asio::get_associated_executor(handler, strand);
          // Read before the handler is moved from. Without this the caller's cancellation slot
          // stops at the token and never reaches the coroutine, which then cannot be cancelled.
          const auto slot = net::asio::get_associated_cancellation_slot(handler);
          net::asio::co_spawn(strand, std::move(c),
                              net::asio::bind_cancellation_slot(
                                  slot, net::asio::bind_executor(
                                            ex, [h = std::move(handler)](
                                                    const std::exception_ptr& e, Result r) mutable {
                                              // Nothing in the operation throws by design, so this
                                              // is bad_alloc or a programming error. Letting it out
                                              // of io_context::run() is louder than inventing an
                                              // ErrorCode for it.
                                              if (e) std::rethrow_exception(e);
                                              std::apply(std::move(h), std::move(r));
                                            })));
        },
        token, std::move(coro));
  }

  // Everything the Client knows, and the coroutines that act on it, co-owned by each of those
  // coroutines (ADR-0009). Defined in Client.cpp.
  class Impl;

  // The same strand Impl runs on, kept here as well so that spawn's initiation can hold it without
  // reaching through `this` or m_impl.
  net::Strand m_strand;
  std::shared_ptr<Impl> m_impl;
};

}  // namespace snmpio

#endif  // SNMPIO_CLIENT_HPP
