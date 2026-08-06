#ifndef SNMPIO_CLIENT_HPP
#define SNMPIO_CLIENT_HPP

#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <snmpio/Oid.hpp>
#include <snmpio/Pdu.hpp>
#include <snmpio/Target.hpp>
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
// at length why not. Everything internal lives on the Client's own strand, so initiating an
// operation from any thread is safe and none of the state needs locking.
//
// Completion follows the Asio convention throughout: every operation takes a completion token and
// reports failure as an ErrorCode. Three categories can show up there -- the system's, for socket
// faults; snmpio's, for timeouts and malformed Responses; and snmp-agent's, for an error-status
// the Agent itself returned.
//
// The Client must outlive its outstanding operations. Call stop() and let the io_context drain
// before destroying it.
class Client {
 public:
  // Receives each batch of a streaming Walk. Returning false stops the Walk, which then completes
  // with Errc::WalkIncomplete -- a partially consumed Walk must never look like a whole one
  // (ADR-0004). Called on the Client's strand.
  using BatchHandler = std::function<bool(std::span<const Varbind>)>;

  explicit Client(const net::Executor& ex);
  // Defaulted, and stop() is deliberately not called here -- see the note on stop().
  ~Client() = default;

  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;
  Client(Client&&) = delete;
  Client& operator=(Client&&) = delete;

  [[nodiscard]] net::Executor getExecutor() const { return m_strand; }

  // Closes the sockets and fails every outstanding request with Errc::ClientStopped. This is not
  // done from the destructor on purpose: the cleanup runs on the strand, so a destructor that
  // scheduled it would be scheduling work against an object that no longer exists.
  void stop();

  // GET: fetch each named instance. Completion: void(ErrorCode, Response).
  template <typename Token>
  auto asyncGet(Target target, Community community, std::vector<Oid> oids, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), std::move(community),
                  makePdu(PduType::Get, toVarbinds(std::move(oids)))),
        std::forward<Token>(token));
  }

  // GETNEXT: the lexicographic successor of each named OID. Completion: void(ErrorCode, Response).
  template <typename Token>
  auto asyncGetNext(Target target, Community community, std::vector<Oid> oids, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), std::move(community),
                  makePdu(PduType::GetNext, toVarbinds(std::move(oids)))),
        std::forward<Token>(token));
  }

  // GETBULK: the first nonRepeaters OIDs get one successor each, the rest get maxRepetitions of
  // them. Completion: void(ErrorCode, Response).
  template <typename Token>
  auto asyncGetBulk(Target target, Community community, std::vector<Oid> oids,
                    std::int32_t nonRepeaters, std::int32_t maxRepetitions, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), std::move(community),
                  makeBulkPdu(toVarbinds(std::move(oids)), nonRepeaters, maxRepetitions)),
        std::forward<Token>(token));
  }

  // SET. Completion: void(ErrorCode, Response); on rejection the ErrorCode is the Agent's
  // error-status and Response::errorIndex names the Varbind it objected to.
  template <typename Token>
  auto asyncSet(Target target, Community community, std::vector<Varbind> varbinds, Token&& token) {
    return spawn<void(net::ErrorCode, Response)>(
        doRequest(std::move(target), std::move(community),
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
    return spawn<void(net::ErrorCode)>(doWalk(std::move(target), std::move(community),
                                              std::move(base), options, std::move(onBatch)),
                                       std::forward<Token>(token));
  }

  // The buffering convenience over asyncWalk. Completion: void(ErrorCode, std::vector<Varbind>).
  // An incomplete Walk still hands back what it collected, alongside Errc::WalkIncomplete.
  template <typename Token>
  auto asyncWalkCollect(Target target, Community community, Oid base, WalkOptions options,
                        Token&& token) {
    return spawn<void(net::ErrorCode, std::vector<Varbind>)>(
        doWalkCollect(std::move(target), std::move(community), std::move(base), options),
        std::forward<Token>(token));
  }

 private:
  // Named because a coroutine's co_return cannot deduce a braced tuple.
  using RequestResult = std::tuple<net::ErrorCode, Response>;
  using WalkResult = std::tuple<net::ErrorCode>;
  using CollectResult = std::tuple<net::ErrorCode, std::vector<Varbind>>;

  static std::vector<Varbind> toVarbinds(std::vector<Oid> oids);
  static Pdu makePdu(PduType type, std::vector<Varbind> varbinds);
  static Pdu makeBulkPdu(std::vector<Varbind> varbinds, std::int32_t nonRepeaters,
                         std::int32_t maxRepetitions);

  net::Awaitable<RequestResult> doRequest(Target target, Community community, Pdu pdu);
  net::Awaitable<WalkResult> doWalk(Target target, Community community, Oid base,
                                    WalkOptions options, BatchHandler onBatch);
  net::Awaitable<CollectResult> doWalkCollect(Target target, Community community, Oid base,
                                              WalkOptions options);

  net::Awaitable<void> receiveLoop(net::UdpSocket* sock);
  net::UdpSocket* socketFor(const net::UdpEndpoint& to, net::ErrorCode& ec);

  // Runs coro on the strand and delivers its result tuple through the completion token, on the
  // token's own executor rather than ours -- which is the whole reason this is not a bare
  // co_spawn at each call site.
  // Token by value, not by forwarding reference: async_initiate binds it as an lvalue.
  template <typename Signature, typename Result, typename Token>
  auto spawn(net::Awaitable<Result> coro, Token token) {
    return net::asio::async_initiate<Token, Signature>(
        [this](auto handler, net::Awaitable<Result> c) {
          auto ex = net::asio::get_associated_executor(handler, m_strand);
          // Read before the handler is moved from. Without this the caller's cancellation slot
          // stops at the token and never reaches the coroutine, which then cannot be cancelled.
          auto slot = net::asio::get_associated_cancellation_slot(handler);
          net::asio::co_spawn(m_strand, std::move(c),
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

  // One outstanding request. The timer is doing double duty: it is the retransmission deadline,
  // and cancelling it early is how the receive loop wakes the waiting coroutine.
  struct Pending {
    explicit Pending(const net::Executor& ex) : timer(ex) {}
    net::SteadyTimer timer;
    net::UdpEndpoint from;  // only a Response from the Target we asked counts
    std::string community;
    Pdu response;
    bool answered = false;
  };

  net::Strand m_strand;
  std::optional<net::UdpSocket> m_v4;
  std::optional<net::UdpSocket> m_v6;
  std::unordered_map<std::int32_t, std::shared_ptr<Pending>> m_pending;
  std::int32_t m_nextRequestId;
  bool m_stopped = false;
};

}  // namespace snmpio

#endif  // SNMPIO_CLIENT_HPP
