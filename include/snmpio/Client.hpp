#ifndef SNMPIO_CLIENT_HPP
#define SNMPIO_CLIENT_HPP

#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <unordered_map>
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

  net::Awaitable<RequestResult> doRequest(Target target, Auth auth, Pdu pdu);
  net::Awaitable<WalkResult> doWalk(Target target, Auth auth, Oid base, WalkOptions options,
                                    BatchHandler onBatch);
  net::Awaitable<CollectResult> doWalkCollect(Target target, Auth auth, Oid base,
                                              WalkOptions options);

  net::Awaitable<void> receiveLoop(net::UdpSocket* sock);
  void deliverV2c(std::span<const std::byte> datagram, const net::UdpEndpoint& from);
  void deliverV3(std::span<const std::byte> datagram, const net::UdpEndpoint& from);
  [[nodiscard]] bool timely(const net::UdpEndpoint& from, const UsmParameters& security) const;
  void observeEngineTime(const net::UdpEndpoint& from, const UsmParameters& security);
  static RequestResult toResult(const Pdu& response);
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
    std::string community;  // v2c: quoted back, and checked
    bool v3 = false;
    bool authRequired = false;
    AuthProtocol authProtocol = AuthProtocol::None;
    PrivProtocol privProtocol = PrivProtocol::None;
    Octets authKey;   // the Localized Key this exchange is authenticated with
    Octets privKey;   // and the one it is encrypted with, at authPriv
    Octets engineId;  // the Authoritative Engine addressed; empty while discovering
    std::int32_t requestId = 0;
    Pdu response;
    UsmParameters security;  // what the reply's security parameters said
    bool answered = false;
    // Whether the reply's digest was checked and matched. False for an unauthenticated Report,
    // which the protocol obliges us to accept and which therefore must not be trusted with
    // anything beyond asking us to discover the Engine again.
    bool replyAuthenticated = false;
  };

  // What we know about one Authoritative Engine, and when we learnt it. The Engine's current time
  // is `time` advanced by the local clock since `at` -- the Time Window is checked against that
  // projection, never against a raw cached number.
  struct EngineState {
    Octets engineId;
    std::int32_t boots = 0;
    std::int32_t time = 0;
    std::chrono::steady_clock::time_point at;
    // Whether the pair above came from an authenticated exchange. A noAuthNoPriv discovery learns
    // the engineID and nothing trustworthy about its clock, so the first authenticated request
    // against the same Engine still has to synchronise.
    bool timeSynced = false;
  };

  // A discovery in flight. The timer is an event, not a deadline: waiters park on it and the
  // discovering coroutine cancels it to wake them all. Same trick as Pending's.
  struct Discovery {
    explicit Discovery(const net::Executor& ex) : done(ex) {}
    net::SteadyTimer done;
    net::ErrorCode ec;
    bool finished = false;
  };

  std::int32_t nextId() noexcept;

  // The shared half of every exchange: send, wait, retransmit, and observe cancellation. Returns
  // an empty ErrorCode when `pending` was answered.
  net::Awaitable<net::ErrorCode> transact(Target target, std::vector<std::byte> datagram,
                                          std::int32_t key, std::shared_ptr<Pending> pending);

  // RFC 3414 section 4, in two phases: the engineID, and then -- only when authenticating -- the
  // boots/time pair. At most one runs per Target; anything else arriving waits on it.
  net::Awaitable<net::ErrorCode> ensureEngine(Target target, Credentials creds);
  net::Awaitable<void> runDiscovery(Target target, Credentials creds,
                                    std::shared_ptr<Discovery> discovery);
  net::Awaitable<net::ErrorCode> discoverEngine(Target target, Credentials creds);
  // The Engine currently believed to answer at this endpoint, or nullptr if none is known.
  EngineState* engineAt(const net::UdpEndpoint& endpoint);

  // Cached because the derivation is a megabyte hash and deliberately expensive (CONTEXT.md) --
  // twice over for Reeder, whose key extension is a second one.
  const Octets* localizedKey(const Credentials& creds, const Octets& engineId, net::ErrorCode& ec);
  const Octets* localizedPrivacyKey(const Credentials& creds, const Octets& engineId,
                                    net::ErrorCode& ec);

  // What a Report means for the request that provoked it: an ErrorCode to fail with, or nothing
  // when it named something we can act on and ask again about.
  std::optional<net::ErrorCode> handleReport(const net::UdpEndpoint& from, const Pending& pending,
                                             bool mayRetry);

  net::Awaitable<RequestResult> doRequestV2c(Target target, Community community, Pdu pdu);
  net::Awaitable<RequestResult> doRequestV3(Target target, Credentials creds, Pdu pdu);

  net::Strand m_strand;
  std::optional<net::UdpSocket> m_v4;
  std::optional<net::UdpSocket> m_v6;
  std::unordered_map<std::int32_t, std::shared_ptr<Pending>> m_pending;
  // Keyed on engineID with a separate endpoint->engineID index, as ADR-0003 requires: one Engine
  // reachable at two Targets is one cache entry, discovered once. The in-flight map below is keyed
  // on the endpoint of necessity -- learning which Engine is there is what discovery is for.
  std::map<Octets, EngineState> m_engines;
  std::map<net::UdpEndpoint, Octets> m_engineAt;
  std::map<net::UdpEndpoint, std::shared_ptr<Discovery>> m_discovering;
  // (engineID, hash, secret, privacy protocol) -- ADR-0003's (master key, engineID), spelled as
  // the things the master key is derived from so that nothing has to derive it to look one up.
  // The privacy protocol is part of the key rather than of the value because it decides how far
  // the derivation is extended: PrivProtocol::None is the authentication key's row.
  std::map<std::tuple<Octets, AuthProtocol, std::string, PrivProtocol>, Octets> m_keys;
  // One counter for both the v3 msgID and the PDU request-id, so that the two protocols cannot
  // collide in m_pending -- which is keyed on the msgID for v3, as CONTEXT.md requires, because a
  // message we cannot open must still be attributable.
  std::int32_t m_nextId;
  bool m_stopped = false;
};

}  // namespace snmpio

#endif  // SNMPIO_CLIENT_HPP
