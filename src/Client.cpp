#include <snmpio/Client.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <variant>

namespace snmpio {
namespace {

// A UDP datagram cannot exceed this, so a buffer this size can never truncate a Response -- which
// matters, because a silently truncated message would decode as malformed rather than as too big.
constexpr std::size_t maxDatagram = 65535;

using net::asio::redirect_error;
using net::asio::use_awaitable;

// RFC 3414 section 5: the six usmStats counters, under snmpUsmMIB. A Report names exactly one of
// them, and its leaf is the whole of what the Report says.
const Oid& usmStatsPrefix() {
  // Function-local rather than namespace-scope: constructing an Oid allocates, and an allocation
  // failure during static initialisation is one nothing can catch.
  static const Oid prefix{1, 3, 6, 1, 6, 3, 15, 1, 1};
  return prefix;
}
constexpr std::uint32_t usmStatsUnsupportedSecLevels = 1;
constexpr std::uint32_t usmStatsNotInTimeWindows = 2;
constexpr std::uint32_t usmStatsUnknownUserNames = 3;
constexpr std::uint32_t usmStatsUnknownEngineIds = 4;
constexpr std::uint32_t usmStatsWrongDigests = 5;
constexpr std::uint32_t usmStatsDecryptionErrors = 6;

// A key that may not exist yet, as the span the encoder takes.
std::span<const std::byte> keySpan(const Octets* key) noexcept {
  return key != nullptr ? std::span<const std::byte>(*key) : std::span<const std::byte>();
}

// RFC 3414 section 2.2.3. 150 seconds either side, and an Engine that has booted this many times
// can no longer be trusted for timeliness at all.
constexpr std::int32_t timeWindowSeconds = 150;
// RFC 3414 section 2.2.3: an Engine that has booted this many times can no longer be trusted for
// timeliness at all. It is also the ceiling on the time field, which shares the range.
constexpr std::int32_t bootsCeiling = std::numeric_limits<std::int32_t>::max();
constexpr std::int64_t timeCeiling = std::numeric_limits<std::int32_t>::max();

// A Report's first Varbind names the counter it is reporting. Returns the leaf, or nothing if this
// is not a shape we recognise.
std::optional<std::uint32_t> usmStatsCounter(const Pdu& report) {
  if (report.varbinds.empty()) return std::nullopt;
  const Oid& prefix = usmStatsPrefix();
  const Oid& name = report.varbinds.front().name;
  if (!prefix.isPrefixOf(name) || name.size() <= prefix.size()) return std::nullopt;
  return *(name.begin() + static_cast<std::ptrdiff_t>(prefix.size()));
}

// The one Report that is about the Engine's clock, and so the one that may carry a pair we take.
bool reportsNotInTimeWindows(const Pdu& pdu) {
  return pdu.type == PduType::Report && usmStatsCounter(pdu) == usmStatsNotInTimeWindows;
}

net::ErrorCode reportError(std::optional<std::uint32_t> counter) {
  if (!counter) return make_error_code(Errc::UnexpectedReport);
  switch (*counter) {
    case usmStatsUnsupportedSecLevels:
      return make_error_code(Errc::UnsupportedSecurityLevel);
    case usmStatsNotInTimeWindows:
      return make_error_code(Errc::NotInTimeWindow);
    case usmStatsUnknownUserNames:
      return make_error_code(Errc::UnknownUserName);
    case usmStatsUnknownEngineIds:
      return make_error_code(Errc::UnknownEngineId);
    case usmStatsWrongDigests:
      return make_error_code(Errc::AuthFailed);
    case usmStatsDecryptionErrors:
      return make_error_code(Errc::DecryptionError);
    default:
      return make_error_code(Errc::UnexpectedReport);
  }
}

// A Get with no Varbinds: what each phase of Engine Discovery sends to provoke a Report, carrying
// no request for data because it expects none to be answered.
ScopedPdu discoveryScopedPdu(std::int32_t requestId, Octets contextEngineId) {
  ScopedPdu s;
  s.contextEngineId = std::move(contextEngineId);
  s.pdu.type = PduType::Get;
  s.pdu.requestId = requestId;
  return s;
}

std::int32_t randomRequestId() {
  // RFC 3416 does not require unpredictability, but a fixed starting point makes a restarted
  // Client collide with in-flight Responses from its previous life. Positive so the encoding
  // stays short and the value reads plainly in a capture.
  std::random_device rd;
  std::uniform_int_distribution<std::int32_t> dist(1, std::numeric_limits<std::int32_t>::max());
  return dist(rd);
}

// The completion of the two coroutines no operation awaits: the receive loop and an Engine
// Discovery. Neither throws by design, so an exception here is bad_alloc or a programming error,
// and it leaves run() the way spawn lets one out of an operation. `detached` would swallow it,
// and leave every request that loop or that discovery was serving waiting forever, in silence.
constexpr auto rethrow = [](const std::exception_ptr& e) {
  if (e) std::rethrow_exception(e);
};

}  // namespace

// Everything the Client knows, shared by every coroutine working on it (ADR-0009), so that the
// Client itself can go at any time and the coroutines still have something to finish against.
//
// Every coroutine here that touches the state is a member taking `Ref self` first, and that
// parameter is the whole of how the frame keeps `this` alive across its suspensions (C++ Core
// Guidelines CP.53): the body reaches the members through `this` as usual, and passes `self` on to
// each coroutine it starts. Nothing holds a pointer to the Client itself. The cycle this makes --
// the state owns the sockets and timers, and their pending waits own the frames -- is what Stopping
// breaks, by closing the one and cancelling the other.
class Client::Impl {
 public:
  using Ref = std::shared_ptr<Impl>;

  explicit Impl(net::Strand strand) : m_strand(std::move(strand)), m_nextId(randomRequestId()) {}

  // Stopping, from any thread. The flag is set at once, and the strand checks it before each
  // exchange and each batch, so nothing begins once the strand has seen it; the cleanup that needs
  // the strand follows on it. From another thread, that is not the same as "after this returns":
  // the strand may already be past a check, mid-send or mid-batch (see BatchHandler).
  static void stop(const Ref& self) {
    if (self->m_stopping.exchange(true)) return;
    // Dispatched rather than posted: stop() is usually the last thing before the io_context
    // drains, and a posted cleanup would never run. Owning `self`, because the Client that asked
    // may be gone by the time it runs.
    net::asio::dispatch(self->m_strand, [self] { self->finishStopping(); });
  }

  net::Awaitable<RequestResult> doRequest(Ref self, Target target, Auth auth, Pdu pdu);
  net::Awaitable<WalkResult> doWalk(Ref self, Target target, Auth auth, Oid base,
                                    WalkOptions options, BatchHandler onBatch);
  net::Awaitable<CollectResult> doWalkCollect(Ref self, Target target, Auth auth, Oid base,
                                              WalkOptions options);

 private:
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
    // Whether the accepted reply's digest was checked and matched -- that datagram's, never an
    // earlier one dropped on the way. False for an unauthenticated Report, which the protocol
    // obliges us to accept and which therefore must not be trusted with anything beyond failing
    // this exchange or asking us to discover the Engine again.
    bool replyAuthenticated = false;
    // Engine Discovery's time-sync phase, the one exchange an unsigned notInTimeWindows Report is
    // dropped from rather than admitted: a genuine one there is always signed (see deliverV3).
    bool timeSyncPhase = false;
    // Why the last unusable reply was discarded, or empty. Read only at expiry (ADR-0008).
    net::ErrorCode dropReason;
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
    // What the discovery threw, if it did: each waiter rethrows it, so that every request it was
    // serving leaves run() the way the discovery itself does, rather than waiting forever.
    std::exception_ptr failure;
  };

  // Stopping's second half, on the strand: closes the sockets, which ends the receive loops, and
  // wakes everything waiting, which then finds the flag set and completes with ClientStopped.
  void finishStopping();

  std::int32_t nextId() noexcept;

  net::UdpSocket* socketFor(const Ref& self, const net::UdpEndpoint& to, net::ErrorCode& ec);
  net::Awaitable<void> receiveLoop(Ref self, net::UdpSocket* sock);
  void deliverV2c(std::span<const std::byte> datagram, const net::UdpEndpoint& from);
  void deliverV3(std::span<const std::byte> datagram, const net::UdpEndpoint& from);
  [[nodiscard]] bool timely(const net::UdpEndpoint& from, const UsmParameters& security) const;
  void observeEngineTime(const net::UdpEndpoint& from, const UsmParameters& security);
  static RequestResult toResult(const Pdu& response);

  // The shared half of every exchange: send, wait, retransmit, and observe cancellation. Returns
  // an empty ErrorCode when `pending` was answered.
  net::Awaitable<net::ErrorCode> transact(Ref self, Target target, std::vector<std::byte> datagram,
                                          std::int32_t key, std::shared_ptr<Pending> pending);

  // RFC 3414 section 4, in two phases: the engineID, and then -- only when authenticating -- the
  // boots/time pair. At most one runs per Target; anything else arriving waits on it.
  net::Awaitable<net::ErrorCode> ensureEngine(Ref self, Target target, Credentials creds);
  net::Awaitable<void> runDiscovery(Ref self, Target target, Credentials creds,
                                    std::shared_ptr<Discovery> discovery);
  net::Awaitable<net::ErrorCode> discoverEngine(Ref self, Target target, Credentials creds);
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

  // Observe both cancellation types rather than throwing on either, once per operation.
  static net::Awaitable<void> observeBothCancellationTypes();

  net::Awaitable<RequestResult> doRequestV2c(Ref self, Target target, Community community, Pdu pdu);
  net::Awaitable<RequestResult> doRequestV3(Ref self, Target target, Credentials creds, Pdu pdu);

  net::Strand m_strand;
  // The one member that is not the strand's alone: written once, by stop() on whichever thread
  // called it, and read on the strand. That is what lets Stopping take effect before the strand
  // gets round to the cleanup.
  std::atomic<bool> m_stopping = false;
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
};

Client::Client(const net::Executor& ex)
    : m_strand(net::asio::make_strand(ex)), m_impl(std::make_shared<Impl>(m_strand)) {}

// ADR-0009. Never waits: this may be running on the strand, inside one of the Client's own
// completions, or with the io_context not running at all, and waiting would deadlock in each.
//
// The cleanup dispatched to the strand may allocate, and a bad_alloc there terminates, as it would
// from any destructor. Catching it would be worse: a Client stopped only half-way keeps its receive
// loops, and with them a run() that never returns, without a word.
// NOLINTNEXTLINE(bugprone-exception-escape): terminating is the intended outcome, as above.
Client::~Client() {
  Impl::stop(m_impl);
}

void Client::stop() {
  Impl::stop(m_impl);
}

net::Awaitable<Client::RequestResult> Client::doRequest(Target target, Auth auth, Pdu pdu) {
  return m_impl->doRequest(m_impl, std::move(target), std::move(auth), std::move(pdu));
}

net::Awaitable<Client::WalkResult> Client::doWalk(Target target, Auth auth, Oid base,
                                                  WalkOptions options, BatchHandler onBatch) {
  return m_impl->doWalk(m_impl, std::move(target), std::move(auth), std::move(base), options,
                        std::move(onBatch));
}

net::Awaitable<Client::CollectResult> Client::doWalkCollect(Target target, Auth auth, Oid base,
                                                            WalkOptions options) {
  return m_impl->doWalkCollect(m_impl, std::move(target), std::move(auth), std::move(base),
                               options);
}

void Client::Impl::finishStopping() {
  // close() hands back the same ErrorCode it writes to the out-parameter; std::ignore says the
  // discard is deliberate rather than forgotten.
  net::ErrorCode ignored;
  if (m_v4) std::ignore = m_v4->close(ignored);
  if (m_v6) std::ignore = m_v6->close(ignored);
  for (auto& [id, pending] : m_pending) pending->timer.cancel();
  // Anything parked on a discovery is waiting on a reply that will now never come.
  for (auto& [endpoint, discovery] : m_discovering) discovery->done.cancel();
}

std::int32_t Client::Impl::nextId() noexcept {
  const std::int32_t id = m_nextId;
  m_nextId = m_nextId == std::numeric_limits<std::int32_t>::max() ? 1 : m_nextId + 1;
  return id;
}

std::vector<Varbind> Client::toVarbinds(std::vector<Oid> oids) {
  std::vector<Varbind> out;
  out.reserve(oids.size());
  // In place rather than push_back of a temporary -- see the note in tests/TestClient.cpp.
  for (auto& oid : oids) out.emplace_back(std::move(oid), null);
  return out;
}

Pdu Client::makePdu(PduType type, std::vector<Varbind> varbinds) {
  Pdu p;
  p.type = type;
  p.varbinds = std::move(varbinds);
  return p;
}

Pdu Client::makeBulkPdu(std::vector<Varbind> varbinds, std::int32_t nonRepeaters,
                        std::int32_t maxRepetitions) {
  Pdu p = makePdu(PduType::GetBulk, std::move(varbinds));
  p.setBulkParams(nonRepeaters, maxRepetitions);
  return p;
}

net::UdpSocket* Client::Impl::socketFor(const Ref& self, const net::UdpEndpoint& to,
                                        net::ErrorCode& ec) {
  const bool v6 = to.address().is_v6();
  auto& slot = v6 ? m_v6 : m_v4;
  if (slot) return &*slot;

  slot.emplace(m_strand);
  std::ignore = slot->open(v6 ? net::Udp::v6() : net::Udp::v4(), ec);
  if (ec) {
    slot.reset();
    return nullptr;
  }
  // One receive loop per socket, running until the socket closes. It outlives every individual
  // request, which is the point: Responses are matched by request-id, not by who is waiting.
  net::asio::co_spawn(m_strand, receiveLoop(self, &*slot), rethrow);
  return &*slot;
}

// By pointer, not by reference: a coroutine parameter that is a reference is a dangling hazard as
// a rule, and the rule is worth keeping even where -- as here -- the socket is a member, which
// `self` keeps alive for as long as the loop runs.
net::Awaitable<void> Client::Impl::receiveLoop([[maybe_unused]] Ref self, net::UdpSocket* sock) {
  std::vector<std::byte> buf(maxDatagram);

  for (;;) {
    net::UdpEndpoint from;
    net::ErrorCode ec;
    const std::size_t n = co_await sock->async_receive_from(net::asio::buffer(buf), from,
                                                            redirect_error(use_awaitable, ec));
    if (ec) co_return;  // the socket was closed, or the loop is over for good

    const std::span<const std::byte> datagram = std::span<const std::byte>(buf).first(n);
    const auto version = messageVersion(datagram);
    if (!version) continue;
    if (*version == versionV2c) {
      deliverV2c(datagram, from);
      continue;
    }
    if (*version == versionV3) deliverV3(datagram, from);
  }
}

void Client::Impl::deliverV2c(std::span<const std::byte> datagram, const net::UdpEndpoint& from) {
  net::ErrorCode decodeEc;
  auto msg = decodeV2cMessage(datagram, decodeEc);
  if (!msg) return;
  // A Report is control-plane traffic that only v3 produces. Any other PDU type here is either a
  // mis-sent request or someone probing us.
  if (msg->pdu.type != PduType::Response) return;

  const auto it = m_pending.find(msg->pdu.requestId);
  if (it == m_pending.end() || it->second->v3) return;
  // The request-id is guessable and UDP is trivially spoofable, so a Response only counts if it
  // came back from the Target we asked and quoted the Community we used.
  if (from != it->second->from || msg->community != it->second->community) return;

  it->second->response = std::move(msg->pdu);
  it->second->answered = true;
  it->second->timer.cancel();
}

// Everything here is a reason to *drop* a datagram rather than to fail the request that it claims
// to answer. UDP is spoofable and the msgID is guessable, so a caller whose request could be
// failed by a malformed reply would be a caller anyone on the path could cancel at will. A dropped
// datagram leaves the request outstanding and its retransmission timer running.
void Client::Impl::deliverV3(std::span<const std::byte> datagram, const net::UdpEndpoint& from) {
  net::ErrorCode decodeEc;
  auto msg = decodeV3Message(datagram, decodeEc);
  if (!msg) return;

  const auto it = m_pending.find(msg->header.msgId);
  if (it == m_pending.end() || !it->second->v3) return;
  Pending& p = *it->second;
  if (from != p.from) return;

  // The one message the protocol requires us to accept unauthenticated: an Engine that does not
  // recognise our engineID has no key to authenticate its complaint with (RFC 3414 section 3.2).
  // It is accepted only as a Report, only against an outstanding msgID, and only from the address
  // we sent to -- and it can do no more than cost us one further round trip, because what it
  // triggers is a re-discovery, not a state change.
  //
  // An encrypted message is never exempt and never has to be: privacy implies authentication, so
  // the PDU inside it cannot be read before the digest has been, which is the right order anyway.
  const bool encrypted = isEncrypted(msg->header.level);
  const bool exemptFromAuth =
      !encrypted && !isAuthenticated(msg->header.level) && msg->scoped.pdu.type == PduType::Report;
  // Local rather than written straight into p: a verified reply can still be dropped below, and a
  // later unsigned Report must not inherit a verdict that was about a different datagram.
  bool authenticated = false;
  if (p.authRequired && !exemptFromAuth) {
    net::ErrorCode authEc;
    if (!verifyAuth(datagram, *msg, p.authProtocol, p.authKey, authEc)) {
      p.dropReason = make_error_code(Errc::AuthFailed);
      return;
    }
    authenticated = true;
  }
  // RFC 3414 section 3.2 puts decryption at step 8, after the digest at step 6 and timeliness at
  // step 7. Timeliness is checked below rather than here, and has to be: an encrypted Report is
  // exempt from that check, and nothing can tell a Report from a Response before it is open.
  if (encrypted) {
    net::ErrorCode privEc;
    // Dropped like every other unreadable reply: the request stays outstanding and retransmits.
    // An Agent that genuinely could not decrypt *ours* says so with a Report, which is a different
    // path entirely and arrives readable.
    if (!decryptScopedPdu(*msg, p.privProtocol, p.privKey, privEc)) {
      p.dropReason = make_error_code(Errc::DecryptionFailed);
      return;
    }
  }
  const bool isReport = msg->scoped.pdu.type == PduType::Report;
  // An unauthenticated Report is admitted whatever it says, because the four counters worth
  // hearing about are precisely the ones the Engine cannot sign: it does not know the user, or the
  // key, or the engineID the message was addressed to. Refusing them would turn "wrong password"
  // into "timed out". The bar it clears is the protocol's own -- an outstanding msgID, from the
  // address we sent to -- which is the same bar a spoofed v2c Response clears, and it buys the
  // sender nothing beyond failing this one request, or a discovery and every request queued behind
  // it (ADR-0003): neither handleReport nor discoverEngine takes a boots/time pair we will trust
  // from an unauthenticated claim. (The identity phase does record one, untrusted: timely()
  // ignores it until the time-sync phase has replaced it with a signed one. It takes the engineID
  // unsigned too, as RFC 3414 section 4 requires; a wrong one costs a key derivation, and the real
  // Engine's unknownEngineIDs Report corrects it.)
  //
  // Except one claim, in one place. Discovery's time-sync phase exists to provoke a
  // notInTimeWindows Report, and a genuine one is always signed -- the Engine knows the user and
  // the key by then, and RFC 3414 section 3.2 step 7(a) has it authenticate the Report. An unsigned
  // one is a forgery racing the Engine, and failing on it would only let the forger win the race
  // outright. So it is dropped like any other unusable reply and the phase keeps waiting for the
  // signed one until its deadline (ADR-0008), which reports NotInTimeWindow if that never comes.
  // The other counters still end the discovery unsigned, deliberately: an Engine that reports them
  // has no key to sign with, so there is no signed answer worth waiting for.
  if (p.timeSyncPhase && !authenticated && reportsNotInTimeWindows(msg->scoped.pdu)) {
    p.dropReason = make_error_code(Errc::NotInTimeWindow);
    return;
  }
  // A Report is exempt from all three of the checks below. It may legitimately come from an Engine
  // other than the one we addressed -- that is what usmStatsUnknownEngineIDs means -- it carries no
  // request-id worth matching, and above all it is the message that *reports* a boots/time
  // disagreement, so checking it against the pair it is disagreeing with would discard every
  // resynchronisation the protocol has.
  if (!isReport) {
    if (!p.engineId.empty() && msg->security.engineId != p.engineId) return;
    if (msg->scoped.pdu.requestId != p.requestId) return;
    if (msg->scoped.pdu.type != PduType::Response) return;
    if (p.authRequired && !timely(from, msg->security)) {
      p.dropReason = make_error_code(Errc::NotInTimeWindow);
      return;
    }
  }

  p.security = std::move(msg->security);
  p.response = std::move(msg->scoped.pdu);
  p.replyAuthenticated = authenticated;
  p.answered = true;
  p.timer.cancel();
}

Client::Impl::EngineState* Client::Impl::engineAt(const net::UdpEndpoint& endpoint) {
  const auto indexed = m_engineAt.find(endpoint);
  if (indexed == m_engineAt.end()) return nullptr;
  const auto engine = m_engines.find(indexed->second);
  return engine == m_engines.end() ? nullptr : &engine->second;
}

// RFC 3414 section 3.2 step 7(b), which is the non-authoritative side's rule and not the
// authoritative side's: only a pair *older* than the one we hold is untimely. A higher boots count
// is an Engine that has restarted and a later time is one whose clock was stepped, and both are it
// telling us where it has got to -- observeEngineTime adopts them, which is the same section 2.2.3
// rule read from the other end.
//
// Requiring the pair to match, as the authoritative side does, costs a Target that is answering:
// every reply from an Engine that restarted mid-session is dropped and the caller is told Timeout
// until the cache is thrown away.
bool Client::Impl::timely(const net::UdpEndpoint& from, const UsmParameters& security) const {
  const auto indexed = m_engineAt.find(from);
  if (indexed == m_engineAt.end()) return true;  // nothing yet to disagree with
  const auto found = m_engines.find(indexed->second);
  if (found == m_engines.end()) return true;

  const EngineState& engine = found->second;
  // A pair the identity phase recorded is unsigned, and so nothing to be untimely against: judging
  // the Engine's signed answer to the time-sync phase by it would let a forged identity reply get
  // that answer dropped.
  if (!engine.timeSynced) return true;
  // An Engine at the boots ceiling can never be timely again (RFC 3414 section 2.2.3), which is
  // why observeEngineTime refuses to cache one either.
  if (security.boots == bootsCeiling || engine.boots == bootsCeiling) return false;
  if (security.boots != engine.boots) return security.boots > engine.boots;

  const auto elapsed =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - engine.at)
          .count();
  const auto projected = static_cast<std::int64_t>(engine.time) + elapsed;
  // Behind our projection by more than the Window is the replay this check exists for; ahead of it
  // is a clock that was stepped forward, which is not.
  return static_cast<std::int64_t>(security.time) >= projected - timeWindowSeconds;
}

void Client::Impl::observeEngineTime(const net::UdpEndpoint& from, const UsmParameters& security) {
  EngineState* engine = engineAt(from);
  if (engine == nullptr) return;
  // An Engine at the boots ceiling can never be timely again, so recording one is a state we could
  // not leave. Refusing it means a spoofed pair cannot wedge this endpoint permanently, and a real
  // Engine that has genuinely reached it fails its own requests rather than poisoning the cache.
  if (security.boots == bootsCeiling) return;
  // RFC 3414 section 2.2.3: a later boots count always wins, and within one boot only a later time
  // does. Anything else is a replay of something we have already seen. (Or an Engine whose boots
  // really did go backwards, which handleReport recovers from by rediscovering, never through
  // here.)
  if (security.boots < engine->boots) return;
  if (security.boots == engine->boots && security.time < engine->time) return;
  engine->boots = security.boots;
  engine->time = security.time;
  engine->at = std::chrono::steady_clock::now();
  engine->timeSynced = true;
}

net::Awaitable<net::ErrorCode> Client::Impl::transact(Ref self, Target target,
                                                      std::vector<std::byte> datagram,
                                                      std::int32_t key,
                                                      std::shared_ptr<Pending> pending) {
  // Before the socket, so that nothing reopens one Stopping has closed.
  if (m_stopping) co_return make_error_code(Errc::ClientStopped);
  net::ErrorCode ec;
  net::UdpSocket* sock = socketFor(self, target.endpoint, ec);
  if (ec) co_return ec;

  m_pending.emplace(key, pending);

  // Cancellation is handled here rather than thrown, so every exit still goes through the
  // bookkeeping below. Which types are observable at all is decided once per request, where the
  // request starts -- see observeBothCancellationTypes.
  co_await net::asio::this_coro::throw_if_cancelled(false);
  auto cancelState = co_await net::asio::this_coro::cancellation_state;
  const auto aborted = [&cancelState] {
    return (cancelState.cancelled() & net::asio::cancellation_type::terminal) !=
           net::asio::cancellation_type::none;
  };
  const auto softCancelled = [&cancelState, &aborted] {
    return cancelState.cancelled() != net::asio::cancellation_type::none && !aborted();
  };

  for (int attempt = 0; attempt <= target.retries; ++attempt) {
    co_await sock->async_send_to(net::asio::buffer(datagram), target.endpoint,
                                 redirect_error(use_awaitable, ec));
    // Stopping may have begun while the send was in flight, and its cleanup has then already
    // cancelled a timer this has not armed yet -- arming it now would wait out a whole deadline
    // before reporting ClientStopped.
    if (ec || m_stopping) break;

    pending->timer.expires_after(target.timeout);
    // The wait's own ErrorCode says nothing useful: the receive loop cancels this timer to wake
    // us, so operation_aborted is the success path and expiry is the retry path.
    [[maybe_unused]] net::ErrorCode waitEc;
    co_await pending->timer.async_wait(redirect_error(use_awaitable, waitEc));
    if (pending->answered || m_stopping || aborted()) break;

    if (softCancelled()) {
      // A total signal stops this request cleanly rather than dropping it: the exchange already
      // in flight is allowed to finish, so wait out the rest of the deadline on a slot nothing
      // can cancel -- a reply that arrives inside it still counts. No further retransmission,
      // and no new exchange after this one, which is also what the Walk above wants when it
      // stops at a batch boundary (ADR-0004).
      co_await pending->timer.async_wait(net::asio::bind_cancellation_slot(
          net::asio::cancellation_slot(), redirect_error(use_awaitable, waitEc)));
      break;
    }
  }

  m_pending.erase(key);

  // Terminal drops the exchange whatever else happened, including a reply that landed while the
  // signal was on its way; total lets that reply count, and ends the request otherwise. Both are
  // ahead of dropReason as well as of ec: the caller asked for this to stop, so that is the
  // honest answer rather than what the Target was last heard doing. A reply accepted as Stopping
  // began does not count either: every Outstanding Request completes with ClientStopped then, and
  // one whose reply was in hand is still outstanding until this returns.
  if (aborted()) co_return net::ErrorCode(net::asio::error::operation_aborted);
  if (pending->answered && !m_stopping) co_return net::ErrorCode{};
  // Spelled out rather than reusing softCancelled(). Not style: GCC 16 emits a spurious
  // -Wmismatched-new-delete from inside Asio's coroutine frame allocator, blamed on doRequestV3,
  // for almost any perturbation of this block's inlining -- reusing the lambda, hoisting it, or
  // deleting the block all trip it. Leave the shape alone unless the compiler stops caring.
  if (cancelState.cancelled() != net::asio::cancellation_type::none) {
    co_return net::ErrorCode(net::asio::error::operation_aborted);
  }
  // Ahead of ec on purpose: stop() closes the socket, so the socket's own complaint about a bad
  // descriptor is a symptom of the stop and would bury the actual reason.
  if (m_stopping) co_return make_error_code(Errc::ClientStopped);
  if (ec) co_return ec;
  // A Target that said nothing at all is a Timeout. One whose replies we refused says why it
  // refused them, at the deadline rather than before it.
  if (pending->dropReason) co_return pending->dropReason;
  co_return make_error_code(Errc::Timeout);
}

Client::RequestResult Client::Impl::toResult(const Pdu& response) {
  Response resp;
  resp.varbinds = response.varbinds;
  resp.errorIndex = response.errorIndex;
  if (response.errorStatus != 0) {
    return RequestResult{make_error_code(static_cast<ErrorStatus>(response.errorStatus)),
                         std::move(resp)};
  }
  return RequestResult{net::ErrorCode{}, std::move(resp)};
}

// The one place an operation decides which cancellation signals it can see: neither type is
// thrown, and total is turned on explicitly because co_spawn's default filter would otherwise
// drop it before any of the waits below could act on it. Per coroutine, at its start -- a Walk
// calls it and so does each request underneath, which is why doWalk re-reads the state it needs
// rather than holding it.
net::Awaitable<void> Client::Impl::observeBothCancellationTypes() {
  co_await net::asio::this_coro::throw_if_cancelled(false);
  co_await net::asio::this_coro::reset_cancellation_state(net::asio::enable_total_cancellation());
}

net::Awaitable<Client::RequestResult> Client::Impl::doRequest(Ref self, Target target, Auth auth,
                                                              Pdu pdu) {
  if (const auto* community = std::get_if<Community>(&auth)) {
    co_return co_await doRequestV2c(self, std::move(target), *community, std::move(pdu));
  }
  co_return co_await doRequestV3(self, std::move(target), std::get<Credentials>(auth),
                                 std::move(pdu));
}

net::Awaitable<Client::RequestResult> Client::Impl::doRequestV2c(Ref self, Target target,
                                                                 Community community, Pdu pdu) {
  if (m_stopping) co_return RequestResult{make_error_code(Errc::ClientStopped), Response{}};
  co_await observeBothCancellationTypes();

  pdu.requestId = nextId();

  net::ErrorCode ec;
  auto datagram = encodeV2cMessage(community.value, pdu, ec);
  if (ec) co_return RequestResult{ec, Response{}};

  const auto pending = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
  pending->from = target.endpoint;
  pending->community = community.value;
  pending->requestId = pdu.requestId;

  ec = co_await transact(self, std::move(target), std::move(datagram), pdu.requestId, pending);
  if (ec) co_return RequestResult{ec, Response{}};
  co_return toResult(pending->response);
}

const Octets* Client::Impl::localizedKey(const Credentials& creds, const Octets& engineId,
                                         net::ErrorCode& ec) {
  // The user name is deliberately not part of the key: what the derivation consumes is the
  // password, the protocol and the engineID, so two users sharing a password share a key.
  auto cacheKey =
      std::make_tuple(engineId, creds.authProtocol, creds.authPassword, PrivProtocol::None);
  const auto it = m_keys.find(cacheKey);
  if (it != m_keys.end()) {
    ec = {};
    return &it->second;
  }
  auto derived = localizedAuthKey(creds, engineId, ec);
  if (ec) return nullptr;
  return &m_keys.emplace(std::move(cacheKey), std::move(derived)).first->second;
}

const Octets* Client::Impl::localizedPrivacyKey(const Credentials& creds, const Octets& engineId,
                                                net::ErrorCode& ec) {
  auto cacheKey =
      std::make_tuple(engineId, creds.authProtocol, creds.privPassword, creds.privProtocol);
  const auto it = m_keys.find(cacheKey);
  if (it != m_keys.end()) {
    ec = {};
    return &it->second;
  }
  auto derived = localizedPrivKey(creds, engineId, ec);
  if (ec) return nullptr;
  return &m_keys.emplace(std::move(cacheKey), std::move(derived)).first->second;
}

net::Awaitable<net::ErrorCode> Client::Impl::ensureEngine(Ref self, Target target,
                                                          Credentials creds) {
  const EngineState* engine = engineAt(target.endpoint);
  // Knowing the engineID is enough for noAuthNoPriv. Authenticating additionally needs a boots/time
  // pair we trust, and a noAuthNoPriv discovery never produced one -- so a Target first met without
  // authentication still synchronises the first time it is addressed with it.
  if (engine != nullptr && (!isAuthenticated(creds.level) || engine->timeSynced)) {
    co_return net::ErrorCode{};
  }

  std::shared_ptr<Discovery> discovery;
  const auto inFlight = m_discovering.find(target.endpoint);
  if (inFlight != m_discovering.end()) {
    // CONTEXT.md: requests issued against an undiscovered Engine queue behind the one discovery
    // rather than each starting their own.
    discovery = inFlight->second;
  } else {
    discovery = std::make_shared<Discovery>(m_strand);
    // A timer used as an event rather than a deadline: it never expires on its own, and cancelling
    // it is how every waiter is woken at once.
    discovery->done.expires_at(std::chrono::steady_clock::time_point::max());
    m_discovering.emplace(target.endpoint, discovery);
    // Spawned on its own rather than awaited, and this is the point of ADR-0003's "Engine
    // Discovery outlives any individual waiter": the discovery belongs to the Engine, not to
    // whichever request happened to arrive first, so cancelling that request must not cancel what
    // everyone else is queued behind.
    net::asio::co_spawn(
        m_strand, runDiscovery(self, std::move(target), std::move(creds), discovery), rethrow);
  }

  co_await net::asio::this_coro::throw_if_cancelled(false);
  [[maybe_unused]] net::ErrorCode waitEc;
  co_await discovery->done.async_wait(redirect_error(use_awaitable, waitEc));
  // Ahead of Stopping: an exception is a bug or bad_alloc, and the louder of the two answers.
  if (discovery->failure) std::rethrow_exception(discovery->failure);
  if (m_stopping) co_return make_error_code(Errc::ClientStopped);
  // The same rule as transact's, in the other wait a request can be in: either cancellation type
  // ends this request. Asked, rather than inferred from an unfinished discovery, because a signal
  // arriving as the discovery completes has to count too. The discovery itself carries on for
  // whoever else is waiting -- this request is the only one that is over.
  const auto cancelled = co_await net::asio::this_coro::cancellation_state;
  if (cancelled.cancelled() != net::asio::cancellation_type::none || !discovery->finished) {
    co_return net::ErrorCode(net::asio::error::operation_aborted);
  }
  co_return discovery->ec;
}

net::Awaitable<void> Client::Impl::runDiscovery(Ref self, Target target, Credentials creds,
                                                std::shared_ptr<Discovery> discovery) {
  const auto endpoint = target.endpoint;
  try {
    discovery->ec = co_await discoverEngine(self, std::move(target), std::move(creds));
    discovery->finished = true;
  } catch (...) {
    discovery->failure = std::current_exception();
  }
  // On both paths: a discovery that threw must not stay registered, or every later request to
  // this Target would queue behind one that will never finish.
  m_discovering.erase(endpoint);
  discovery->done.cancel();
  if (discovery->failure) std::rethrow_exception(discovery->failure);
}

// RFC 3414 section 4. Phase one asks with no engineID at all and reads the Engine's own from what
// comes back; phase two, needed only when authenticating, sends a deliberately untimely message
// and reads the real boots/time out of the rejection.
net::Awaitable<net::ErrorCode> Client::Impl::discoverEngine(Ref self, Target target,
                                                            Credentials creds) {
  const std::int32_t identifyId = nextId();
  V3Header header;
  header.msgId = identifyId;
  header.level = SecurityLevel::NoAuthNoPriv;

  net::ErrorCode ec;
  auto datagram = encodeV3Message(header, UsmParameters{}, discoveryScopedPdu(identifyId, {}),
                                  AuthProtocol::None, {}, ec);
  if (ec) co_return ec;

  const auto identify = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
  identify->from = target.endpoint;
  identify->v3 = true;
  identify->requestId = identifyId;

  ec = co_await transact(self, target, std::move(datagram), identifyId, identify);
  if (ec) co_return ec;
  // Some Agents answer with a Report and some with an ordinary Response; either way the engineID
  // is in the security parameters, and that is the only part of the reply this phase wanted.
  if (identify->security.engineId.empty()) co_return make_error_code(Errc::UnknownEngineId);

  const Octets engineId = identify->security.engineId;
  m_engineAt[target.endpoint] = engineId;
  EngineState& engine = m_engines[engineId];
  engine.engineId = engineId;
  if (!engine.timeSynced) {
    engine.boots = identify->security.boots;
    engine.time = identify->security.time;
    engine.at = std::chrono::steady_clock::now();
  }

  if (!isAuthenticated(creds.level)) co_return net::ErrorCode{};
  // ADR-0003's payoff: the same Engine reached at a second Target is the same cache entry, so the
  // pair we already synchronised stands and only the identity phase had to run again.
  if (engine.timeSynced) co_return net::ErrorCode{};

  const Octets* key = localizedKey(creds, engineId, ec);
  if (ec) co_return ec;
  const Octets* privKey = nullptr;
  if (isEncrypted(creds.level)) {
    privKey = localizedPrivacyKey(creds, engineId, ec);
    if (ec) co_return ec;
  }

  const std::int32_t syncId = nextId();
  V3Header syncHeader;
  syncHeader.msgId = syncId;
  syncHeader.level = creds.level;
  UsmParameters usm;
  usm.engineId = engineId;
  usm.userName = creds.userName;  // boots and time left at zero: being wrong is the point

  // Sent at the Credentials' own level rather than downgraded to authNoPriv: an Engine may enforce
  // a minimum level per user, and being refused for asking too politely would end discovery. The
  // Engine never has to decrypt it -- RFC 3414 section 3.2 rejects it as untimely at step 7, one
  // step before decryption -- and the Report that rejection produces is the point of sending it.
  auto syncDatagram =
      encodeV3Message(syncHeader, usm, discoveryScopedPdu(syncId, engineId), creds.authProtocol,
                      *key, ec, creds.privProtocol, keySpan(privKey));
  if (ec) co_return ec;

  const auto sync = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
  sync->from = target.endpoint;
  sync->v3 = true;
  sync->authRequired = true;
  sync->authProtocol = creds.authProtocol;
  sync->privProtocol = creds.privProtocol;
  sync->authKey = *key;
  if (privKey != nullptr) sync->privKey = *privKey;
  sync->engineId = engineId;
  sync->requestId = syncId;
  sync->timeSyncPhase = true;

  ec = co_await transact(self, std::move(target), std::move(syncDatagram), syncId, sync);
  if (ec) co_return ec;
  // RFC 3414 sections 3.2 step 7(b) and 11.1: the pair is learnt from an authenticated message,
  // and only from one. That is usually the notInTimeWindows Report this phase was sent to provoke,
  // or a Response from an Engine that found boots and time zero timely -- but any signed reply
  // carries the Engine's own clock, whatever counter it names, and the pinned `simulator` image
  // answers with a signed unknownEngineIDs Report. An unsigned one, which deliverV3 admitted only
  // for the error it names, ends the discovery with that error, and its boots and time are not
  // read.
  if (!sync->replyAuthenticated) co_return reportError(usmStatsCounter(sync->response));
  if (sync->security.boots == bootsCeiling) co_return make_error_code(Errc::NotInTimeWindow);

  // The Engine has just told us where its clock is, and signed for it. This is the one place a
  // pair is taken without being compared against an earlier one, because there is no earlier one:
  // it is the baseline every later comparison is made against.
  EngineState& discovered = m_engines[engineId];
  discovered.boots = sync->security.boots;
  discovered.time = sync->security.time;
  discovered.at = std::chrono::steady_clock::now();
  discovered.timeSynced = true;
  co_return net::ErrorCode{};
}

std::optional<net::ErrorCode> Client::Impl::handleReport(const net::UdpEndpoint& from,
                                                         const Pending& pending, bool mayRetry) {
  const auto counter = usmStatsCounter(pending.response);
  if (!mayRetry || !counter) return reportError(counter);

  const bool retryable =
      *counter == usmStatsNotInTimeWindows || *counter == usmStatsUnknownEngineIds;
  if (!retryable) return reportError(counter);

  // An unauthenticated Report is a claim, not a fact. It is enough to make us go and ask the
  // Engine again -- a round trip an attacker could cost us anyway by dropping a datagram -- and
  // never enough to write into the cache, because the answer to the re-discovery is authenticated
  // and this is not.
  if (!pending.replyAuthenticated || *counter == usmStatsUnknownEngineIds) {
    m_engineAt.erase(from);
    return std::nullopt;
  }
  // A signed Report naming a boots *lower* than the one we hold is the one pair observeEngineTime
  // refuses, and refusing it here would be refusing it for good: the retry would carry the same
  // stale pair and fail the same way, for the rest of this Client's life. RFC 3414 section 3.2
  // step 7(b) deems the message untimely, and we keep to that -- its pair is never written. What
  // we act on is that an Engine holding our key has just told us our notion of its clock is wrong,
  // which leaves only the Engine that broke section 2.2.2 by letting its boots go backwards (a
  // factory reset, a replaced line card, firmware that lost snmpEngineBoots) or a cache poisoned by
  // some route #25 did not close. Either way we forget our notion and let the retry rediscover,
  // time-sync phase included; discoverEngine takes its answer as a fresh baseline. ADR-0010.
  //
  // The flag lives on the Engine, not the endpoint, so every Target reaching this Engine stops
  // judging timeliness until the rediscovery completes -- the same window the first discovery had.
  //
  // Not a replay hole. The Report carries our msgID inside the signed header and msgIDs do not
  // repeat within a Client short of 2^31 requests, so an old capture cannot match a request still
  // waiting for an answer. What remains is a recording from an earlier Client process that happened
  // to reuse the msgID. That buys one rediscovery per request -- mayRetry bounds it -- and the
  // rediscovery is exposed exactly as every first discovery is: only a second recording that
  // matches the time-sync phase's own msgID could set its baseline.
  EngineState* engine = engineAt(from);
  if (engine != nullptr && engine->timeSynced && pending.security.boots < engine->boots) {
    engine->timeSynced = false;
    return std::nullopt;
  }
  observeEngineTime(from, pending.security);
  return std::nullopt;
}

net::Awaitable<Client::RequestResult> Client::Impl::doRequestV3(Ref self, Target target,
                                                                Credentials creds, Pdu pdu) {
  if (m_stopping) co_return RequestResult{make_error_code(Errc::ClientStopped), Response{}};
  co_await observeBothCancellationTypes();
  // Refused at the call rather than downgraded: a message that claims privacy it does not have is
  // worse than one that was never sent.
  if (isEncrypted(creds.level) && creds.privProtocol == PrivProtocol::None) {
    co_return RequestResult{make_error_code(Errc::UnsupportedPrivProtocol), Response{}};
  }
  if (isAuthenticated(creds.level) && creds.authProtocol == AuthProtocol::None) {
    co_return RequestResult{make_error_code(Errc::UnsupportedAuthProtocol), Response{}};
  }

  // Two attempts, never more. A Report that says "resynchronise and ask again" earns exactly one
  // further try; an Engine that keeps saying it is an Engine we cannot talk to, and two
  // implementations that disagree must not be able to trade messages forever.
  for (int attempt = 0; attempt < 2; ++attempt) {
    net::ErrorCode ec = co_await ensureEngine(self, target, creds);
    if (ec) co_return RequestResult{ec, Response{}};

    const EngineState* engine = engineAt(target.endpoint);
    // Only reachable if the Engine was forgotten between the discovery finishing and this line,
    // which nothing on this strand does.
    if (engine == nullptr)
      co_return RequestResult{make_error_code(Errc::UnknownEngineId), Response{}};
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::steady_clock::now() - engine->at)
                             .count();
    const auto projected =
        std::min<std::int64_t>(static_cast<std::int64_t>(engine->time) + elapsed, timeCeiling);

    const Octets* key = nullptr;
    if (isAuthenticated(creds.level)) {
      key = localizedKey(creds, engine->engineId, ec);
      if (ec) co_return RequestResult{ec, Response{}};
    }
    const Octets* privKey = nullptr;
    if (isEncrypted(creds.level)) {
      privKey = localizedPrivacyKey(creds, engine->engineId, ec);
      if (ec) co_return RequestResult{ec, Response{}};
    }

    const std::int32_t id = nextId();
    pdu.requestId = id;

    V3Header header;
    header.msgId = id;
    header.level = creds.level;

    UsmParameters usm;
    usm.engineId = engine->engineId;
    usm.boots = engine->boots;
    usm.time = static_cast<std::int32_t>(projected);
    usm.userName = creds.userName;

    ScopedPdu scoped;
    scoped.contextEngineId = engine->engineId;
    scoped.pdu = pdu;

    auto datagram = encodeV3Message(header, usm, scoped, creds.authProtocol, keySpan(key), ec,
                                    creds.privProtocol, keySpan(privKey));
    if (ec) co_return RequestResult{ec, Response{}};

    const auto pending = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
    pending->from = target.endpoint;
    pending->v3 = true;
    pending->authRequired = isAuthenticated(creds.level);
    pending->authProtocol = creds.authProtocol;
    pending->privProtocol = creds.privProtocol;
    if (key != nullptr) pending->authKey = *key;
    if (privKey != nullptr) pending->privKey = *privKey;
    pending->engineId = engine->engineId;
    pending->requestId = id;

    ec = co_await transact(self, target, std::move(datagram), id, pending);
    if (ec) co_return RequestResult{ec, Response{}};

    if (pending->response.type == PduType::Report) {
      const auto failure = handleReport(target.endpoint, *pending, attempt == 0);
      if (!failure) continue;
      co_return RequestResult{*failure, Response{}};
    }

    if (pending->replyAuthenticated) observeEngineTime(target.endpoint, pending->security);
    co_return toResult(pending->response);
  }

  // Unreachable: the second attempt never asks to retry, so the loop always returns from inside.
  co_return RequestResult{make_error_code(Errc::UnexpectedReport), Response{}};
}

net::Awaitable<Client::WalkResult> Client::Impl::doWalk(Ref self, Target target, Auth auth,
                                                        Oid base, WalkOptions options,
                                                        BatchHandler onBatch) {
  // A total cancellation is a request to stop cleanly at a batch boundary rather than to drop
  // everything, so it has to be observable here -- and observed, not thrown.
  co_await observeBothCancellationTypes();
  // The two halves of ADR-0004's split, in one place so they cannot drift apart: terminal drops
  // everything and says so with operation_aborted, total stops here and reports an incomplete
  // Walk. Nothing else may turn a cancellation into an ordinary failure. The state is asked for
  // at each call rather than held, because each request underneath re-seats it.
  const auto stopNow = [](net::asio::cancellation_state state) -> std::optional<net::ErrorCode> {
    const auto c = state.cancelled();
    if ((c & net::asio::cancellation_type::terminal) != net::asio::cancellation_type::none) {
      return net::ErrorCode(net::asio::error::operation_aborted);
    }
    if (c != net::asio::cancellation_type::none) return make_error_code(Errc::WalkIncomplete);
    return std::nullopt;
  };

  Oid current = base;
  std::int32_t maxRepetitions = options.maxRepetitions;

  for (;;) {
    if (const auto stop = stopNow(co_await net::asio::this_coro::cancellation_state))
      co_return WalkResult{*stop};

    const Pdu req = maxRepetitions <= 0 ? makePdu(PduType::GetNext, toVarbinds({current}))
                                        : makeBulkPdu(toVarbinds({current}), 0, maxRepetitions);

    auto [ec, resp] = co_await doRequest(self, target, auth, req);
    // tooBig means the Response did not fit, not that the request was wrong: ask for less and try
    // again. Only a deliberately misbehaving Simulator reaches this path (ADR-0006).
    if (ec == ErrorStatus::TooBig && maxRepetitions > 1) {
      maxRepetitions /= 2;
      continue;
    }
    if (ec) {
      // A cancellation that cut the exchange short is an incomplete Walk, not a fault of the
      // Target's -- a total cancel against a silent Target must not surface as a Timeout.
      if (const auto stop = stopNow(co_await net::asio::this_coro::cancellation_state))
        co_return WalkResult{*stop};
      co_return WalkResult{ec};
    }
    // A reply in hand as Stopping began is a batch the caller never sees: the batch handler is not
    // called once Stopping has begun, from whichever thread it began on (ADR-0009).
    if (m_stopping) co_return WalkResult{make_error_code(Errc::ClientStopped)};
    if (resp.varbinds.empty()) co_return WalkResult{make_error_code(Errc::MissingVarbind)};

    std::vector<Varbind> batch;
    batch.reserve(resp.varbinds.size());
    bool done = false;
    for (auto& vb : resp.varbinds) {
      // endOfMibView -- or either of the noSuch markers, from an Agent that should not be sending
      // them here -- ends the Walk, as does leaving the Subtree.
      if (isException(vb.val) || !base.isPrefixOf(vb.name)) {
        done = true;
        break;
      }
      // ADR-0004: an Agent that repeats an OID would otherwise walk forever.
      if (!(current < vb.name)) co_return WalkResult{make_error_code(Errc::NonIncreasingOid)};
      current = vb.name;
      batch.push_back(std::move(vb));
    }

    if (!batch.empty() && !onBatch(batch))
      co_return WalkResult{make_error_code(Errc::WalkIncomplete)};
    if (done) co_return WalkResult{net::ErrorCode{}};
  }
}

net::Awaitable<Client::CollectResult> Client::Impl::doWalkCollect(Ref self, Target target,
                                                                  Auth auth, Oid base,
                                                                  WalkOptions options) {
  std::vector<Varbind> collected;
  auto [ec] = co_await doWalk(self, std::move(target), std::move(auth), std::move(base), options,
                              [&collected](std::span<const Varbind> batch) {
                                collected.insert(collected.end(), batch.begin(), batch.end());
                                return true;
                              });
  // ADR-0004 again: `total` keeps what arrived, `terminal` drops everything immediately.
  if (ec == net::asio::error::operation_aborted) collected.clear();
  co_return CollectResult{ec, std::move(collected)};
}

}  // namespace snmpio
