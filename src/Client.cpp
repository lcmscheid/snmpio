#include <snmpio/Client.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <limits>
#include <optional>
#include <random>
#include <string>
#include <tuple>
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

}  // namespace

Client::Client(const net::Executor& ex)
    : m_strand(net::asio::make_strand(ex)), m_nextId(randomRequestId()) {}

std::int32_t Client::nextId() noexcept {
  const std::int32_t id = m_nextId;
  m_nextId = m_nextId == std::numeric_limits<std::int32_t>::max() ? 1 : m_nextId + 1;
  return id;
}

void Client::stop() {
  // Dispatched rather than posted: stop() is usually the last thing before the io_context drains,
  // and a posted cleanup would never run.
  net::asio::dispatch(m_strand, [this] {
    if (m_stopped) return;
    m_stopped = true;
    // close() hands back the same ErrorCode it writes to the out-parameter; std::ignore says the
    // discard is deliberate rather than forgotten.
    net::ErrorCode ignored;
    if (m_v4) std::ignore = m_v4->close(ignored);
    if (m_v6) std::ignore = m_v6->close(ignored);
    for (auto& [id, pending] : m_pending) pending->timer.cancel();
    // Anything parked on a discovery is waiting on a reply that will now never come.
    for (auto& [endpoint, discovery] : m_discovering) discovery->done.cancel();
  });
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

net::UdpSocket* Client::socketFor(const net::UdpEndpoint& to, net::ErrorCode& ec) {
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
  net::asio::co_spawn(m_strand, receiveLoop(&*slot), net::asio::detached);
  return &*slot;
}

// By pointer, not by reference: a coroutine parameter that is a reference is a dangling hazard as
// a rule, and the rule is worth keeping even where -- as here -- the socket is a member that
// outlives the loop.
net::Awaitable<void> Client::receiveLoop(net::UdpSocket* sock) {
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

void Client::deliverV2c(std::span<const std::byte> datagram, const net::UdpEndpoint& from) {
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
void Client::deliverV3(std::span<const std::byte> datagram, const net::UdpEndpoint& from) {
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
  if (p.authRequired && !exemptFromAuth) {
    net::ErrorCode authEc;
    if (!verifyAuth(datagram, *msg, p.authProtocol, p.authKey, authEc)) {
      p.dropReason = make_error_code(Errc::AuthFailed);
      return;
    }
    p.replyAuthenticated = true;
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
  // sender nothing beyond failing this one request: handleReport will not let an unauthenticated
  // claim change anything we have cached.
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
  p.answered = true;
  p.timer.cancel();
}

Client::EngineState* Client::engineAt(const net::UdpEndpoint& endpoint) {
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
bool Client::timely(const net::UdpEndpoint& from, const UsmParameters& security) const {
  const auto indexed = m_engineAt.find(from);
  if (indexed == m_engineAt.end()) return true;  // nothing yet to disagree with
  const auto found = m_engines.find(indexed->second);
  if (found == m_engines.end()) return true;

  const EngineState& engine = found->second;
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

void Client::observeEngineTime(const net::UdpEndpoint& from, const UsmParameters& security) {
  EngineState* engine = engineAt(from);
  if (engine == nullptr) return;
  // An Engine at the boots ceiling can never be timely again, so recording one is a state we could
  // not leave. Refusing it means a spoofed pair cannot wedge this endpoint permanently, and a real
  // Engine that has genuinely reached it fails its own requests rather than poisoning the cache.
  if (security.boots == bootsCeiling) return;
  // RFC 3414 section 2.2.3: a later boots count always wins, and within one boot only a later time
  // does. Anything else is a replay of something we have already seen.
  if (security.boots < engine->boots) return;
  if (security.boots == engine->boots && security.time < engine->time) return;
  engine->boots = security.boots;
  engine->time = security.time;
  engine->at = std::chrono::steady_clock::now();
  engine->timeSynced = true;
}

net::Awaitable<net::ErrorCode> Client::transact(Target target, std::vector<std::byte> datagram,
                                                std::int32_t key,
                                                std::shared_ptr<Pending> pending) {
  net::ErrorCode ec;
  net::UdpSocket* sock = socketFor(target.endpoint, ec);
  if (ec) co_return ec;

  m_pending.emplace(key, pending);

  // Cancellation is handled here rather than thrown, so every exit still goes through the
  // bookkeeping below.
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
    if (ec) break;

    pending->timer.expires_after(target.timeout);
    // The wait's own ErrorCode says nothing useful: the receive loop cancels this timer to wake
    // us, so operation_aborted is the success path and expiry is the retry path.
    [[maybe_unused]] net::ErrorCode waitEc;
    co_await pending->timer.async_wait(redirect_error(use_awaitable, waitEc));
    if (pending->answered || m_stopped || aborted()) break;

    if (softCancelled()) {
      // A total signal is not this request's to act on -- it belongs to the Walk above us, which
      // stops at a batch boundary and wants this exchange finished (ADR-0004). It did however cut
      // the wait short, so wait out the rest of the deadline on a slot nothing can cancel, and
      // stop retransmitting either way.
      co_await pending->timer.async_wait(net::asio::bind_cancellation_slot(
          net::asio::cancellation_slot(), redirect_error(use_awaitable, waitEc)));
      break;
    }
  }

  m_pending.erase(key);

  if (pending->answered) co_return net::ErrorCode{};
  if (aborted()) co_return net::ErrorCode(net::asio::error::operation_aborted);
  // Ahead of ec on purpose: stop() closes the socket, so the socket's own complaint about a bad
  // descriptor is a symptom of the stop and would bury the actual reason.
  if (m_stopped) co_return make_error_code(Errc::ClientStopped);
  if (ec) co_return ec;
  // A Target that said nothing at all is a Timeout. One whose replies we refused says why it
  // refused them, at the deadline rather than before it.
  if (pending->dropReason) co_return pending->dropReason;
  co_return make_error_code(Errc::Timeout);
}

Client::RequestResult Client::toResult(const Pdu& response) {
  Response resp;
  resp.varbinds = response.varbinds;
  resp.errorIndex = response.errorIndex;
  if (response.errorStatus != 0) {
    return RequestResult{make_error_code(static_cast<ErrorStatus>(response.errorStatus)),
                         std::move(resp)};
  }
  return RequestResult{net::ErrorCode{}, std::move(resp)};
}

net::Awaitable<Client::RequestResult> Client::doRequest(Target target, Auth auth, Pdu pdu) {
  if (const auto* community = std::get_if<Community>(&auth)) {
    co_return co_await doRequestV2c(std::move(target), *community, std::move(pdu));
  }
  co_return co_await doRequestV3(std::move(target), std::get<Credentials>(auth), std::move(pdu));
}

net::Awaitable<Client::RequestResult> Client::doRequestV2c(Target target, Community community,
                                                           Pdu pdu) {
  if (m_stopped) co_return RequestResult{make_error_code(Errc::ClientStopped), Response{}};

  pdu.requestId = nextId();

  net::ErrorCode ec;
  auto datagram = encodeV2cMessage(community.value, pdu, ec);
  if (ec) co_return RequestResult{ec, Response{}};

  auto pending = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
  pending->from = target.endpoint;
  pending->community = community.value;
  pending->requestId = pdu.requestId;

  ec = co_await transact(std::move(target), std::move(datagram), pdu.requestId, pending);
  if (ec) co_return RequestResult{ec, Response{}};
  co_return toResult(pending->response);
}

const Octets* Client::localizedKey(const Credentials& creds, const Octets& engineId,
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

const Octets* Client::localizedPrivacyKey(const Credentials& creds, const Octets& engineId,
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

net::Awaitable<net::ErrorCode> Client::ensureEngine(Target target, Credentials creds) {
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
    discovery = std::make_shared<Discovery>(co_await net::asio::this_coro::executor);
    // A timer used as an event rather than a deadline: it never expires on its own, and cancelling
    // it is how every waiter is woken at once.
    discovery->done.expires_at(std::chrono::steady_clock::time_point::max());
    m_discovering.emplace(target.endpoint, discovery);
    // Detached, and this is the point of ADR-0003's "Engine Discovery outlives any individual
    // waiter": the discovery belongs to the Engine, not to whichever request happened to arrive
    // first, so cancelling that request must not cancel what everyone else is queued behind.
    net::asio::co_spawn(m_strand, runDiscovery(std::move(target), std::move(creds), discovery),
                        net::asio::detached);
  }

  [[maybe_unused]] net::ErrorCode waitEc;
  co_await discovery->done.async_wait(redirect_error(use_awaitable, waitEc));
  if (m_stopped) co_return make_error_code(Errc::ClientStopped);
  // Woken by our own cancellation rather than by the discovery finishing. The discovery carries on
  // for whoever else is waiting; this request is the one that is over.
  if (!discovery->finished) co_return net::ErrorCode(net::asio::error::operation_aborted);
  co_return discovery->ec;
}

net::Awaitable<void> Client::runDiscovery(Target target, Credentials creds,
                                          std::shared_ptr<Discovery> discovery) {
  const auto endpoint = target.endpoint;
  discovery->ec = co_await discoverEngine(std::move(target), std::move(creds));
  discovery->finished = true;
  m_discovering.erase(endpoint);
  discovery->done.cancel();
}

// RFC 3414 section 4. Phase one asks with no engineID at all and reads the Engine's own from what
// comes back; phase two, needed only when authenticating, sends a deliberately untimely message
// and reads the real boots/time out of the rejection.
net::Awaitable<net::ErrorCode> Client::discoverEngine(Target target, Credentials creds) {
  const std::int32_t identifyId = nextId();
  V3Header header;
  header.msgId = identifyId;
  header.level = SecurityLevel::NoAuthNoPriv;

  net::ErrorCode ec;
  auto datagram = encodeV3Message(header, UsmParameters{}, discoveryScopedPdu(identifyId, {}),
                                  AuthProtocol::None, {}, ec);
  if (ec) co_return ec;

  auto identify = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
  identify->from = target.endpoint;
  identify->v3 = true;
  identify->requestId = identifyId;

  ec = co_await transact(target, std::move(datagram), identifyId, identify);
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

  auto sync = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
  sync->from = target.endpoint;
  sync->v3 = true;
  sync->authRequired = true;
  sync->authProtocol = creds.authProtocol;
  sync->privProtocol = creds.privProtocol;
  sync->authKey = *key;
  if (privKey != nullptr) sync->privKey = *privKey;
  sync->engineId = engineId;
  sync->requestId = syncId;

  ec = co_await transact(std::move(target), std::move(syncDatagram), syncId, sync);
  if (ec) co_return ec;
  if (sync->security.boots == bootsCeiling) co_return make_error_code(Errc::NotInTimeWindow);

  // The Engine has just told us where its clock is. This is the one place a pair is taken without
  // being compared against an earlier one, because there is no earlier one: it is the baseline
  // every later comparison is made against.
  EngineState& discovered = m_engines[engineId];
  discovered.boots = sync->security.boots;
  discovered.time = sync->security.time;
  discovered.at = std::chrono::steady_clock::now();
  discovered.timeSynced = true;
  co_return net::ErrorCode{};
}

std::optional<net::ErrorCode> Client::handleReport(const net::UdpEndpoint& from,
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
  observeEngineTime(from, pending.security);
  return std::nullopt;
}

net::Awaitable<Client::RequestResult> Client::doRequestV3(Target target, Credentials creds,
                                                          Pdu pdu) {
  if (m_stopped) co_return RequestResult{make_error_code(Errc::ClientStopped), Response{}};
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
    net::ErrorCode ec = co_await ensureEngine(target, creds);
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

    auto pending = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
    pending->from = target.endpoint;
    pending->v3 = true;
    pending->authRequired = isAuthenticated(creds.level);
    pending->authProtocol = creds.authProtocol;
    pending->privProtocol = creds.privProtocol;
    if (key != nullptr) pending->authKey = *key;
    if (privKey != nullptr) pending->privKey = *privKey;
    pending->engineId = engine->engineId;
    pending->requestId = id;

    ec = co_await transact(target, std::move(datagram), id, pending);
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

net::Awaitable<Client::WalkResult> Client::doWalk(Target target, Auth auth, Oid base,
                                                  WalkOptions options, BatchHandler onBatch) {
  // A total cancellation is a request to stop cleanly at a batch boundary rather than to drop
  // everything, so it has to be observable here -- and observed, not thrown.
  co_await net::asio::this_coro::throw_if_cancelled(false);
  co_await net::asio::this_coro::reset_cancellation_state(net::asio::enable_total_cancellation());
  auto cancelState = co_await net::asio::this_coro::cancellation_state;
  // The two halves of ADR-0004's split, in one place so they cannot drift apart: terminal drops
  // everything and says so with operation_aborted, total stops here and reports an incomplete
  // Walk. Nothing else may turn a cancellation into an ordinary failure.
  const auto stopNow = [&cancelState]() -> std::optional<net::ErrorCode> {
    const auto c = cancelState.cancelled();
    if ((c & net::asio::cancellation_type::terminal) != net::asio::cancellation_type::none) {
      return net::ErrorCode(net::asio::error::operation_aborted);
    }
    if (c != net::asio::cancellation_type::none) return make_error_code(Errc::WalkIncomplete);
    return std::nullopt;
  };

  Oid current = base;
  std::int32_t maxRepetitions = options.maxRepetitions;

  for (;;) {
    if (const auto stop = stopNow()) co_return WalkResult{*stop};

    const Pdu req = maxRepetitions <= 0 ? makePdu(PduType::GetNext, toVarbinds({current}))
                                        : makeBulkPdu(toVarbinds({current}), 0, maxRepetitions);

    auto [ec, resp] = co_await doRequest(target, auth, req);
    // tooBig means the Response did not fit, not that the request was wrong: ask for less and try
    // again. Only a deliberately misbehaving Simulator reaches this path (ADR-0006).
    if (ec == ErrorStatus::TooBig && maxRepetitions > 1) {
      maxRepetitions /= 2;
      continue;
    }
    if (ec) {
      // A cancellation that cut the exchange short is an incomplete Walk, not a fault of the
      // Target's -- a total cancel against a silent Target must not surface as a Timeout.
      if (const auto stop = stopNow()) co_return WalkResult{*stop};
      co_return WalkResult{ec};
    }
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

net::Awaitable<Client::CollectResult> Client::doWalkCollect(Target target, Auth auth, Oid base,
                                                            WalkOptions options) {
  std::vector<Varbind> collected;
  auto [ec] = co_await doWalk(std::move(target), std::move(auth), std::move(base), options,
                              [&collected](std::span<const Varbind> batch) {
                                collected.insert(collected.end(), batch.begin(), batch.end());
                                return true;
                              });
  // ADR-0004 again: `total` keeps what arrived, `terminal` drops everything immediately.
  if (ec == net::asio::error::operation_aborted) collected.clear();
  co_return CollectResult{ec, std::move(collected)};
}

}  // namespace snmpio
