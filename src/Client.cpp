#include <snmpio/Client.hpp>
#include <snmpio/detail/CacheView.hpp>

#include "MessageIds.hpp"
#include "Secret.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
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
ScopedPdu discoveryScopedPdu(Octets contextEngineId) {
  ScopedPdu s;
  s.contextEngineId = std::move(contextEngineId);
  s.pdu.type = PduType::Get;
  return s;
}

// The completion of an Engine Discovery, which no operation awaits. It does not throw by design, so
// an exception here is bad_alloc or a programming error, and it leaves run() the way spawn lets one
// out of an operation. `detached` would swallow it, and leave every request that discovery was
// serving waiting forever, in silence. The receive loop has a completion of its own (socketFor).
constexpr auto rethrow = [](const std::exception_ptr& e) {
  if (e) std::rethrow_exception(e);
};

// What a request's cancellation state records: every type that has reached it, not only the last.
// Asio's state overwrites what it holds with each signal (`cancelled_ = in_filter_(in)`), although
// cancelled() is documented as the types "that have been triggered" and clear() takes a mask. So a
// total signal that follows a terminal one before the request has acted on it would read as total
// alone, and the dropped request would go back to waiting out its deadline. A filter is where
// Asio lets an operation shape that record; this one passes every type, as
// enable_total_cancellation does, and keeps it. Nothing here clears the state, and a clear()
// would last only until the next signal brought back what this has kept.
class EveryCancellationSoFar {
 public:
  net::asio::cancellation_type_t operator()(net::asio::cancellation_type_t type) noexcept {
    m_seen |= type;
    return m_seen;
  }

 private:
  net::asio::cancellation_type_t m_seen = net::asio::cancellation_type::none;
};

// The two halves of ADR-0004's split, in one place so they cannot drift apart: terminal drops a
// Walk and says so with operation_aborted, total stops it and reports it incomplete. Nothing else
// may turn a cancellation into an ordinary failure.
std::optional<net::ErrorCode> cancellationEnding(const net::asio::cancellation_state& state) {
  const auto c = state.cancelled();
  if ((c & net::asio::cancellation_type::terminal) != net::asio::cancellation_type::none) {
    return net::ErrorCode(net::asio::error::operation_aborted);
  }
  if (c != net::asio::cancellation_type::none) return make_error_code(Errc::WalkIncomplete);
  return std::nullopt;
}

// Target.hpp's documented bounds. Refused rather than clamped: a value past them is a bug in the
// caller, and quietly rewriting it would hide the bug and send something other than was asked.
template <typename T>
constexpr bool withinCeiling(T value, T ceiling) noexcept {
  return value >= T{} && value <= ceiling;
}

bool targetInRange(const Target& target) noexcept {
  return withinCeiling(target.retries, retriesCeiling);
}

// A request's: its Target's and, for a GETBULK, both of its parameters. A negative nonRepeaters is
// outside the PDU's own range, non-repeaters INTEGER (0..max-bindings) in RFC 3416 section 3. None
// past the OIDs given needs refusing: section 4.2.3 reads it as all of them, and it never makes an
// Agent send more.
bool requestInRange(const Target& target, const Pdu& pdu) noexcept {
  if (!targetInRange(target)) return false;
  if (pdu.type != PduType::GetBulk) return true;
  return pdu.nonRepeaters() >= 0 && withinCeiling(pdu.maxRepetitions(), maxRepetitionsCeiling);
}

// What is wrong with the Credentials a request travels under, if anything
// (detail::credentialsFault). A Community has nothing to check.
std::optional<Errc> authFault(const std::variant<Community, Credentials>& auth) noexcept {
  const auto* creds = std::get_if<Credentials>(&auth);
  return creds == nullptr ? std::nullopt : detail::credentialsFault(*creds);
}

// A Walk's: its Target's retries, and the WalkOptions. A negative maxRepetitions would otherwise
// read as GETNEXT, and a negative time limit as one already reached.
bool walkInRange(const Target& target, const WalkOptions& options) noexcept {
  return targetInRange(target) && withinCeiling(options.maxRepetitions, maxRepetitionsCeiling) &&
         (!options.timeLimit || *options.timeLimit >= std::chrono::milliseconds::zero());
}

// Ends a scope by clearing a cancellation slot, so that a handler left in it cannot outlive the
// state it captured -- an exception from the awaited operation included.
class SlotClearer {
 public:
  explicit SlotClearer(net::asio::cancellation_slot slot) noexcept : m_slot(slot) {}
  SlotClearer(const SlotClearer&) = delete;
  SlotClearer& operator=(const SlotClearer&) = delete;
  SlotClearer(SlotClearer&&) = delete;
  SlotClearer& operator=(SlotClearer&&) = delete;
  ~SlotClearer() {
    if (m_slot.is_connected()) m_slot.clear();
  }

 private:
  net::asio::cancellation_slot m_slot;
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

  explicit Impl(net::Strand strand) : m_strand(std::move(strand)) {}

  // detail::CacheView's, and only safe where it says.
  [[nodiscard]] detail::CacheCounts cacheCounts() const noexcept {
    return {.masterKeys = m_masterKeys.size(),
            .localizedKeys = m_keys.size(),
            .masterKeyDerivations = m_masterKeyDerivations};
  }

  // Stopping, from any thread. The flag is set at once, and the strand checks it before each
  // exchange and each Batch, so nothing begins once the strand has seen it; the cleanup that needs
  // the strand follows on it. From another thread the strand may already be past a check, mid-send
  // or mid-Batch. A send is left to finish on its own; a Batch is waited for (ADR-0009's
  // amendment), so that no handler is still running once this returns.
  static void stop(const Ref& self) {
    if (!self->m_stopping.exchange(true)) {
      // Dispatched rather than posted: stop() is usually the last thing before the io_context
      // drains, and a posted cleanup would never run. Owning `self`, because the Client that asked
      // may be gone by the time it runs.
      net::asio::dispatch(self->m_strand, [self] { self->finishStopping(); });
    }
    // Every call waits, not just the first: a second thread stopping while the first is still
    // waiting is owed the same guarantee.
    self->awaitBatchDelivery();
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
    SecretOctets authKey;  // the Localized Key this exchange is authenticated with
    SecretOctets privKey;  // and the one it is encrypted with, at authPriv
    Octets engineId;       // the Authoritative Engine addressed; empty while discovering
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
    // Whether the pair above is a baseline from discovery's time-sync phase, kept current since by
    // signed replies, and not doubted since. A noAuthNoPriv discovery learns the engineID and
    // nothing trustworthy about its clock, so the first authenticated request against the same
    // Engine still has to synchronise. Only discoverEngine's time-sync phase sets it; handleReport
    // clears it when a signed Report says the pair is wrong (ADR-0010). Nothing else may set it
    // (#43). A Response the Engine signed just before its boots went backwards can still be in
    // flight when handleReport clears the flag. It is timely by RFC 3414 section 3.2 step 7(b)(1),
    // and observeEngineTime adopts its pair, but it says nothing about the Engine having been
    // rediscovered since. Had it set the flag, the rediscovery that clearing it asked for would
    // skip its time-sync phase, and the retry would go out at the old boots.
    bool timeSynced = false;
  };

  // A discovery in flight. The timer is an event, not a deadline: waiters park on it and the
  // discovering coroutine cancels it to wake them all. Same trick as Pending's.
  struct Discovery {
    explicit Discovery(const net::Executor& ex) : done(ex) {}
    net::SteadyTimer done;
    net::ErrorCode ec;
    bool finished = false;
    // Whether it runs the time-sync phase: it does when the request that started it authenticates.
    bool synchronises = false;
    // What the discovery threw, if it did: each waiter rethrows it, so that every request it was
    // serving leaves run() the way the discovery itself does, rather than waiting forever.
    std::exception_ptr failure;

    // The time-sync phase a discovery that does not synchronise owes the requests queued behind it
    // that authenticate: its identity phase records only an unsigned pair, which they may not
    // carry. The first such request leaves its Credentials, and runDiscovery goes on to a second
    // pass with them before it wakes anyone. Its outcome is theirs alone; the requests that needed
    // only the engineID have ec. Every request that authenticates shares the one pass, as it would
    // behind a discovery that an authenticated request started.
    struct OwedSync {
      Credentials credentials;
      net::ErrorCode ec;
    };
    std::optional<OwedSync> owedSync;

    // Whether a request at this level needs the time-sync phase this discovery does not run.
    [[nodiscard]] bool owesSyncTo(SecurityLevel level) const {
      return isAuthenticated(level) && !synchronises;
    }
    // A request queued behind this discovery. If it is owed the time-sync phase and is the first
    // to be, its Credentials are the ones the second pass runs with.
    void queue(const Credentials& creds) {
      if (owesSyncTo(creds.level) && !owedSync) owedSync = OwedSync{.credentials = creds, .ec = {}};
    }
    // How it went for a request at this level.
    [[nodiscard]] net::ErrorCode outcomeFor(SecurityLevel level) const {
      return owesSyncTo(level) && owedSync ? owedSync->ec : ec;
    }
  };

  // Stopping's second half, on the strand: closes the sockets, which ends the receive loops, and
  // wakes everything waiting, which then finds the flag set and completes with ClientStopped.
  void finishStopping();

  // Marks the calling thread as the one delivering a Batch, for as long as this lives -- which is
  // never across a suspension (see deliverBatch).
  class BatchDelivery {
   public:
    explicit BatchDelivery(std::atomic<std::thread::id>& deliverer) : m_deliverer(deliverer) {
      m_deliverer.store(std::this_thread::get_id());
    }
    ~BatchDelivery() {
      m_deliverer.store(std::thread::id{});
      m_deliverer.notify_all();
    }
    BatchDelivery(const BatchDelivery&) = delete;
    BatchDelivery& operator=(const BatchDelivery&) = delete;
    BatchDelivery(BatchDelivery&&) = delete;
    BatchDelivery& operator=(BatchDelivery&&) = delete;

   private:
    std::atomic<std::thread::id>& m_deliverer;
  };

  // Hands one Batch to the handler, unless it is empty or Stopping has begun: the error the Walk
  // then ends with, or nothing to carry on. Not a coroutine, so the deliverer can never be recorded
  // across a suspension.
  std::optional<net::ErrorCode> deliverBatch(const BatchHandler& onBatch,
                                             std::span<const Varbind> batch) {
    // doWalk's own check settles a stop() the strand has already seen; this one settles a stop()
    // on another thread racing the delivery. The deliverer is recorded first and the flag read
    // second, the mirror image of stop(), so either this sees the flag or stop() sees the delivery
    // and waits for the handler to return.
    if (batch.empty()) return std::nullopt;
    const BatchDelivery delivery(m_deliverer);
    if (m_stopping) return make_error_code(Errc::ClientStopped);
    if (!onBatch(batch)) return make_error_code(Errc::WalkIncomplete);
    return std::nullopt;
  }

  // Stopping's wait, after the flag is set: returns once no Batch is being delivered on another
  // thread. The delivering thread's own stop never waits -- it is inside the handler it would be
  // waiting for -- and neither does one on the strand, where no other thread can be delivering.
  // The same arrangement as libstdc++'s std::stop_callback, whose destructor waits for its
  // callback only when another thread is running it.
  void awaitBatchDelivery() const {
    const auto caller = std::this_thread::get_id();
    for (auto id = m_deliverer.load(); id != std::thread::id{} && id != caller;
         id = m_deliverer.load()) {
      m_deliverer.wait(id);
    }
  }

  net::UdpSocket* socketFor(const Ref& self, const net::UdpEndpoint& to, net::ErrorCode& ec);
  net::Awaitable<void> receiveLoop(Ref self, net::UdpSocket* sock);
  void deliverV2c(std::span<const std::byte> datagram, const net::UdpEndpoint& from);
  void deliverV3(std::span<const std::byte> datagram, const net::UdpEndpoint& from);
  [[nodiscard]] bool timely(const net::UdpEndpoint& from, const UsmParameters& security) const;
  void observeEngineTime(const net::UdpEndpoint& from, const UsmParameters& security);
  static RequestResult toResult(const Pdu& response);

  // One transmission of an exchange, built afresh for each: the datagram that carries this ID as
  // its Message ID at v3, and as its request-id at both versions.
  using Encoder = std::function<std::vector<std::byte>(std::int32_t id, net::ErrorCode& ec)>;

  // The Encoder for a v3 exchange: the message as given, under the ID each transmission draws, and
  // under the protocols and keys `pending` holds -- those its reply is checked with, so the two
  // cannot differ. None, at noAuthNoPriv.
  static Encoder v3Encoder(V3Header header, UsmParameters usm, ScopedPdu scoped,
                           const std::shared_ptr<Pending>& pending);

  // The shared half of every exchange: send, wait, retransmit, and observe cancellation. Returns
  // an empty ErrorCode when `pending` was answered.
  net::Awaitable<net::ErrorCode> transact(Ref self, Target target, Encoder encode,
                                          std::shared_ptr<Pending> pending);

  // RFC 3414 section 4, in two phases: the engineID, and then -- only when authenticating -- the
  // boots/time pair. At most one runs per Target; anything else arriving waits on it.
  net::Awaitable<net::ErrorCode> ensureEngine(Ref self, Target target, Credentials creds);
  net::Awaitable<void> runDiscovery(Ref self, Target target, Credentials creds,
                                    std::shared_ptr<Discovery> discovery);
  // By reference, which the coroutine check forbids for the dangling it usually means: here the one
  // caller, runDiscovery, awaits this to the end, and the Credentials outlive that wait -- its own,
  // in its frame, or those a queued request left on the Discovery it holds (Discovery::OwedSync).
  // By value, GCC 16 raises the spurious -Wmismatched-new-delete described in transact.
  net::Awaitable<net::ErrorCode> discoverEngine(
      Ref self, Target target,
      const Credentials& creds);  // NOLINT(cppcoreguidelines-avoid-reference-coroutine-parameters)
  // The Engine currently believed to answer at this endpoint, or nullptr if none is known.
  EngineState* engineAt(const net::UdpEndpoint& endpoint);

  // The Master Key for one secret: the one the Credentials carry, or the one this Client derived
  // from the password -- once, the first time it met it, since the derivation is a megabyte hash
  // and deliberately expensive (CONTEXT.md). Empty, with `ec` set, if there is none.
  std::span<const std::byte> masterKey(const detail::Secret& secret, net::ErrorCode& ec);
  // One secret's key, localized per Engine from its Master Key, and cached: a short hash for the
  // authentication key, but a second megabyte for a Reeder privacy key, whose extension runs
  // password-to-key again.
  const SecretOctets* localizedKey(const detail::Secret& secret, const Octets& engineId,
                                   net::ErrorCode& ec);
  // The keys a message at the Credentials' Security Level goes out with: the authentication key
  // wherever it authenticates, the privacy key wherever it encrypts, nullptr for either it does
  // not use. Both point into the cache, which never evicts (threat model B2).
  struct LocalizedKeys {
    const SecretOctets* auth = nullptr;
    const SecretOctets* priv = nullptr;
  };
  LocalizedKeys localizedKeys(const Credentials& creds, const Octets& engineId, net::ErrorCode& ec);

  // What a Report means for the request that provoked it: an ErrorCode to fail with, or nothing
  // when it named something we can act on and ask again about. `cancelled` is the request's
  // cancellation state as the Report arrived, since a cancelled request never asks again.
  std::optional<net::ErrorCode> handleReport(const net::UdpEndpoint& from, const Pending& pending,
                                             bool mayRetry, net::asio::cancellation_type cancelled);

  // A Walk's time limit (WalkOptions::timeLimit): a timer, and the slot each of the Walk's
  // requests runs on so that the timer can end it in whichever wait it is. `fired` is how the Walk
  // tells that ending from the caller's cancellation.
  struct WalkTimeLimit {
    explicit WalkTimeLimit(const net::Executor& ex) : timer(ex) {}
    net::SteadyTimer timer;
    net::asio::cancellation_signal signal;
    std::chrono::steady_clock::time_point at;
    bool fired = false;  // the timer expired, and ended the Outstanding Request, if there was one

    // By the clock as well as by the flag: the timer's handler may be queued behind the strand's
    // current work when the limit passes.
    [[nodiscard]] bool reached() const { return fired || std::chrono::steady_clock::now() >= at; }
  };

  // Starts the timer, which ends the Walk's Outstanding Request, if any, once `limit` has passed.
  static std::shared_ptr<WalkTimeLimit> armTimeLimit(const net::Executor& ex,
                                                     std::chrono::milliseconds limit);

  // Awaits one of a time-limited Walk's requests on the time limit's slot rather than the Walk's
  // own, so that reaching the limit can end it.
  net::Awaitable<RequestResult> underTimeLimit(std::shared_ptr<WalkTimeLimit> limit,
                                               net::asio::cancellation_slot walkSlot,
                                               net::Awaitable<RequestResult> request);

  // Why an operation will not start, in the order every operation keeps: Stopping first, so that
  // one initiated after it completes with ClientStopped whatever else is wrong with it; then the
  // arguments (requestInRange or walkInRange); then the Credentials (authFault) -- all before
  // anything is sent or discovered. Both checks are the caller's to make, since what is in range
  // depends on the operation.
  [[nodiscard]] std::optional<net::ErrorCode> refusal(bool argumentsInRange,
                                                      std::optional<Errc> authProblem) const {
    if (m_stopping) return make_error_code(Errc::ClientStopped);
    if (!argumentsInRange) return make_error_code(Errc::ArgumentOutOfRange);
    if (authProblem) return make_error_code(*authProblem);
    return std::nullopt;
  }

  // What a Walk ends with when one of its requests failed. A cancellation that cut the exchange
  // short is an incomplete Walk, not a fault of the Target's -- a total cancel against a silent
  // Target must not surface as a Timeout. So is the time limit dropping it: the Walk ran out of
  // time, and the Target did nothing wrong.
  static net::ErrorCode walkFailure(const net::ErrorCode& ec,
                                    const net::asio::cancellation_state& state,
                                    const WalkTimeLimit* timeLimit) {
    if (const auto stop = cancellationEnding(state)) return *stop;
    if (timeLimit != nullptr && timeLimit->fired && ec == net::asio::error::operation_aborted) {
      return make_error_code(Errc::WalkIncomplete);
    }
    return ec;
  }

  // What one reply adds to a Walk: the Batch, and how the Walk goes on after it -- asks for More,
  // has seen the end of the Subtree, reached its Varbind limit with more of the Subtree to come, or
  // was sent a NonIncreasing OID. `room` is how many more Varbinds the limit allows. Advances
  // `current` past the Batch.
  enum class WalkNext { More, SubtreeEnded, LimitReached, NonIncreasing };
  struct WalkStep {
    std::vector<Varbind> batch;
    WalkNext next = WalkNext::More;
  };
  static WalkStep takeBatch(const Oid& base, Oid& current, std::vector<Varbind>& varbinds,
                            std::size_t room);

  // Observe both cancellation types rather than throwing on either, once per operation.
  static net::Awaitable<void> observeBothCancellationTypes();

  // The request itself, by SNMP version, with nothing asked first: doRequest asks refusal(), and a
  // Walk asks it once, before its first request, and doWalkRequest before each.
  net::Awaitable<RequestResult> doExchange(Ref self, Target target, Auth auth, Pdu pdu);
  // One of a Walk's requests, whose arguments were judged before the first. Stopping is asked again
  // of each, since each begins after the Batch before it: a Client stopped meanwhile must not start
  // an Engine Discovery or derive keys only for transact to refuse the send.
  net::Awaitable<RequestResult> doWalkRequest(Ref self, Target target, Auth auth, Pdu pdu);
  net::Awaitable<RequestResult> doRequestV2c(Ref self, Target target, Community community, Pdu pdu);
  net::Awaitable<RequestResult> doRequestV3(Ref self, Target target, Credentials creds, Pdu pdu);

  net::Strand m_strand;
  // One of the two members that are not the strand's alone: written once, by stop() on whichever
  // thread called it -- the strand itself when a receive loop throws -- and read on the strand.
  // That is what lets Stopping take effect before the strand gets round to the cleanup.
  std::atomic<bool> m_stopping = false;
  // The other: the thread delivering a Batch, or no thread. Written on the strand around each
  // handler call and read by stop(). Each side writes its own atomic and then reads the other's,
  // all sequentially consistent, so at least one sees the other: either the strand finds the flag
  // set and calls no handler, or stop() finds the delivery and waits for it (ADR-0009's amendment).
  std::atomic<std::thread::id> m_deliverer;
  std::optional<net::UdpSocket> m_v4;
  std::optional<net::UdpSocket> m_v6;
  std::unordered_map<std::int32_t, std::shared_ptr<Pending>> m_pending;
  // Keyed on engineID with a separate endpoint->engineID index, as ADR-0003 requires: one Engine
  // reachable at two Targets is one cache entry, discovered once. The in-flight map below is keyed
  // on the endpoint of necessity -- learning which Engine is there is what discovery is for.
  std::map<Octets, EngineState> m_engines;
  std::map<net::UdpEndpoint, Octets> m_engineAt;
  std::map<net::UdpEndpoint, std::shared_ptr<Discovery>> m_discovering;
  // Master Keys this Client derived, per (hash, password) -- the password as a passwordDigest
  // under m_digestKey rather than in plaintext, so that no password outlives the Credentials that
  // brought it (threat model S4). Master Keys the caller supplied are not copied here; they are
  // already as cheap to reach as a cache could make them. Every key and digest the Client keeps,
  // here and below, wipes itself when it goes (threat model S5).
  std::map<std::pair<AuthProtocol, SecretOctets>, SecretOctets> m_masterKeys;
  // The Client's own random key for passwordDigest, so that two Clients' digests of one password
  // differ and none can be looked up in a table built before the Client existed. Drawn the first
  // time a password needs it, so a Client handed only Master Keys never draws one.
  SecretOctets m_digestKey;
  std::size_t m_masterKeyDerivations = 0;  // for detail::CacheView, and nothing else
  // (engineID, hash, Master Key, privacy protocol) -- ADR-0003's (master key, engineID), whether
  // the Master Key was derived above or supplied. The privacy protocol is part of the key rather
  // than of the value because it decides how far the derivation is extended: PrivProtocol::None is
  // the authentication key's row.
  std::map<std::tuple<Octets, AuthProtocol, SecretOctets, PrivProtocol>, SecretOctets> m_keys;
  // One generator for both the v3 msgID and the PDU request-id, so that the two protocols cannot
  // collide in m_pending -- which is keyed on the msgID for v3, as CONTEXT.md requires, because a
  // message we cannot open must still be attributable. Unpredictable, and fresh for every
  // transmission (see transact).
  detail::MessageIds m_ids;
};

Client::Client(const net::Executor& ex)
    : m_strand(net::asio::make_strand(ex)), m_impl(std::make_shared<Impl>(m_strand)) {}

// ADR-0009. Waits for nothing that has not already started: this may be running on the strand,
// inside one of the Client's own completions, or with the io_context not running at all, and
// waiting for the strand would deadlock in each. The one wait is for a Batch handler already
// running on another thread, which needs nothing from the io_context to return (see stop()).
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
  //
  // A loop that throws stops the Client before rethrowing: it serves every Target on its socket, so
  // the fault is the Client's own, and anything less leaves the socket open with nothing reading
  // it (ADR-0009's amendment).
  net::asio::co_spawn(m_strand, receiveLoop(self, &*slot), [self](const std::exception_ptr& e) {
    if (!e) return;
    stop(self);
    std::rethrow_exception(e);
  });
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
  // The request-id is in the clear for anyone on the path and UDP is trivially spoofable, so a
  // Response only counts if it came back from the Target we asked and quoted the Community we used.
  if (from != it->second->from || msg->community != it->second->community) return;

  it->second->response = std::move(msg->pdu);
  it->second->answered = true;
  it->second->timer.cancel();
}

// Everything here is a reason to *drop* a datagram rather than to fail the request that it claims
// to answer. UDP is spoofable and the msgID is in the clear, so a caller whose request could be
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
    // Each transmission carries its Message ID as its request-id too, so a Response must quote
    // the pair one transmission went out with -- not one transmission's msgID and another's
    // request-id.
    if (msg->scoped.pdu.requestId != it->first) return;
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
  // And never marks the Engine synced: see EngineState::timeSynced (#43). There is no early return
  // for an unsynced Engine above because it would save nothing: a pair written then is never
  // relied on, since timely() ignores it and the next discovery overwrites it before an
  // authenticated request carries it. (The early return also trips the spurious GCC 16
  // -Wmismatched-new-delete described in transact.)
}

Client::Impl::Encoder Client::Impl::v3Encoder(V3Header header, UsmParameters usm, ScopedPdu scoped,
                                              const std::shared_ptr<Pending>& pending) {
  return [header, usm = std::move(usm), scoped = std::move(scoped), pending](
             std::int32_t id, net::ErrorCode& ec) mutable {
    header.msgId = id;
    scoped.pdu.requestId = id;
    return encodeV3Message(header, usm, scoped, pending->authProtocol, pending->authKey, ec,
                           pending->privProtocol, pending->privKey);
  };
}

net::Awaitable<net::ErrorCode> Client::Impl::transact(Ref self, Target target, Encoder encode,
                                                      std::shared_ptr<Pending> pending) {
  // Before the socket, so that nothing reopens one Stopping has closed.
  if (m_stopping) co_return make_error_code(Errc::ClientStopped);
  net::ErrorCode ec;
  net::UdpSocket* sock = socketFor(self, target.endpoint, ec);
  if (ec) co_return ec;

  // Every transmission's ID, each mapped to this request until it completes, so that a reply to
  // any of them counts: one delayed past its deadline still answers the request after the
  // retransmission has gone out (CONTEXT.md, Message ID). None can belong to another Outstanding
  // Request, since m_ids repeats nothing short of 2^31 transmissions.
  std::vector<std::int32_t> ids;
  ids.reserve(static_cast<std::size_t>(target.retries) + 1);

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
    // A fresh ID for each transmission, as RFC 3412 section 6.2 asks: a retransmission that
    // repeated one would tell an observer which reply to forge for longest. Re-encoded rather than
    // patched, so that at authPriv each transmission has a salt of its own as well.
    const std::int32_t id = m_ids.next(ec);
    if (ec) break;
    const auto datagram = encode(id, ec);
    if (ec) break;
    m_pending.emplace(id, pending);
    ids.push_back(id);

    co_await sock->async_send_to(net::asio::buffer(datagram), target.endpoint,
                                 redirect_error(use_awaitable, ec));
    // Stopping may have begun while the send was in flight, and its cleanup has then already
    // cancelled a timer this has not armed yet -- arming it now would wait out a whole deadline
    // before reporting ClientStopped. A reply can overtake the send the same way: with several
    // threads running the io_context, the send's completion and the reply's reach the strand from
    // different threads, in either order, and the reply's cancel finds no wait to wake. So can a
    // terminal signal: one that lands once the send has completed has nothing left to cancel, and
    // the wait armed after it would never hear of it.
    if (ec || m_stopping || pending->answered || aborted()) break;

    pending->timer.expires_after(target.timeout);
    // The wait's own ErrorCode says nothing useful: the receive loop cancels this timer to wake
    // us, so operation_aborted is the success path and expiry is the retry path.
    [[maybe_unused]] net::ErrorCode waitEc;
    co_await pending->timer.async_wait(redirect_error(use_awaitable, waitEc));
    if (pending->answered || m_stopping || aborted()) break;

    if (softCancelled()) {
      // Total lets the exchange in flight finish: wait out the rest of the deadline, so a reply
      // inside it still counts, on a slot only terminal reaches, so terminal still drops the
      // request at once (#74). No retransmission and no new exchange, which is also where the
      // Walk above stops at a Batch boundary (ADR-0004). A child state is Asio's own way to
      // narrow a slot, as its composed operations do.
      const net::asio::cancellation_state terminalOnly(cancelState.slot(),
                                                       net::asio::enable_terminal_cancellation());
      co_await pending->timer.async_wait(net::asio::bind_cancellation_slot(
          terminalOnly.slot(), redirect_error(use_awaitable, waitEc)));
      break;
    }
  }

  for (const auto id : ids) m_pending.erase(id);

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
// drop it before any of the waits below could act on it. The state keeps every type it has seen,
// so terminal is never lost to a total signal behind it. Per coroutine, at its start -- a Walk
// calls it and so does each request underneath, which is why doWalk re-reads the state it needs
// rather than holding it.
net::Awaitable<void> Client::Impl::observeBothCancellationTypes() {
  co_await net::asio::this_coro::throw_if_cancelled(false);
  co_await net::asio::this_coro::reset_cancellation_state(EveryCancellationSoFar(),
                                                          net::asio::enable_total_cancellation());
}

net::Awaitable<Client::RequestResult> Client::Impl::doRequest(Ref self, Target target, Auth auth,
                                                              Pdu pdu) {
  if (const auto refused = refusal(requestInRange(target, pdu), authFault(auth))) {
    co_return RequestResult{*refused, Response{}};
  }
  co_return co_await doExchange(self, std::move(target), std::move(auth), std::move(pdu));
}

net::Awaitable<Client::RequestResult> Client::Impl::doWalkRequest(Ref self, Target target,
                                                                  Auth auth, Pdu pdu) {
  if (m_stopping) co_return RequestResult{make_error_code(Errc::ClientStopped), Response{}};
  co_return co_await doExchange(self, std::move(target), std::move(auth), std::move(pdu));
}

net::Awaitable<Client::RequestResult> Client::Impl::doExchange(Ref self, Target target, Auth auth,
                                                               Pdu pdu) {
  if (const auto* community = std::get_if<Community>(&auth)) {
    co_return co_await doRequestV2c(self, std::move(target), *community, std::move(pdu));
  }
  co_return co_await doRequestV3(self, std::move(target), std::move(std::get<Credentials>(auth)),
                                 std::move(pdu));
}

net::Awaitable<Client::RequestResult> Client::Impl::doRequestV2c(Ref self, Target target,
                                                                 Community community, Pdu pdu) {
  co_await observeBothCancellationTypes();

  const auto pending = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
  pending->from = target.endpoint;
  pending->community = community.value;

  auto encode = [community = std::move(community.value), pdu = std::move(pdu)](
                    std::int32_t id, net::ErrorCode& ec) mutable {
    pdu.requestId = id;
    return encodeV2cMessage(community, pdu, ec);
  };
  const auto ec = co_await transact(self, std::move(target), std::move(encode), pending);
  if (ec) co_return RequestResult{ec, Response{}};
  co_return toResult(pending->response);
}

std::span<const std::byte> Client::Impl::masterKey(const detail::Secret& secret,
                                                   net::ErrorCode& ec) {
  ec = {};
  if (const SecretOctets* supplied = secret.suppliedMasterKey()) return *supplied;
  if (m_digestKey.empty()) {
    m_digestKey = detail::randomDigestKey(ec);
    if (ec) return {};
  }
  // A keyed digest, not a bare hash: a bare one could be checked against a table of guesses built
  // for any Client. It is still far cheaper to guess against than the megabyte-hashed Master Key
  // beside it, which is why it is keyed per Client and not kept anywhere else.
  auto digest = detail::passwordDigest(m_digestKey, secret.password(), ec);
  if (ec) return {};
  auto cacheKey = std::make_pair(secret.authProtocol(), std::move(digest));
  const auto it = m_masterKeys.find(cacheKey);
  if (it != m_masterKeys.end()) return it->second;
  auto derived = passwordToKey(secret.authProtocol(), secret.password(), ec);
  if (ec) return {};
  ++m_masterKeyDerivations;
  return m_masterKeys.emplace(std::move(cacheKey), std::move(derived)).first->second;
}

const SecretOctets* Client::Impl::localizedKey(const detail::Secret& secret, const Octets& engineId,
                                               net::ErrorCode& ec) {
  const auto master = masterKey(secret, ec);
  if (ec) return nullptr;
  // The user name is deliberately not part of the key: what the derivation consumes is the Master
  // Key, the protocols and the engineID, so two users sharing a password share a key.
  auto cacheKey =
      std::make_tuple(engineId, secret.authProtocol(), SecretOctets(master.begin(), master.end()),
                      secret.privProtocol());
  const auto it = m_keys.find(cacheKey);
  if (it != m_keys.end()) return &it->second;
  auto derived = detail::localizedKeyFor(secret, master, engineId, ec);
  if (ec) return nullptr;
  return &m_keys.emplace(std::move(cacheKey), std::move(derived)).first->second;
}

Client::Impl::LocalizedKeys Client::Impl::localizedKeys(const Credentials& creds,
                                                        const Octets& engineId,
                                                        net::ErrorCode& ec) {
  ec = {};
  LocalizedKeys keys;
  if (isAuthenticated(creds.level)) {
    keys.auth = localizedKey(detail::Secret::auth(creds), engineId, ec);
    if (ec) return {};
  }
  if (isEncrypted(creds.level)) {
    keys.priv = localizedKey(detail::Secret::priv(creds), engineId, ec);
    if (ec) return {};
  }
  return keys;
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
    // One that will stop after its identity phase leaves this request without a pair it may
    // carry, so it asks that discovery to go on and synchronise.
    discovery->queue(creds);
  } else {
    discovery = std::make_shared<Discovery>(m_strand);
    discovery->synchronises = isAuthenticated(creds.level);
    // A timer used as an event rather than a deadline: it never expires on its own, and cancelling
    // it is how every waiter is woken at once.
    discovery->done.expires_at(std::chrono::steady_clock::time_point::max());
    m_discovering.emplace(target.endpoint, discovery);
    // Spawned on its own rather than awaited, and this is the point of ADR-0003's "Engine
    // Discovery outlives any individual waiter": the discovery belongs to the Engine, not to
    // whichever request happened to arrive first, so cancelling that request must not cancel what
    // everyone else is queued behind. The Credentials are copied, not moved: this request reads
    // their level after the wait. Reading it into a local first instead trips the spurious GCC 16
    // -Wmismatched-new-delete described in transact.
    net::asio::co_spawn(m_strand, runDiscovery(self, std::move(target), creds, discovery), rethrow);
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
  co_return discovery->outcomeFor(creds.level);
}

net::Awaitable<void> Client::Impl::runDiscovery(Ref self, Target target, Credentials creds,
                                                std::shared_ptr<Discovery> discovery) {
  const auto endpoint = target.endpoint;
  try {
    discovery->ec = co_await discoverEngine(self, target, creds);
    // A request that authenticates queued behind this one while it ran without authenticating
    // (see Discovery::OwedSync). The second pass is a whole discoverEngine, so it repeats the
    // identity phase before the time-sync one, as a later authenticated request would. It runs even
    // if the request that asked for it has since been cancelled: like the first pass, it belongs to
    // the Engine (ADR-0003). The requests that needed only the engineID wait for it too, since one
    // timer wakes every waiter. That costs them its round trips, but only when the two levels meet
    // one Engine at once. Spelled out through discovery->owedSync each time: binding a reference
    // to it trips the spurious GCC 16 -Wmismatched-new-delete described in transact.
    if (discovery->owedSync) {
      discovery->owedSync->ec = discovery->ec;
      if (!discovery->ec) {
        discovery->owedSync->ec =
            co_await discoverEngine(self, std::move(target), discovery->owedSync->credentials);
      }
    }
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
net::Awaitable<net::ErrorCode> Client::Impl::discoverEngine(
    Ref self, Target target,
    const Credentials& creds) {  // NOLINT(cppcoreguidelines-avoid-reference-coroutine-parameters)
  const auto identify = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
  identify->from = target.endpoint;
  identify->v3 = true;

  V3Header header;
  header.level = SecurityLevel::NoAuthNoPriv;
  auto identifyEncoder = v3Encoder(header, UsmParameters{}, discoveryScopedPdu({}), identify);
  auto ec = co_await transact(self, target, std::move(identifyEncoder), identify);
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

  const auto [key, privKey] = localizedKeys(creds, engineId, ec);
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
  sync->timeSyncPhase = true;

  V3Header syncHeader;
  syncHeader.level = creds.level;
  UsmParameters usm;
  usm.engineId = engineId;
  usm.userName = creds.userName;  // boots and time left at zero: being wrong is the point

  // Sent at the Credentials' own level rather than downgraded to authNoPriv: an Engine may enforce
  // a minimum level per user, and being refused for asking too politely would end discovery. The
  // Engine never has to decrypt it -- RFC 3414 section 3.2 rejects it as untimely at step 7, one
  // step before decryption -- and the Report that rejection produces is the point of sending it.
  auto syncEncoder = v3Encoder(syncHeader, std::move(usm), discoveryScopedPdu(engineId), sync);
  ec = co_await transact(self, std::move(target), std::move(syncEncoder), sync);
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
                                                         const Pending& pending, bool mayRetry,
                                                         net::asio::cancellation_type cancelled) {
  const auto counter = usmStatsCounter(pending.response);
  if (!mayRetry || !counter) return reportError(counter);

  const bool retryable =
      *counter == usmStatsNotInTimeWindows || *counter == usmStatsUnknownEngineIds;
  if (!retryable) return reportError(counter);

  // What every path below returns: nothing, to ask again, or operation_aborted for a cancelled
  // request. A total signal let this Report count as the reply on its way, but a retryable Report
  // is not an answer, only a call for another exchange, and total forbids one. The waits a second
  // attempt would enter cannot hear the signal either, because it was emitted before they were
  // armed (#73). The Reports above are answers -- they name a failure -- so they keep their own
  // error, cancelled or not. Terminal never gets this far: transact has already dropped the
  // exchange.
  //
  // The cache is still acted on first. What the Report says about the Engine is as true for the
  // next request as it would have been for the retry, and ADR-0010's forgetting must not hinge on
  // whether the request that heard it is still wanted.
  const auto retryOrAbort =
      cancelled == net::asio::cancellation_type::none
          ? std::optional<net::ErrorCode>{}
          : std::optional(net::ErrorCode(net::asio::error::operation_aborted));

  // An unauthenticated Report is a claim, not a fact. It is enough to make us go and ask the
  // Engine again -- a round trip an attacker could cost us anyway by dropping a datagram -- and
  // never enough to write into the cache, because the answer to the re-discovery is authenticated
  // and this is not.
  if (!pending.replyAuthenticated || *counter == usmStatsUnknownEngineIds) {
    m_engineAt.erase(from);
    return retryOrAbort;
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
  // repeat within a Client short of 2^31 transmissions, so an old capture cannot match a request
  // still waiting for an answer. What remains is a recording from an earlier Client process whose
  // unrelated, separately keyed IDs happened to include this one. That buys one rediscovery per
  // request -- mayRetry bounds it -- and the rediscovery is exposed exactly as every first
  // discovery is: only a second recording that matches the time-sync phase's own msgID could set
  // its baseline.
  EngineState* engine = engineAt(from);
  if (engine != nullptr && engine->timeSynced && pending.security.boots < engine->boots) {
    engine->timeSynced = false;
    return retryOrAbort;
  }
  observeEngineTime(from, pending.security);
  return retryOrAbort;
}

net::Awaitable<Client::RequestResult> Client::Impl::doRequestV3(Ref self, Target target,
                                                                Credentials creds, Pdu pdu) {
  co_await observeBothCancellationTypes();
  // Refused at the call rather than downgraded: a message that claims privacy it does not have is
  // worse than one that was never sent.
  if (detail::Secret::priv(creds).protocolMissing()) {
    co_return RequestResult{make_error_code(Errc::UnsupportedPrivProtocol), Response{}};
  }
  if (detail::Secret::auth(creds).protocolMissing()) {
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

    const auto [key, privKey] = localizedKeys(creds, engine->engineId, ec);
    if (ec) co_return RequestResult{ec, Response{}};

    V3Header header;
    header.level = creds.level;

    UsmParameters usm;
    usm.engineId = engine->engineId;
    usm.boots = engine->boots;
    usm.time = static_cast<std::int32_t>(projected);
    usm.userName = creds.userName;

    ScopedPdu scoped;
    scoped.contextEngineId = engine->engineId;
    scoped.pdu = pdu;

    const auto pending = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
    pending->from = target.endpoint;
    pending->v3 = true;
    pending->authRequired = isAuthenticated(creds.level);
    pending->authProtocol = creds.authProtocol;
    pending->privProtocol = creds.privProtocol;
    if (key != nullptr) pending->authKey = *key;
    if (privKey != nullptr) pending->privKey = *privKey;
    pending->engineId = engine->engineId;

    ec = co_await transact(self, target,
                           v3Encoder(header, std::move(usm), std::move(scoped), pending), pending);
    if (ec) co_return RequestResult{ec, Response{}};

    if (pending->response.type == PduType::Report) {
      const auto cancelState = co_await net::asio::this_coro::cancellation_state;
      const auto failure =
          handleReport(target.endpoint, *pending, attempt == 0, cancelState.cancelled());
      if (!failure) continue;
      co_return RequestResult{*failure, Response{}};
    }

    if (pending->replyAuthenticated) observeEngineTime(target.endpoint, pending->security);
    co_return toResult(pending->response);
  }

  // Unreachable: the second attempt never asks to retry, so the loop always returns from inside.
  co_return RequestResult{make_error_code(Errc::UnexpectedReport), Response{}};
}

std::shared_ptr<Client::Impl::WalkTimeLimit> Client::Impl::armTimeLimit(
    const net::Executor& ex, std::chrono::milliseconds limit) {
  using Clock = std::chrono::steady_clock;
  auto timeLimit = std::make_shared<WalkTimeLimit>(ex);
  // Saturating: now() + limit converts the limit to the clock's nanoseconds, which a limit such as
  // milliseconds::max() -- a natural way to write "none" -- overflows. One the clock cannot reach
  // is never reached.
  const auto now = Clock::now();
  const auto headroom =
      std::chrono::duration_cast<std::chrono::milliseconds>(Clock::time_point::max() - now);
  timeLimit->at = limit < headroom ? now + limit : Clock::time_point::max();
  timeLimit->timer.expires_at(timeLimit->at);
  // Weak, so that the timer's own wait does not keep the timer alive: when the Walk ends, its frame
  // lets go of the time limit, the timer's destructor cancels the wait, and nothing fires.
  timeLimit->timer.async_wait([weak = std::weak_ptr<WalkTimeLimit>(timeLimit)](net::ErrorCode ec) {
    const auto t = weak.lock();
    if (ec || !t) return;
    t->fired = true;
    t->signal.emit(net::asio::cancellation_type::terminal);
  });
  return timeLimit;
}

// The request runs as an operation of its own, on the time limit's slot, so that reaching the
// limit can emit terminal into it. The caller's signals reach that slot too, forwarded from the
// Walk's own slot, which nothing else uses while this waits; the Walk's state still records them
// first, so a Walk reads the caller's cancellation the same way with a time limit as without one.
net::Awaitable<Client::RequestResult> Client::Impl::underTimeLimit(
    std::shared_ptr<WalkTimeLimit> limit, net::asio::cancellation_slot walkSlot,
    net::Awaitable<RequestResult> request) {
  const SlotClearer clearer(walkSlot);
  if (walkSlot.is_connected()) {
    walkSlot.assign([limit](net::asio::cancellation_type type) { limit->signal.emit(type); });
  }
  co_return co_await net::asio::co_spawn(
      m_strand, std::move(request),
      net::asio::bind_cancellation_slot(limit->signal.slot(), use_awaitable));
}

Client::Impl::WalkStep Client::Impl::takeBatch(const Oid& base, Oid& current,
                                               std::vector<Varbind>& varbinds, std::size_t room) {
  WalkStep step;
  step.batch.reserve(std::min(varbinds.size(), room));
  for (auto& vb : varbinds) {
    // endOfMibView -- or either of the noSuch markers, from an Agent that should not be sending
    // them here -- ends the Walk, as does leaving the Subtree.
    if (isException(vb.val) || !base.isPrefixOf(vb.name)) {
      step.next = WalkNext::SubtreeEnded;
      break;
    }
    // ADR-0004: an Agent that repeats an OID would otherwise walk forever.
    if (!(current < vb.name)) {
      step.next = WalkNext::NonIncreasing;
      break;
    }
    // Past the limit is cut only once it is known to be more of the Subtree: the end arriving with
    // the last Varbind allowed still makes a whole Walk.
    if (step.batch.size() == room) {
      step.next = WalkNext::LimitReached;
      break;
    }
    current = vb.name;
    step.batch.push_back(std::move(vb));
  }
  return step;
}

net::Awaitable<Client::WalkResult> Client::Impl::doWalk(Ref self, Target target, Auth auth,
                                                        Oid base, WalkOptions options,
                                                        BatchHandler onBatch) {
  // A total cancellation is a request to stop cleanly at a Batch boundary rather than to drop
  // everything, so it has to be observable here -- and observed, not thrown. The state is asked
  // for at each use rather than held, because each request underneath re-seats it.
  co_await observeBothCancellationTypes();
  if (const auto refused = refusal(walkInRange(target, options), authFault(auth))) {
    co_return WalkResult{*refused};
  }

  // Either limit ends the Walk with WalkIncomplete, never as a whole one (ADR-0004). Both are
  // checked before each request, after the caller's cancellation, so a Walk that has used up
  // either sends nothing more.
  const std::size_t varbindLimit =
      options.maxVarbinds.value_or(std::numeric_limits<std::size_t>::max());
  std::size_t delivered = 0;
  const auto timeLimit =
      options.timeLimit ? armTimeLimit(co_await net::asio::this_coro::executor, *options.timeLimit)
                        : nullptr;

  Oid current = base;
  std::int32_t maxRepetitions = options.maxRepetitions;

  for (;;) {
    const auto state = co_await net::asio::this_coro::cancellation_state;
    if (const auto stop = cancellationEnding(state)) co_return WalkResult{*stop};
    if (delivered >= varbindLimit || (timeLimit && timeLimit->reached())) {
      co_return WalkResult{make_error_code(Errc::WalkIncomplete)};
    }

    const Pdu req = maxRepetitions <= 0 ? makePdu(PduType::GetNext, toVarbinds({current}))
                                        : makeBulkPdu(toVarbinds({current}), 0, maxRepetitions);

    auto [ec, resp] = timeLimit ? co_await underTimeLimit(timeLimit, state.slot(),
                                                          doWalkRequest(self, target, auth, req))
                                : co_await doWalkRequest(self, target, auth, req);
    // tooBig means the Response did not fit, not that the request was wrong: ask for less and try
    // again. Only a deliberately misbehaving Simulator reaches this path (ADR-0006).
    if (ec == ErrorStatus::TooBig && maxRepetitions > 1) {
      maxRepetitions /= 2;
      continue;
    }
    if (ec) {
      co_return WalkResult{
          walkFailure(ec, co_await net::asio::this_coro::cancellation_state, timeLimit.get())};
    }
    // A reply in hand as Stopping began is a Batch the caller never sees: the Batch handler is not
    // called once Stopping has begun, from whichever thread it began on (ADR-0009).
    if (m_stopping) co_return WalkResult{make_error_code(Errc::ClientStopped)};
    if (resp.varbinds.empty()) co_return WalkResult{make_error_code(Errc::MissingVarbind)};

    const WalkStep step = takeBatch(base, current, resp.varbinds, varbindLimit - delivered);
    if (step.next == WalkNext::NonIncreasing) {
      co_return WalkResult{make_error_code(Errc::NonIncreasingOid)};
    }
    if (const auto ended = deliverBatch(onBatch, step.batch)) co_return WalkResult{*ended};
    if (step.next == WalkNext::SubtreeEnded) co_return WalkResult{net::ErrorCode{}};
    if (step.next == WalkNext::LimitReached)
      co_return WalkResult{make_error_code(Errc::WalkIncomplete)};
    delivered += step.batch.size();
  }
}

net::Awaitable<Client::CollectResult> Client::Impl::doWalkCollect(Ref self, Target target,
                                                                  Auth auth, Oid base,
                                                                  WalkOptions options) {
  // ADR-0004's wrapper is the half that buffers, so it is the half with a limit by default.
  if (!options.maxVarbinds) options.maxVarbinds = defaultCollectLimit;
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

detail::CacheCounts detail::CacheView::counts(const Client& client) {
  return client.m_impl->cacheCounts();
}

}  // namespace snmpio
