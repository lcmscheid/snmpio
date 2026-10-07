// The receive path any UDP sender can reach, fuzzed whole: a real Client with Outstanding Requests,
// against a Scripted Agent that answers them with whatever the input says (HostileAgent.hpp). The
// other fuzzers reach the decoders; this one reaches what the Client does with what they decode --
// the matching, the digest, the Reports, Engine Discovery and the retransmission loop.
//
// It runs on the Client's real seams, a socket and a steady clock, and adds none: short Target
// timeouts keep an iteration fast, and the nondeterminism of real timers is accepted. Each
// completion is judged against the threat model (docs/threat-model.md):
//
//   L1  every Outstanding Request completes exactly once, and its handler is destroyed once;
//   R5  no reply the Client drops fails a request before its deadline;
//   R6  at authNoPriv and authPriv, nothing unauthenticated completes or fails a request before its
//       deadline, except an unsigned Report and the answer to Engine Discovery's identity phase;
//   R8  at v2c and noAuthNoPriv, only a datagram that matches the request completes or fails it.
//
// The oracle cannot see which datagram the Client acted on, so it works from the other end. Every
// datagram the Agent sends is recorded as it goes out and classified once the run is over (Ledger,
// below), by the rule the threat model gives, and a completion must be one some datagram entitled.
// A completion nothing entitled has to be one a deadline produced, and a deadline cannot pass
// early: a request that reports one sooner than its Target's whole deadline, every retry included,
// broke the rule.
//
// The classification is coarser than the Client's matching, never finer. It ignores the Time
// Window, which the Client checks and it does not, and it credits a discovery's answer to every
// request; both make it accept more than the Client should do, so neither can raise a false alarm.
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/Error.hpp>
#include <snmpio/Pdu.hpp>
#include <snmpio/Usm.hpp>
#include <snmpio/V3Message.hpp>
#include <snmpio/detail/Net.hpp>

#include "HostileAgent.hpp"

namespace snmpio::fuzz {
namespace {

using Clock = std::chrono::steady_clock;

// How long an iteration may run before an Outstanding Request counts as stranded. The longest
// legitimate one is two attempts, each behind a two-phase Engine Discovery: six exchanges of at
// most 50 ms here. Two orders of magnitude above that leaves room for a slow sanitizer build.
constexpr auto strandedAfter = std::chrono::seconds(10);

[[noreturn]] void violated(const char* invariant, const std::string& what) {
  std::cerr << "\n*** " << invariant << " violated: " << what << "\n\n" << std::flush;
  std::abort();
}

std::string describe(const net::ErrorCode& ec) {
  return std::string(ec.category().name()) + ":" + std::to_string(ec.value()) + " (" +
         ec.message() + ")";
}

Profile readProfile(Script& script) {
  Profile p;
  p.mode = static_cast<Mode>(script.pick(4));
  if (p.mode == Mode::V2c) return p;

  p.creds.userName = "fuzzer";
  if (p.mode == Mode::NoAuthNoPriv) return p;

  constexpr std::array auths{AuthProtocol::Md5, AuthProtocol::Sha1, AuthProtocol::Sha256};
  p.creds.authProtocol = auths[script.pick(auths.size())];
  p.creds.authPassword = "maplesyrup";
  p.creds.level = SecurityLevel::AuthNoPriv;
  if (p.mode == Mode::AuthNoPriv) return p;

  // DES last, so that the input's default is a cipher that needs no legacy provider.
  constexpr std::array privs{PrivProtocol::Aes128, PrivProtocol::Aes256, PrivProtocol::Des};
  p.creds.privProtocol = privs[script.pick(privs.size())];
  p.creds.privPassword = "pancakemix";
  p.creds.level = SecurityLevel::AuthPriv;
  return p;
}

// The error a Report names, by its usmStats counter (RFC 3414 section 5): the Client's mapping,
// restated here as the threat model states it, so that a change to either is a disagreement.
net::ErrorCode reportError(const Pdu& report) {
  const Oid prefix{1, 3, 6, 1, 6, 3, 15, 1, 1};
  if (report.varbinds.empty()) return make_error_code(Errc::UnexpectedReport);
  const Oid& name = report.varbinds.front().name;
  if (!prefix.isPrefixOf(name) || name.size() <= prefix.size()) {
    return make_error_code(Errc::UnexpectedReport);
  }
  switch (name[prefix.size()]) {
    case 1:
      return make_error_code(Errc::UnsupportedSecurityLevel);
    case 2:
      return make_error_code(Errc::NotInTimeWindow);
    case 3:
      return make_error_code(Errc::UnknownUserName);
    case 4:
      return make_error_code(Errc::UnknownEngineId);
    case 5:
      return make_error_code(Errc::AuthFailed);
    case 6:
      return make_error_code(Errc::DecryptionError);
    default:
      return make_error_code(Errc::UnexpectedReport);
  }
}

// What the Agent's datagrams entitle each Outstanding Request to.
class Ledger {
 public:
  struct Entitlement {
    // The Responses that match the request: any of them may complete it, with exactly its
    // error-status and Varbinds.
    std::vector<Pdu> responses;
    // The errors the Reports it must accept name (R6 (1), R8): any of them may fail it.
    std::vector<net::ErrorCode> errors;
  };

  Ledger(const HostileAgent& agent, std::size_t requests)
      : m_agent(&agent), m_entitlements(requests) {}

  // Called for every datagram before it goes out. Judged only once the run is over: a reply can
  // name a Message ID before the Agent has read the request that carries it, and only then is
  // every owner known.
  void sent(std::span<const std::byte> datagram, bool fromTarget) {
    // R1 and R6: nothing from an address the Client did not send to counts for anything.
    if (fromTarget) m_sent.emplace_back(datagram.begin(), datagram.end());
  }

  void settle() {
    for (const auto& datagram : m_sent) {
      if (m_agent->profile().mode == Mode::V2c) {
        settleV2c(datagram);
      } else {
        settleV3(datagram);
      }
    }
  }

  [[nodiscard]] const Entitlement& entitlement(std::size_t request) const {
    return m_entitlements.at(request);
  }
  // The errors an answer to Engine Discovery may end it with (R6 (2)). A discovery's failure fails
  // every request queued behind it, and the oracle does not track which requests those were, so
  // these may fail any request.
  [[nodiscard]] const std::vector<net::ErrorCode>& discoveryErrors() const noexcept {
    return m_discoveryErrors;
  }
  // An answer to a request the Agent could not read, which the oracle cannot attribute. Never
  // expected; if it happens the iteration's completions are not judged rather than misjudged.
  [[nodiscard]] bool unattributed() const noexcept { return m_unattributed; }

 private:
  void settleV2c(std::span<const std::byte> datagram) {
    net::ErrorCode ec;
    auto msg = decodeV2cMessage(datagram, ec);
    if (!msg || msg->pdu.type != PduType::Response) return;
    if (msg->community != m_agent->profile().community.value) return;
    const auto* seen = m_agent->seen(msg->pdu.requestId);
    if (seen == nullptr) return;
    credit(*seen, [&](Entitlement& e) { e.responses.push_back(std::move(msg->pdu)); });
  }

  void settleV3(std::span<const std::byte> datagram) {
    net::ErrorCode ec;
    auto msg = decodeV3Message(datagram, ec);
    if (!msg) return;
    const auto* seen = m_agent->seen(msg->header.msgId);
    if (seen == nullptr) return;

    const Credentials& creds = m_agent->profile().creds;
    const bool authRequired = isAuthenticated(seen->level);
    const Keys keys = keysFor(creds, seen->engineId);
    const bool verified = authRequired && isAuthenticated(msg->header.level) &&
                          verifyAuth(datagram, *msg, creds.authProtocol, keys.auth, ec);
    const bool encrypted = isEncrypted(msg->header.level);
    // Privacy implies authentication: nothing encrypted is read before its digest verifies, and
    // nothing at noAuthNoPriv can be opened at all.
    if (encrypted && (!verified || !decryptScopedPdu(*msg, creds.privProtocol, keys.priv, ec))) {
      return;
    }

    const bool isReport = msg->scoped.pdu.type == PduType::Report;
    // R6 (1): unsigned and unencrypted, or verified. At noAuthNoPriv, any Report (R8).
    const bool exempt = isReport && !encrypted && !isAuthenticated(msg->header.level);
    if (authRequired && !exempt && !verified) return;

    if (seen->owner == HostileAgent::Owner::Discovery) {
      // The identity phase reads only the engineID, and fails without one.
      if (seen->engineId.empty()) {
        if (msg->security.engineId.empty()) grantDiscovery(Errc::UnknownEngineId);
        return;
      }
      // The time-sync phase fails on a signed pair at the boots ceiling, or with an unsigned
      // Report's error, except an unsigned notInTimeWindows, which it drops (R6 (1), ADR-0008's
      // amendment). A signed Report carries the Engine's clock, so it ends the phase in success.
      if (isReport && !verified) {
        const auto error = reportError(msg->scoped.pdu);
        if (error != Errc::NotInTimeWindow) m_discoveryErrors.push_back(error);
      }
      if (verified && msg->security.boots == std::numeric_limits<std::int32_t>::max()) {
        grantDiscovery(Errc::NotInTimeWindow);
      }
      return;
    }
    if (isReport) {
      credit(*seen, [&](Entitlement& e) { e.errors.push_back(reportError(msg->scoped.pdu)); });
      return;
    }
    if (seen->owner == HostileAgent::Owner::Request) {
      // The rest of the match: the request's own engineID and request-id, and a Response.
      if (msg->security.engineId != seen->engineId) return;
      if (msg->scoped.pdu.type != PduType::Response) return;
      if (msg->scoped.pdu.requestId != msg->header.msgId) return;
    }
    credit(*seen, [&](Entitlement& e) { e.responses.push_back(std::move(msg->scoped.pdu)); });
  }

  void grantDiscovery(Errc e) { m_discoveryErrors.push_back(make_error_code(e)); }

  template <typename Grant>
  void credit(const HostileAgent::Seen& seen, Grant grant) {
    switch (seen.owner) {
      case HostileAgent::Owner::Request:
        if (seen.requestIndex < m_entitlements.size()) grant(m_entitlements[seen.requestIndex]);
        return;
      case HostileAgent::Owner::Discovery:
        return;
      case HostileAgent::Owner::Unknown:
        m_unattributed = true;
        return;
    }
  }

  const HostileAgent* m_agent;
  std::vector<Octets> m_sent;
  std::vector<Entitlement> m_entitlements;
  std::vector<net::ErrorCode> m_discoveryErrors;
  bool m_unattributed = false;
};

// One Outstanding Request's completions, shared with its handler so that a handler destroyed late
// never reaches a dead record. The same bookkeeping as tests/CompletionOracle.hpp, without gtest.
struct Outcome {
  int invocations = 0;
  int destructions = 0;
  net::ErrorCode code;
  Response response;
  Clock::duration elapsed{};
};

class Handler {
 public:
  Handler(std::shared_ptr<Outcome> outcome, Clock::time_point started)
      : m_outcome(std::move(outcome)), m_started(started) {}
  Handler(Handler&& other) noexcept
      : m_outcome(std::exchange(other.m_outcome, nullptr)), m_started(other.m_started) {}
  Handler(const Handler&) = delete;
  Handler& operator=(const Handler&) = delete;
  Handler& operator=(Handler&&) = delete;
  ~Handler() {
    if (m_outcome) ++m_outcome->destructions;
  }

  void operator()(net::ErrorCode ec, Response response) {
    if (!m_outcome) violated("L1", "a moved-from completion handler was invoked");
    ++m_outcome->invocations;
    m_outcome->code = ec;
    m_outcome->response = std::move(response);
    m_outcome->elapsed = Clock::now() - m_started;
  }

 private:
  std::shared_ptr<Outcome> m_outcome;
  Clock::time_point m_started;
};

// ADR-0008: the reasons a request reports at its deadline when every reply was dropped.
bool isDropReason(const net::ErrorCode& ec) {
  return ec == Errc::AuthFailed || ec == Errc::DecryptionFailed || ec == Errc::NotInTimeWindow;
}

void judge(std::size_t request, const Outcome& outcome, const Ledger& ledger,
           const Profile& profile, const Target& target) {
  const auto& code = outcome.code;
  const auto& entitled = ledger.entitlement(request);
  const auto where =
      "request " + std::to_string(request) + " completed with " + describe(code) + " after " +
      std::to_string(
          std::chrono::duration_cast<std::chrono::microseconds>(outcome.elapsed).count()) +
      " us";
  const char* rule = profile.mode == Mode::V2c || profile.mode == Mode::NoAuthNoPriv ? "R8" : "R6";

  // A completion with data, or with the Agent's error-status, must carry what some matching
  // Response carried.
  if (!code || code.category() == agentErrorCategory()) {
    for (const auto& pdu : entitled.responses) {
      const auto status = code ? code.value() : 0;
      if (pdu.errorStatus == status && pdu.errorIndex == outcome.response.errorIndex &&
          pdu.varbinds == outcome.response.varbinds) {
        return;
      }
    }
    violated(rule, where + ", which no matching Response entitled it to");
  }

  // A deadline cannot pass early, and every deadline is at least the Target's whole one: each
  // attempt's timeout, every retry included.
  const bool atDeadline = outcome.elapsed >= target.timeout * (target.retries + 1);
  if (code == Errc::Timeout) {
    if (!atDeadline) violated("R5", where + ", before its deadline could pass");
    return;
  }
  if (profile.mode != Mode::V2c) {
    if (std::ranges::find(entitled.errors, code) != entitled.errors.end()) return;
    if (std::ranges::find(ledger.discoveryErrors(), code) != ledger.discoveryErrors().end()) return;
    if (isDropReason(code)) {
      if (!atDeadline) {
        violated("R5", where + ", before its deadline, and no Report the rules accept names it");
      }
      return;
    }
  }
  // Not the fuzz input's doing: this OpenSSL has no legacy provider, so DES cannot run at all.
  if (code == Errc::LegacyProviderUnavailable && profile.creds.privProtocol == PrivProtocol::Des) {
    return;
  }
  violated(rule, where + ", which nothing the Agent sent can explain");
}

void run(Script& script) {
  const Profile profile = readProfile(script);
  const std::size_t requests = 1 + script.pick(4);

  net::IoContext io;
  HostileAgent agent(io, profile, script);
  Ledger ledger(agent, requests);
  agent.setOnSent([&ledger](std::span<const std::byte> datagram, bool fromTarget) {
    ledger.sent(datagram, fromTarget);
  });

  Target target;
  target.endpoint = agent.endpoint();
  target.timeout = std::chrono::milliseconds(25);
  target.retries = static_cast<int>(script.pick(2));

  Client client(io.get_executor());
  std::vector<std::shared_ptr<Outcome>> outcomes;
  const auto started = Clock::now();
  for (std::size_t i = 0; i < requests; ++i) {
    outcomes.push_back(std::make_shared<Outcome>());
    Handler handler(outcomes.back(), started);
    if (profile.mode == Mode::V2c) {
      client.asyncGet(target, profile.community, {requestOid(i)}, std::move(handler));
    } else {
      client.asyncGet(target, profile.creds, {requestOid(i)}, std::move(handler));
    }
  }

  const auto allCompleted = [&outcomes] {
    return std::ranges::all_of(outcomes, [](const auto& o) { return o->invocations != 0; });
  };
  while (!allCompleted() && Clock::now() - started < strandedAfter) {
    io.run_one_for(std::chrono::milliseconds(50));
  }
  const bool stranded = !allCompleted();

  client.stop();
  agent.close();
  io.restart();
  io.run();

  for (std::size_t i = 0; i < requests; ++i) {
    const auto& o = *outcomes[i];
    const auto which = "request " + std::to_string(i);
    if (o.invocations != 1) {
      violated("L1", which + " completed " + std::to_string(o.invocations) + " times");
    }
    if (o.destructions != 1) {
      violated("L1",
               which + "'s handler was destroyed " + std::to_string(o.destructions) + " times");
    }
  }
  if (stranded) {
    violated("L1", "a request was still outstanding after " +
                       std::to_string(strandedAfter.count()) + " s");
  }

  ledger.settle();
  if (ledger.unattributed()) return;
  for (std::size_t i = 0; i < requests; ++i) judge(i, *outcomes[i], ledger, profile, target);
}

}  // namespace
}  // namespace snmpio::fuzz

// libFuzzer looks this entry point up by name; the spelling is not ours to pick.
// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  snmpio::fuzz::Script script(
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(data), size));
  snmpio::fuzz::run(script);
  return 0;
}
