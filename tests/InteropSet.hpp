#ifndef SNMPIO_TESTS_INTEROPSET_HPP
#define SNMPIO_TESTS_INTEROPSET_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/Oid.hpp>
#include <snmpio/Pdu.hpp>
#include <snmpio/Target.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/detail/Net.hpp>

#include <gtest/gtest.h>

#include "InteropCredentials.hpp"
#include "InteropOperations.hpp"
#include "InteropSummary.hpp"
#include "InteropTarget.hpp"

// SET against a live Agent: a write that lands, and a write the Agent refuses.
//
// The write that lands is sysContact.0 -- written, read back with a GET, and restored -- and only
// with the writer Credentials the environment names. Nobody names them for a Target we did not
// configure unless they choose to, so a run against a borrowed switch writes nothing by default,
// and its summary says the writes were skipped rather than proven.
//
// The write that is refused needs no writer: it SETs sysDescr.0, read-only in its MIB, to the value
// it already has, with the Credentials every other test reads with. So it changes nothing even on
// an Agent that took it, and runs everywhere, hardware included.
namespace snmpio::test {

inline const Oid sysContact{1, 3, 6, 1, 2, 1, 1, 4, 0};

// An error-status's name as RFC 3416 spells it: the library's own message for the status, up to any
// explanation after a colon -- so there is no second table of names to drift from it.
[[nodiscard]] inline std::string statusName(ErrorStatus status) {
  const auto message = make_error_code(status).message();
  return message.substr(0, message.find(':'));
}

// The error-status RFC 3416 spells `name`, or nothing when it spells none -- or spells noError,
// which refuses nothing.
[[nodiscard]] inline std::optional<ErrorStatus> errorStatusNamed(std::string_view name) {
  for (auto value = static_cast<std::int32_t>(ErrorStatus::TooBig);
       value <= static_cast<std::int32_t>(ErrorStatus::InconsistentName); ++value) {
    const auto status = static_cast<ErrorStatus>(value);
    if (!name.empty() && statusName(status) == name) return status;
  }
  return std::nullopt;
}

// The first thing wrong with a SET that should have been refused, or empty when there is nothing.
// `expected` is the error-status the Agent's capability flag names, or nothing when it names none
// and any refusal will do. A refusal is the Agent's own error-status: a timeout is its silence.
[[nodiscard]] inline std::string refusalProblem(const ExchangeResult& set,
                                                std::optional<ErrorStatus> expected) {
  if (!set.ec) return "the Agent accepted a SET of a read-only object";
  if (set.ec.category() != agentErrorCategory()) {
    return "not refused by the Agent: " + errorText(set.ec);
  }
  if (expected && set.ec != make_error_code(*expected)) {
    return "refused with " + set.ec.message() + ", but SNMPIO_INTEROP_SET_REFUSAL says " +
           statusName(*expected);
  }
  return {};
}

// What an ok refusal row was held to, when that was less than one exact status or less than
// RFC 3416 asks of the Agent; `errorIndex` is the Varbind the refusal blamed.
[[nodiscard]] inline std::string refusalNote(std::optional<ErrorStatus> expected,
                                             std::int32_t errorIndex) {
  std::string note;
  const auto add = [&](const std::string& part) { note += (note.empty() ? "" : "; ") + part; };
  if (!expected) add("any refusal accepted: SNMPIO_INTEROP_SET_REFUSAL is unset");
  // The pinned Simulator images refuse a read-only object with readOnly(4), which RFC 3416 section
  // 4.2.5 says an SNMPv2 entity never sends -- notWritable is the status it means. The flag
  // asserts what the Agent does, not what it should, and becomes notWritable when an image fixing
  // it is pinned.
  if (expected == ErrorStatus::ReadOnly) {
    add("readOnly, which RFC 3416 says an SNMPv2 entity never sends "
        "(lcmscheid/snmp-fault-agent#10)");
  }
  // The request carries one Varbind, so RFC 3416 has the error-index name it. Both pinned
  // Simulator images say 0. Noted rather than failed: the status is what this test asserts, and
  // the index is the Agent's to get right -- `snmpd` gets it right, so a row without this note is
  // an Agent that did and a Command Generator that read it.
  if (errorIndex != 1) {
    add("blamed Varbind " + std::to_string(errorIndex) +
        " of the one sent, where RFC 3416 names it");
  }
  return note;
}

// One GET's OCTET STRING, or what was wrong with it.
struct OctetsRead {
  Octets value;
  std::string problem;
};

[[nodiscard]] inline OctetsRead readOctets(const ExchangeResult& get, const Oid& oid) {
  if (auto problem = transportProblem(get); !problem.empty()) return {{}, problem};
  const auto& varbinds = get.response.varbinds;
  if (varbinds.size() != 1) {
    return {{}, "asked for one Varbind, got " + std::to_string(varbinds.size())};
  }
  if (varbinds[0].name != oid) {
    return {{}, "asked for " + oid.toString() + ", got " + varbinds[0].name.toString()};
  }
  const auto* const octets = std::get_if<Octets>(&varbinds[0].val);
  if (octets == nullptr) {
    return {{},
            oid.toString() +
                " came back as something other than an OCTET STRING: " + toString(varbinds[0].val)};
  }
  return {*octets, {}};
}

// A value to write that is not the one already there, since writing that would pass the read-back
// without ever having landed.
[[nodiscard]] inline Octets differentFrom(const Octets& original) {
  constexpr std::string_view written = "snmpio interop write";
  Octets value;
  for (const char c : written) value.push_back(static_cast<std::byte>(c));
  if (value == original) value.push_back(static_cast<std::byte>('!'));
  return value;
}

// `auth` is a Community or a Credentials.
template <typename Auth>
OctetsRead getOctets(const Target& target, const Auth& auth, const Oid& oid) {
  return readOctets(exchange([&](Client& client, auto handler) {
                      client.asyncGet(target, auth, {oid}, std::move(handler));
                    }),
                    oid);
}

template <typename Auth>
ExchangeResult sendSet(const Target& target, const Auth& auth, const Oid& oid, Octets value) {
  return exchange([&](Client& client, auto handler) {
    client.asyncSet(target, auth, {Varbind{oid, std::move(value)}}, std::move(handler));
  });
}

// The first thing wrong with reading `oid` back as `expected`, `when` saying at which step.
template <typename Auth>
std::string readBackProblem(const Target& target, const Auth& auth, const Oid& oid,
                            const Octets& expected, const std::string& when) {
  const auto after = getOctets(target, auth, oid);
  if (!after.problem.empty()) return when + ": " + after.problem;
  if (after.value != expected) return when + ": " + oid.toString() + " came back different";
  return {};
}

// Write sysContact.0, read it back, and restore it -- recorded as `SET <label>`. The restore is
// attempted whatever happened to the write, since a write that landed but read back wrong has
// still changed the Agent, and restoring a value that never changed is harmless.
template <typename Auth>
void writeReadAndRestoreAndRecord(const Target& target, const Auth& auth,
                                  const std::string& label) {
  const auto before = getOctets(target, auth, sysContact);
  std::string problem;
  if (!before.problem.empty()) {
    problem = "reading sysContact.0 before writing it: " + before.problem;
  } else {
    const auto written = differentFrom(before.value);
    if (const auto write = sendSet(target, auth, sysContact, written); write.ec) {
      problem = "the write: " + errorText(write.ec);
    } else {
      problem = readBackProblem(target, auth, sysContact, written, "reading back the write");
    }
    std::string restoreProblem;
    if (const auto restore = sendSet(target, auth, sysContact, before.value); restore.ec) {
      restoreProblem = "restoring it: " + errorText(restore.ec);
    } else {
      restoreProblem =
          readBackProblem(target, auth, sysContact, before.value, "reading back the restore");
    }
    if (problem.empty()) {
      problem = restoreProblem;
    } else if (!restoreProblem.empty()) {
      problem += "; and " + restoreProblem;
    }
  }
  recordOutcome(operationLabel(Operation::Set, label), problem, {});
}

// The error-status SNMPIO_INTEROP_SET_REFUSAL says this Agent refuses the SET with, into
// `expected`, or nothing when it says none. Set to a name that is no error-status fails the test,
// like every other interop variable set but unusable: a typo that fell back to any refusal would
// pass a Command Generator that turned every refusal into one generic error.
//
// tests/interop/start-agent.sh sets it: noAccess for `snmpd`, whose access control refuses a
// read-only identity before it looks at the object, and readOnly for the pinned Simulator images --
// which RFC 3416 says an SNMPv2 entity never sends. It becomes notWritable when an image fixing
// lcmscheid/snmp-fault-agent#10 is pinned, and refusalNote says so on every row until then.
inline void expectedRefusal(std::optional<ErrorStatus>& expected) {
  const auto name = envVar("SNMPIO_INTEROP_SET_REFUSAL");
  if (!name) return;
  expected = errorStatusNamed(*name);
  ASSERT_TRUE(expected.has_value()) << "SNMPIO_INTEROP_SET_REFUSAL is not an RFC 3416 error-status "
                                       "other than noError, spelled as the RFC does: "
                                    << *name;
}

// SET sysDescr.0 to the value it already has, expecting `expected` or, with nothing expected, any
// refusal, and check that the value is unchanged -- recorded as `SET refused <label>`.
template <typename Auth>
void refusedSetAndRecord(const Target& target, const Auth& auth, const std::string& label,
                         std::optional<ErrorStatus> expected) {
  const auto before = getOctets(target, auth, sysDescr);
  std::string problem;
  std::string note;
  if (!before.problem.empty()) {
    problem = "reading sysDescr.0 before the SET: " + before.problem;
  } else {
    const auto refusal = sendSet(target, auth, sysDescr, before.value);
    problem = refusalProblem(refusal, expected);
    note = refusalNote(expected, refusal.response.errorIndex);
    if (problem.empty()) {
      problem = readBackProblem(target, auth, sysDescr, before.value, "after the refusal");
    }
  }
  recordOutcome(operationLabel(Operation::RefusedSet, label), problem, note);
}

// The variable naming the v3 writer at `level`. Each writer carries that level's representative
// pair (test::securityLevelPairs) and SNMPIO_INTEROP_V3_PASSWORD, as the users our own
// configuration creates for it do.
[[nodiscard]] inline const char* writerVariable(SecurityLevel level) {
  switch (level) {
    case SecurityLevel::NoAuthNoPriv:
      return "SNMPIO_INTEROP_WRITER_NOAUTHNOPRIV";
    case SecurityLevel::AuthNoPriv:
      return "SNMPIO_INTEROP_WRITER_AUTHNOPRIV";
    case SecurityLevel::AuthPriv:
      return "SNMPIO_INTEROP_WRITER_AUTHPRIV";
  }
  return "";
}

inline constexpr const char* writerCommunityVariable = "SNMPIO_INTEROP_WRITER_COMMUNITY";

// Why a write row skips: nobody named a writer for it.
[[nodiscard]] inline std::string writerUnset(const char* variable) {
  return std::string("needs ") + variable +
         ": a write changes the Target, so only a run that names a writer makes one";
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPSET_HPP
