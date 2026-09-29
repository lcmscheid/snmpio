#ifndef SNMPIO_TESTS_INTEROPOPERATIONS_HPP
#define SNMPIO_TESTS_INTEROPOPERATIONS_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/Oid.hpp>
#include <snmpio/Value.hpp>

#include <gtest/gtest.h>

#include "InteropSummary.hpp"
#include "InteropTarget.hpp"

// GETNEXT and GETBULK against a live Agent, asserted only on what a caller observes.
//
// No MIB contents are pinned beyond what the GET half already relies on: sysDescr.0 exists. From
// that alone, both operations' successor semantics are checkable against any Agent. sysDescr is
// the `system` group's first column and a scalar, so sysDescr.0 is the first instance under
// `system` -- the successor of `system` itself. And two GETNEXT chains, one from `system` and one
// from sysDescr.0, are the same chain one step apart, whatever the Agent serves after it.
namespace snmpio::test {

inline const Oid systemGroup{1, 3, 6, 1, 2, 1, 1};

// Enough rows that an encrypted Response runs to many cipher blocks, which is where DES padding
// and the AES-CFB tail are exercised, and well inside what any Agent fits in one datagram.
inline constexpr std::int32_t bulkRepetitions = 20;

// Why the successor checks cannot run against this Agent, or nothing when they can. Both pinned
// Simulator images answer a GETNEXT or GETBULK carrying several Varbinds from the wrong requested
// OIDs (lcmscheid/snmp-fault-agent#11) -- which is what these checks exist to catch, and which a
// test that asserted the Simulator's answers would pin in place. tests/interop/start-agent.sh sets
// the flag for them, and unsets it when a fixed image is pinned. It names the defect rather than
// the compliance, so a Target nobody described is held to RFC 3416 like `snmpd`.
[[nodiscard]] inline std::optional<std::string> successorsUncheckable() {
  if (!envVar("SNMPIO_INTEROP_BROKEN_SUCCESSORS")) return std::nullopt;
  return "SNMPIO_INTEROP_BROKEN_SUCCESSORS: the Agent answers multi-Varbind GETNEXT/GETBULK from "
         "the wrong OIDs (lcmscheid/snmp-fault-agent#11)";
}

// What an operation's summary row is called: the operation, then the pair or Community it ran as.
[[nodiscard]] inline std::string operationLabel(const char* operation, const std::string& label) {
  return std::string(operation) + " " + label;
}

[[nodiscard]] inline bool isException(const Varbind& varbind) {
  return std::holds_alternative<ValueException>(varbind.val);
}

// The first thing wrong with a result, or empty when there is nothing: the text a summary row and
// a failure message both carry.
[[nodiscard]] inline std::string transportProblem(const GetResult& result) {
  if (!result.ec) return {};
  return std::string(result.ec.category().name()) + ": " + result.ec.message();
}

// GETNEXT of {system, sysDescr.0}: the first comes back as sysDescr.0, its immediate successor,
// and the second as something after sysDescr.0 that the Agent actually has.
[[nodiscard]] inline std::string getNextProblem(const GetResult& result) {
  if (auto problem = transportProblem(result); !problem.empty()) return problem;
  const auto& varbinds = result.response.varbinds;
  if (varbinds.size() != 2) {
    return "asked for 2 successors, got " + std::to_string(varbinds.size());
  }
  if (varbinds[0].name != sysDescr) {
    return "the successor of system is sysDescr.0, got " + varbinds[0].name.toString();
  }
  for (const auto& varbind : varbinds) {
    if (isException(varbind)) {
      return varbind.name.toString() + " came back as " + toString(varbind.val);
    }
  }
  if (!(sysDescr < varbinds[1].name)) {
    return "the successor of sysDescr.0 does not follow it: " + varbinds[1].name.toString();
  }
  return {};
}

// GETBULK of {system | system, sysDescr.0} with one non-repeater: the non-repeater's single
// successor, then rows of two columns, each column strictly increasing until it runs off the end
// of the MIB view and stays there. The columns are GETNEXT chains from `system` and from
// sysDescr.0, so the first is the second one row late -- which checks that each row is the
// immediate successor of the one before, not merely a later OID.
[[nodiscard]] inline std::string getBulkProblem(const GetResult& result) {
  if (auto problem = transportProblem(result); !problem.empty()) return problem;
  const auto& varbinds = result.response.varbinds;
  constexpr std::size_t columns = 2;
  // An Agent may drop Varbinds off the end to fit its datagram, and RFC 3416 section 4.2.3 lets
  // that end partway through a row -- so the last row may be short, and is checked as far as it
  // goes. The one row every Response has room for is still required.
  if (varbinds.size() < 1 + columns ||
      varbinds.size() > 1 + (columns * static_cast<std::size_t>(bulkRepetitions))) {
    return "asked for one non-repeater and " + std::to_string(bulkRepetitions) +
           " rows of two, got " + std::to_string(varbinds.size()) + " Varbinds";
  }
  const std::size_t rows = (varbinds.size() - 1 + columns - 1) / columns;
  const auto present = [&](std::size_t row, std::size_t column) {
    return 1 + (row * columns) + column < varbinds.size();
  };
  if (varbinds[0].name != sysDescr || isException(varbinds[0])) {
    return "the non-repeater's successor is sysDescr.0, got " + varbinds[0].name.toString();
  }
  const auto at = [&](std::size_t row, std::size_t column) -> const Varbind& {
    return varbinds[1 + (row * columns) + column];
  };
  if (at(0, 0).name != sysDescr) {
    return "the first repetition of system is sysDescr.0, got " + at(0, 0).name.toString();
  }
  const std::vector<Oid> requested{systemGroup, sysDescr};
  for (std::size_t column = 0; column < columns; ++column) {
    const Oid* previous = &requested[column];
    bool ended = false;
    for (std::size_t row = 0; row < rows && present(row, column); ++row) {
      const auto& varbind = at(row, column);
      const std::string where =
          "column " + std::to_string(column) + " row " + std::to_string(row) + ": ";
      if (ended || isException(varbind)) {
        // RFC 3416 section 4.2.3: once a column runs out, every later row of it says so.
        if (!isException(varbind) ||
            std::get<ValueException>(varbind.val) != ValueException::EndOfMibView) {
          return where + varbind.name.toString() + " came back as " + toString(varbind.val) +
                 (ended ? " after the column had ended" : "");
        }
        ended = true;
        continue;
      }
      if (!(*previous < varbind.name)) {
        return where + varbind.name.toString() + " does not follow " + previous->toString();
      }
      previous = &varbind.name;
    }
  }
  for (std::size_t row = 0; row + 1 < rows && present(row + 1, 0); ++row) {
    const auto& late = at(row + 1, 0);
    const auto& early = at(row, 1);
    if (isException(late) || isException(early)) break;
    if (late.name != early.name) {
      return "row " + std::to_string(row + 1) + " from system is " + late.name.toString() +
             " but row " + std::to_string(row) + " from sysDescr.0 is " + early.name.toString() +
             ", and they are the same successor";
    }
  }
  return {};
}

// Record `problem` against `label` in the run summary, and fail the test on it. Recorded before
// the assertion, so a failing row is still in the summary.
inline void recordOutcome(const std::string& label, const std::string& problem) {
  recordPair(label, problem.empty(), problem);
  EXPECT_TRUE(problem.empty()) << label << ": " << problem;
}

// One GETNEXT, recorded as `GETNEXT <label>`. `auth` is a Community or a Credentials.
template <typename Auth>
void getNextAndRecord(const Target& target, const Auth& auth, const std::string& label) {
  const auto result = exchange([&](Client& client, auto handler) {
    client.asyncGetNext(target, auth, {systemGroup, sysDescr}, std::move(handler));
  });
  recordOutcome(operationLabel("GETNEXT", label), getNextProblem(result));
}

// One GETBULK with a non-repeater and two repeating columns, recorded as `GETBULK <label>`.
template <typename Auth>
void getBulkAndRecord(const Target& target, const Auth& auth, const std::string& label) {
  const auto result = exchange([&](Client& client, auto handler) {
    client.asyncGetBulk(target, auth, {systemGroup, systemGroup, sysDescr}, 1, bulkRepetitions,
                        std::move(handler));
  });
  recordOutcome(operationLabel("GETBULK", label), getBulkProblem(result));
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPOPERATIONS_HPP
