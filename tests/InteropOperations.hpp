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
#include <snmpio/Pdu.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/detail/Net.hpp>

#include <gtest/gtest.h>

#include "InteropCredentials.hpp"
#include "InteropSummary.hpp"
#include "InteropTarget.hpp"

// GETNEXT and GETBULK against a live Agent, asserted only on what a caller observes, and the
// summary rows every operation the suite sends is recorded under.
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

// What a summary row says was sent. A Walk is recorded as two operations, one per traversal mode,
// because the mode is what its row reports and what tests/InteropWalk.hpp sends it in.
enum class Operation : std::uint8_t { Get, GetNext, GetBulk, WalkGetNext, WalkGetBulk };

[[nodiscard]] inline bool isWalk(Operation operation) {
  return operation == Operation::WalkGetNext || operation == Operation::WalkGetBulk;
}

// The PDU an operation sends, which for a Walk is its mode. The one place either is said.
[[nodiscard]] inline PduType pduOf(Operation operation) {
  switch (operation) {
    case Operation::Get:
      return PduType::Get;
    case Operation::GetNext:
    case Operation::WalkGetNext:
      return PduType::GetNext;
    case Operation::GetBulk:
    case Operation::WalkGetBulk:
      return PduType::GetBulk;
  }
  return PduType::Get;
}

[[nodiscard]] inline std::string pduName(Operation operation) {
  switch (pduOf(operation)) {
    case PduType::Get:
      return "GET";
    case PduType::GetNext:
      return "GETNEXT";
    case PduType::GetBulk:
      return "GETBULK";
    case PduType::Set:
    case PduType::Response:
    case PduType::Report:
      break;  // no Operation sends these
  }
  return {};
}

// GET's rows are the pair or Community alone, which is how the matrix was labelled before any
// other operation reached an Agent; the rest say their PDU first, and a Walk says so after it.
[[nodiscard]] inline std::string operationLabel(Operation operation, const std::string& label) {
  if (operation == Operation::Get) return label;
  return pduName(operation) + (isWalk(operation) ? " Walk " : " ") + label;
}

// How many Varbinds a GETNEXT carries. Several is the whole check: each answered from its own
// requested OID. One is what an Agent with the defect below can still be held to.
enum class GetNextVarbinds : std::uint8_t { Several, One };

// Why this Agent is sent one Varbind per GETNEXT, or nothing when it can take several. Both pinned
// Simulator images answer a GETNEXT carrying several Varbinds from the last requested OID
// (lcmscheid/snmp-fault-agent#11) -- which is what the whole check exists to catch, and which
// asserting the Simulator's answers would pin in place. tests/interop/start-agent.sh sets the flag
// for them. It names the defect rather than the compliance, so a Target nobody described is held
// to RFC 3416 like `snmpd`. GETBULK needs no such flag: the same images answer the one it sends
// correctly.
[[nodiscard]] inline std::optional<std::string> severalVarbindGetNextBroken() {
  if (!envVar("SNMPIO_INTEROP_BROKEN_GETNEXT")) return std::nullopt;
  return "one Varbind per request: SNMPIO_INTEROP_BROKEN_GETNEXT says the Agent answers several "
         "from the wrong OIDs (lcmscheid/snmp-fault-agent#11)";
}

// GETNEXT asks for {system, sysDescr.0}, or {system}.
[[nodiscard]] inline std::vector<Oid> getNextRequest(GetNextVarbinds count) {
  if (count == GetNextVarbinds::One) return {systemGroup};
  return {systemGroup, sysDescr};
}

// GETBULK asks for {system | system, sysDescr.0}: `system` as its one non-repeater, then a column
// from each of these.
inline const std::vector<Oid> bulkColumns{systemGroup, sysDescr};
inline constexpr std::size_t columnFromSysDescr = 1;

[[nodiscard]] inline std::vector<Oid> getBulkRequest() {
  std::vector<Oid> request{systemGroup};
  request.insert(request.end(), bulkColumns.begin(), bulkColumns.end());
  return request;
}

// The GETBULK Varbind in `row` of `column`, counted past the non-repeater.
[[nodiscard]] inline std::size_t bulkIndex(std::size_t row, std::size_t column) {
  return 1 + (row * bulkColumns.size()) + column;
}

[[nodiscard]] inline bool isException(const Varbind& varbind) {
  return std::holds_alternative<ValueException>(varbind.val);
}

// A Varbind as a failure message wants it: its OID, or the exception that stands in for one.
[[nodiscard]] inline std::string describe(const Varbind& varbind) {
  return isException(varbind) ? std::string(toString(varbind.val)) : varbind.name.toString();
}

// The first thing wrong with a result, or empty when there is nothing.
[[nodiscard]] inline std::string transportProblem(const ExchangeResult& result) {
  if (!result.ec) return {};
  return errorText(result.ec);
}

// What GETBULK's column from sysDescr.0 starts with -- its answer for the successor of sysDescr.0
// -- or nothing when that GETBULK failed or stopped short of it, which fails its own row.
[[nodiscard]] inline std::optional<Varbind> bulkSuccessorOfSysDescr(const ExchangeResult& bulk) {
  const auto index = bulkIndex(0, columnFromSysDescr);
  if (bulk.ec || bulk.response.varbinds.size() <= index) return std::nullopt;
  return bulk.response.varbinds[index];
}

// GETNEXT of {system, sysDescr.0}: the first comes back as sysDescr.0, its immediate successor.
// What the second's immediate successor is, no pinned MIB content says -- so it is held to
// `fromBulk`, the same successor asked through another PDU, when there is one. With one Varbind,
// only the first.
[[nodiscard]] inline std::string getNextProblem(const ExchangeResult& next, GetNextVarbinds count,
                                                const std::optional<Varbind>& fromBulk) {
  if (auto problem = transportProblem(next); !problem.empty()) return problem;
  const auto& varbinds = next.response.varbinds;
  const auto requested = getNextRequest(count);
  if (varbinds.size() != requested.size()) {
    return "asked for " + std::to_string(requested.size()) + " successors, got " +
           std::to_string(varbinds.size());
  }
  if (varbinds[0].name != sysDescr) {
    return "the successor of system is sysDescr.0, got " + varbinds[0].name.toString();
  }
  for (const auto& varbind : varbinds) {
    if (isException(varbind)) {
      return varbind.name.toString() + " came back as " + toString(varbind.val);
    }
  }
  if (count == GetNextVarbinds::One) return {};
  if (!(sysDescr < varbinds[1].name)) {
    return "the successor of sysDescr.0 does not follow it: " + varbinds[1].name.toString();
  }
  if (fromBulk && (isException(*fromBulk) || fromBulk->name != varbinds[1].name)) {
    return "the successor of sysDescr.0 is " + varbinds[1].name.toString() + " by GETNEXT but " +
           describe(*fromBulk) + " by GETBULK";
  }
  return {};
}

// GETBULK: the non-repeater's single successor, then rows of two columns, each column strictly
// increasing until it runs off the end of the MIB view and stays there. The columns are GETNEXT
// chains from `system` and from sysDescr.0, so the first is the second one row late -- which checks
// that each row is the immediate successor of the one before, not merely a later OID.
[[nodiscard]] inline std::string getBulkProblem(const ExchangeResult& bulk) {
  if (auto problem = transportProblem(bulk); !problem.empty()) return problem;
  const auto& varbinds = bulk.response.varbinds;
  const std::size_t columns = bulkColumns.size();
  // An Agent may drop Varbinds off the end to fit its datagram, and RFC 3416 section 4.2.3 lets
  // that end partway through a row -- so the last row may be short, and is checked as far as it
  // goes. The one row every Response has room for is still required.
  const auto repetitions = static_cast<std::size_t>(bulkRepetitions);
  if (varbinds.size() < bulkIndex(1, 0) || varbinds.size() > bulkIndex(repetitions, 0)) {
    return "asked for one non-repeater and " + std::to_string(repetitions) + " rows of " +
           std::to_string(columns) + ", got " + std::to_string(varbinds.size()) + " Varbinds";
  }
  const std::size_t rows = (varbinds.size() - bulkIndex(0, 0) + columns - 1) / columns;
  const auto present = [&](std::size_t row, std::size_t column) {
    return bulkIndex(row, column) < varbinds.size();
  };
  const auto at = [&](std::size_t row, std::size_t column) -> const Varbind& {
    return varbinds[bulkIndex(row, column)];
  };
  if (varbinds[0].name != sysDescr || isException(varbinds[0])) {
    return "the non-repeater's successor is sysDescr.0, got " + describe(varbinds[0]);
  }
  if (at(0, 0).name != sysDescr) {
    return "the first repetition of system is sysDescr.0, got " + at(0, 0).name.toString();
  }
  for (std::size_t column = 0; column < columns; ++column) {
    const Oid* previous = &bulkColumns[column];
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
    const auto& early = at(row, columnFromSysDescr);
    // Both columns running out together is the one way they may stop agreeing on an OID; one
    // running out while the other still has the successor it should have reached is a mismatch.
    if (isException(late) && isException(early)) break;
    if (isException(late) || isException(early) || late.name != early.name) {
      return "row " + std::to_string(row + 1) + " from system is " + describe(late) + " but row " +
             std::to_string(row) + " from sysDescr.0 is " + describe(early) +
             ", and they are the same successor";
    }
  }
  return {};
}

// Record `problem` against `label` in the run summary, and fail the test on it. Recorded before
// the assertion, so a failing row is still in the summary. `note` is what an ok row did not prove.
inline void recordOutcome(const std::string& label, const std::string& problem,
                          const std::string& note) {
  recordPair(label, problem.empty(), problem.empty() ? note : problem);
  EXPECT_TRUE(problem.empty()) << label << ": " << problem;
}

// `auth` is a Community or a Credentials.
template <typename Auth>
ExchangeResult sendGetNext(const Target& target, const Auth& auth, GetNextVarbinds count) {
  return exchange([&](Client& client, auto handler) {
    client.asyncGetNext(target, auth, getNextRequest(count), std::move(handler));
  });
}

template <typename Auth>
ExchangeResult sendGetBulk(const Target& target, const Auth& auth) {
  return exchange([&](Client& client, auto handler) {
    client.asyncGetBulk(target, auth, getBulkRequest(), 1, bulkRepetitions, std::move(handler));
  });
}

// One GETNEXT and one GETBULK, recorded as `GETNEXT <label>` and `GETBULK <label>`: sent together
// because the GETBULK is what the GETNEXT's second successor is held to.
template <typename Auth>
void getNextAndGetBulkAndRecord(const Target& target, const Auth& auth, const std::string& label) {
  const auto broken = severalVarbindGetNextBroken();
  const auto count = broken ? GetNextVarbinds::One : GetNextVarbinds::Several;
  const auto next = sendGetNext(target, auth, count);
  const auto bulk = sendGetBulk(target, auth);
  const auto fromBulk = bulkSuccessorOfSysDescr(bulk);
  std::string note = broken.value_or("");
  if (!broken && !fromBulk) {
    note = "the successor of sysDescr.0 held only to following it: GETBULK gave none to compare";
  }
  recordOutcome(operationLabel(Operation::GetNext, label), getNextProblem(next, count, fromBulk),
                note);
  recordOutcome(operationLabel(Operation::GetBulk, label), getBulkProblem(bulk), {});
}

// One GETBULK, recorded as `GETBULK <label>`.
template <typename Auth>
void getBulkAndRecord(const Target& target, const Auth& auth, const std::string& label) {
  recordOutcome(operationLabel(Operation::GetBulk, label),
                getBulkProblem(sendGetBulk(target, auth)), {});
}

// Record that every row of the GET matrix was skipped for the same reason.
inline void recordAuthAndPrivacyMatrixSkipped(const std::string& reason) {
  recordSkip(pairLabel(noAuthRow, noPrivRow), reason);
  for (const auto& auth : authProtocols) {
    recordSkip(pairLabel(auth, noPrivRow), reason);
    for (const auto& priv : privProtocols) {
      recordSkip(pairLabel(auth, priv), reason);
    }
  }
}

// Why the Key Extension rows skip when the run does not say the Agent serves them.
inline const std::string keyExtensionsUnset =
    "needs SNMPIO_INTEROP_V3_KEY_EXTENSIONS and an Agent serving AES-192/256";

// Record that all four of an operation's Key Extension rows were skipped for the same reason.
inline void recordKeyExtensionsSkipped(Operation operation, const std::string& reason) {
  for (const auto& priv : keyExtensionProtocols) {
    recordSkip(operationLabel(operation, pairLabel(keyExtensionAuthRow, priv)), reason);
  }
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPOPERATIONS_HPP
