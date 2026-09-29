#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <vector>

#include <snmpio/Oid.hpp>
#include <snmpio/Value.hpp>

#include "InteropOperations.hpp"

// The successor checks the interop suite holds a live Agent to, held here to Responses built by
// hand -- so that a check which passes a wrong answer is caught without an Agent that sends one.
namespace snmpio {
namespace {

using test::bulkSuccessorOfSysDescr;
using test::ExchangeResult;
using test::getBulkProblem;
using test::getNextProblem;
using test::GetNextVarbinds;
using test::Operation;
using test::operationLabel;
using test::replaces;
using test::RowOutcome;
using test::sysDescr;

constexpr auto several = GetNextVarbinds::Several;
constexpr auto one = GetNextVarbinds::One;

// The `system` group's scalars in order, 1.3.6.1.2.1.1.<n>.0: n = 1 is sysDescr.0.
Oid scalarOid(std::uint32_t n) {
  return Oid{1, 3, 6, 1, 2, 1, 1, n, 0};
}

Varbind scalar(std::uint32_t n) {
  return Varbind{scalarOid(n), Octets{}};
}

Varbind endOfMibView(const Oid& name) {
  return Varbind{name, ValueException::EndOfMibView};
}

ExchangeResult answered(std::vector<Varbind> varbinds) {
  ExchangeResult result;
  result.response.varbinds = std::move(varbinds);
  return result;
}

TEST(InteropOperations, GetBulkAcceptsTwoColumnsOneRowApart) {
  EXPECT_EQ(getBulkProblem(answered(
                {scalar(1), scalar(1), scalar(2), scalar(2), scalar(3), scalar(3), scalar(4)})),
            "");
}

// RFC 3416 section 4.2.3 lets the last row stop partway through.
TEST(InteropOperations, GetBulkAcceptsAShortLastRow) {
  EXPECT_EQ(
      getBulkProblem(answered({scalar(1), scalar(1), scalar(2), scalar(2), scalar(3), scalar(3)})),
      "");
}

TEST(InteropOperations, GetBulkAcceptsColumnsEndingOneRowApart) {
  EXPECT_EQ(getBulkProblem(
                answered({scalar(1), scalar(1), scalar(2), scalar(2), endOfMibView(scalar(2).name),
                          endOfMibView(scalar(2).name), endOfMibView(scalar(2).name)})),
            "");
}

// The column from `system` ending while the column from sysDescr.0 still has the OID it should
// have reached is the same mismatch as two different OIDs, and must not pass for running out.
TEST(InteropOperations, GetBulkRejectsTheColumnFromSystemEndingEarly) {
  EXPECT_NE(getBulkProblem(answered({scalar(1), scalar(1), scalar(2), endOfMibView(scalar(1).name),
                                     endOfMibView(scalar(2).name)})),
            "");
}

TEST(InteropOperations, GetBulkRejectsTheColumnFromSysDescrEndingEarly) {
  EXPECT_NE(getBulkProblem(answered(
                {scalar(1), scalar(1), endOfMibView(sysDescr), scalar(2), endOfMibView(sysDescr)})),
            "");
}

// GETNEXT's second successor is held to GETBULK's column from sysDescr.0, since no MIB contents
// are pinned to say what it is.
TEST(InteropOperations, GetNextAgreesWithGetBulkOnTheSuccessorOfSysDescr) {
  const auto bulk = answered({scalar(1), scalar(1), scalar(2), scalar(2), scalar(3)});
  EXPECT_EQ(
      getNextProblem(answered({scalar(1), scalar(2)}), several, bulkSuccessorOfSysDescr(bulk)), "");
  EXPECT_NE(
      getNextProblem(answered({scalar(1), scalar(3)}), several, bulkSuccessorOfSysDescr(bulk)), "");
}

TEST(InteropOperations, GetNextRejectsAGetBulkThatFoundNothingAfterSysDescr) {
  const auto bulk = answered({scalar(1), scalar(1), endOfMibView(sysDescr)});
  EXPECT_NE(
      getNextProblem(answered({scalar(1), scalar(2)}), several, bulkSuccessorOfSysDescr(bulk)), "");
}

// Both Varbinds answered from the last requested OID -- the defect the Simulator images have.
TEST(InteropOperations, GetNextRejectsBothAnsweredFromOneOid) {
  const auto bulk = answered({scalar(1), scalar(1), scalar(2), scalar(2), scalar(3)});
  EXPECT_NE(
      getNextProblem(answered({scalar(2), scalar(2)}), several, bulkSuccessorOfSysDescr(bulk)), "");
}

// One Varbind per request is what an Agent that answers several from the wrong OIDs can still be
// held to.
TEST(InteropOperations, GetNextOfOneVarbindIsSysDescr) {
  const auto bulk = answered({scalar(1), scalar(2)});
  EXPECT_EQ(getNextProblem(answered({scalar(1)}), one, bulkSuccessorOfSysDescr(bulk)), "");
  EXPECT_NE(getNextProblem(answered({scalar(2)}), one, bulkSuccessorOfSysDescr(bulk)), "");
}

TEST(InteropOperations, GetRowsAreLabelledByThePairAlone) {
  EXPECT_EQ(operationLabel(Operation::Get, "noAuthNoPriv"), "noAuthNoPriv");
  EXPECT_EQ(operationLabel(Operation::GetBulk, "noAuthNoPriv"), "GETBULK noAuthNoPriv");
}

// Without a GETBULK answer to compare with, the second successor is only held to following
// sysDescr.0 -- the caller says so on the row, and the GETBULK's own row fails.
TEST(InteropOperations, GetNextWithoutAGetBulkAnswerIsHeldToOrderAlone) {
  EXPECT_EQ(getNextProblem(answered({scalar(1), scalar(3)}), several, std::nullopt), "");
  EXPECT_NE(getNextProblem(answered({scalar(1), scalar(1)}), several, std::nullopt), "");
}

// A row two tests reach says the worst either found, whichever ran first.
TEST(InteropOperations, SummaryRowsKeepTheWorstOutcome) {
  EXPECT_TRUE(replaces(RowOutcome::Ok, RowOutcome::Skipped));
  EXPECT_TRUE(replaces(RowOutcome::Failed, RowOutcome::Skipped));
  EXPECT_TRUE(replaces(RowOutcome::Failed, RowOutcome::Ok));
  EXPECT_FALSE(replaces(RowOutcome::Ok, RowOutcome::Failed));
  EXPECT_FALSE(replaces(RowOutcome::Skipped, RowOutcome::Ok));
  EXPECT_FALSE(replaces(RowOutcome::Skipped, RowOutcome::Failed));
}

}  // namespace
}  // namespace snmpio
