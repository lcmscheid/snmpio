#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include <snmpio/Oid.hpp>
#include <snmpio/Value.hpp>

#include "InteropOperations.hpp"

// The successor checks the interop suite holds a live Agent to, held here to Responses built by
// hand -- so that a check which passes a wrong answer is caught without an Agent that sends one.
namespace snmpio {
namespace {

using test::ExchangeResult;
using test::getBulkProblem;
using test::getNextProblem;
using test::GetNextShape;
using test::Operation;
using test::operationLabel;
using test::sysDescr;

constexpr auto several = GetNextShape::SeveralVarbinds;
constexpr auto one = GetNextShape::OneVarbind;

// The `system` group's scalars in order, 1.3.6.1.2.1.1.<n>.0: n = 1 is sysDescr.0.
Oid systemScalar(std::uint32_t n) {
  return Oid{1, 3, 6, 1, 2, 1, 1, n, 0};
}

Varbind at(std::uint32_t n) {
  return Varbind{systemScalar(n), Octets{}};
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
  EXPECT_EQ(getBulkProblem(answered({at(1), at(1), at(2), at(2), at(3), at(3), at(4)})), "");
}

// RFC 3416 section 4.2.3 lets the last row stop partway through.
TEST(InteropOperations, GetBulkAcceptsAShortLastRow) {
  EXPECT_EQ(getBulkProblem(answered({at(1), at(1), at(2), at(2), at(3), at(3)})), "");
}

TEST(InteropOperations, GetBulkAcceptsColumnsEndingOneRowApart) {
  EXPECT_EQ(getBulkProblem(answered({at(1), at(1), at(2), at(2), endOfMibView(at(2).name),
                                     endOfMibView(at(2).name), endOfMibView(at(2).name)})),
            "");
}

// The column from `system` ending while the column from sysDescr.0 still has the OID it should
// have reached is the same mismatch as two different OIDs, and must not pass for running out.
TEST(InteropOperations, GetBulkRejectsTheColumnFromSystemEndingEarly) {
  EXPECT_NE(getBulkProblem(answered(
                {at(1), at(1), at(2), endOfMibView(at(1).name), endOfMibView(at(2).name)})),
            "");
}

TEST(InteropOperations, GetBulkRejectsTheColumnFromSysDescrEndingEarly) {
  EXPECT_NE(getBulkProblem(
                answered({at(1), at(1), endOfMibView(sysDescr), at(2), endOfMibView(sysDescr)})),
            "");
}

// GETNEXT's second successor is held to GETBULK's column from sysDescr.0, since no MIB contents
// are pinned to say what it is.
TEST(InteropOperations, GetNextAgreesWithGetBulkOnTheSuccessorOfSysDescr) {
  const auto bulk = answered({at(1), at(1), at(2), at(2), at(3)});
  EXPECT_EQ(getNextProblem(answered({at(1), at(2)}), several, bulk), "");
  EXPECT_NE(getNextProblem(answered({at(1), at(3)}), several, bulk), "");
}

TEST(InteropOperations, GetNextRejectsAGetBulkThatFoundNothingAfterSysDescr) {
  const auto bulk = answered({at(1), at(1), endOfMibView(sysDescr)});
  EXPECT_NE(getNextProblem(answered({at(1), at(2)}), several, bulk), "");
}

// Both Varbinds answered from the last requested OID -- the defect the Simulator images have.
TEST(InteropOperations, GetNextRejectsBothAnsweredFromOneOid) {
  const auto bulk = answered({at(1), at(1), at(2), at(2), at(3)});
  EXPECT_NE(getNextProblem(answered({at(2), at(2)}), several, bulk), "");
}

// One Varbind per request is what an Agent that answers several from the wrong OIDs can still be
// held to.
TEST(InteropOperations, GetNextOfOneVarbindIsSysDescr) {
  const auto bulk = answered({at(1), at(2)});
  EXPECT_EQ(getNextProblem(answered({at(1)}), one, bulk), "");
  EXPECT_NE(getNextProblem(answered({at(2)}), one, bulk), "");
}

TEST(InteropOperations, GetRowsAreLabelledByThePairAlone) {
  EXPECT_EQ(operationLabel(Operation::Get, "noAuthNoPriv"), "noAuthNoPriv");
  EXPECT_EQ(operationLabel(Operation::GetBulk, "noAuthNoPriv"), "GETBULK noAuthNoPriv");
}

}  // namespace
}  // namespace snmpio
