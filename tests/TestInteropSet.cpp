#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include <snmpio/Error.hpp>
#include <snmpio/Oid.hpp>
#include <snmpio/Pdu.hpp>
#include <snmpio/Value.hpp>

#include "InteropOperations.hpp"
#include "InteropSet.hpp"

// The checks the interop suite holds a live SET to, held here to Responses built by hand -- so
// that a check which passes a wrong answer is caught without an Agent that sends one.
namespace snmpio {
namespace {

using test::differentFrom;
using test::errorStatusNamed;
using test::ExchangeResult;
using test::Operation;
using test::operationLabel;
using test::readOctets;
using test::refusalNote;
using test::refusalProblem;
using test::sysContact;
using test::sysDescr;

Octets octets(const std::string& text) {
  Octets bytes;
  for (const char c : text) bytes.push_back(static_cast<std::byte>(c));
  return bytes;
}

ExchangeResult answered(std::vector<Varbind> varbinds) {
  ExchangeResult result;
  result.response.varbinds = std::move(varbinds);
  return result;
}

ExchangeResult refused(ErrorStatus status, std::int32_t errorIndex = 1) {
  ExchangeResult result;
  result.ec = make_error_code(status);
  result.response.errorIndex = errorIndex;
  return result;
}

bool mentions(const std::string& text, const std::string& part) {
  return text.find(part) != std::string::npos;
}

// The flag is spelled as RFC 3416 spells the status, which is how the library's own messages
// spell it too.
TEST(InteropSet, NamesAnErrorStatusAsRfc3416SpellsIt) {
  EXPECT_EQ(errorStatusNamed("noAccess"), ErrorStatus::NoAccess);
  EXPECT_EQ(errorStatusNamed("notWritable"), ErrorStatus::NotWritable);
  EXPECT_EQ(errorStatusNamed("readOnly"), ErrorStatus::ReadOnly);
  EXPECT_EQ(errorStatusNamed("tooBig"), ErrorStatus::TooBig);
  EXPECT_EQ(errorStatusNamed("inconsistentName"), ErrorStatus::InconsistentName);
}

// noError is no refusal, and anything else is a typo that must fail the run rather than widen the
// check to any refusal.
TEST(InteropSet, NamesNoStatusForNoErrorOrATypo) {
  EXPECT_EQ(errorStatusNamed("noError"), std::nullopt);
  EXPECT_EQ(errorStatusNamed("success"), std::nullopt);
  EXPECT_EQ(errorStatusNamed("noaccess"), std::nullopt);
  EXPECT_EQ(errorStatusNamed("NoAccess"), std::nullopt);
  EXPECT_EQ(errorStatusNamed("4"), std::nullopt);
  EXPECT_EQ(errorStatusNamed(""), std::nullopt);
}

TEST(InteropSet, AcceptsTheRefusalTheFlagNames) {
  EXPECT_EQ(refusalProblem(refused(ErrorStatus::NoAccess), ErrorStatus::NoAccess), "");
}

// A Command Generator that turned every refusal into one generic error fails here.
TEST(InteropSet, RejectsARefusalOtherThanTheOneTheFlagNames) {
  const auto problem = refusalProblem(refused(ErrorStatus::GenErr), ErrorStatus::NoAccess);
  EXPECT_TRUE(mentions(problem, "genErr")) << problem;
  EXPECT_TRUE(mentions(problem, "noAccess")) << problem;
}

// With the flag unset, any error-status is a refusal -- and nothing else is.
TEST(InteropSet, AcceptsAnyRefusalWhenTheFlagIsUnset) {
  EXPECT_EQ(refusalProblem(refused(ErrorStatus::NotWritable), std::nullopt), "");
  EXPECT_EQ(refusalProblem(refused(ErrorStatus::ReadOnly), std::nullopt), "");
}

TEST(InteropSet, RejectsASetThatWasAccepted) {
  EXPECT_NE(refusalProblem(answered({{sysDescr, octets("x")}}), ErrorStatus::NoAccess), "");
  EXPECT_NE(refusalProblem(answered({{sysDescr, octets("x")}}), std::nullopt), "");
}

// A timeout is the Agent's silence, not its refusal -- even beside an error-index that would pass.
TEST(InteropSet, RejectsAFailureThatIsNotTheAgentsOwn) {
  ExchangeResult timedOut;
  timedOut.ec = make_error_code(Errc::Timeout);
  timedOut.response.errorIndex = 1;
  EXPECT_NE(refusalProblem(timedOut, std::nullopt), "");
  EXPECT_NE(refusalProblem(timedOut, ErrorStatus::NoAccess), "");
}

// The request carries one Varbind, so RFC 3416 has the error-index name it. An Agent that names
// another is noted on the row, not failed: the status is what the test asserts.
TEST(InteropSet, NotesARefusalThatBlamesAnotherVarbind) {
  EXPECT_EQ(refusalProblem(refused(ErrorStatus::NoAccess, 0), ErrorStatus::NoAccess), "");
  EXPECT_EQ(refusalNote(ErrorStatus::NoAccess, 1), "");
  EXPECT_TRUE(mentions(refusalNote(ErrorStatus::NoAccess, 0), "blamed Varbind 0"));
  EXPECT_TRUE(mentions(refusalNote(ErrorStatus::NoAccess, 2), "blamed Varbind 2"));
}

TEST(InteropSet, ReadsTheOctetsOfTheOneVarbindAskedFor) {
  const auto read = readOctets(answered({{sysContact, octets("noc")}}), sysContact);
  EXPECT_EQ(read.problem, "");
  EXPECT_EQ(read.value, octets("noc"));
}

TEST(InteropSet, RejectsAReadThatIsNotThatObjectsOctets) {
  EXPECT_NE(readOctets(answered({{sysDescr, octets("noc")}}), sysContact).problem, "");
  EXPECT_NE(readOctets(answered({{sysContact, 4}}), sysContact).problem, "");
  EXPECT_NE(readOctets(answered({{sysContact, ValueException::NoSuchObject}}), sysContact).problem,
            "");
  EXPECT_NE(readOctets(answered({}), sysContact).problem, "");
  ExchangeResult timedOut;
  timedOut.ec = make_error_code(Errc::Timeout);
  EXPECT_NE(readOctets(timedOut, sysContact).problem, "");
}

// A write of the value already there would pass a read-back without ever landing.
TEST(InteropSet, WritesSomethingOtherThanWhatWasThere) {
  EXPECT_NE(differentFrom(octets("")), octets(""));
  EXPECT_NE(differentFrom(octets("noc")), octets("noc"));
  const auto usual = differentFrom(octets(""));
  EXPECT_NE(differentFrom(usual), usual);
}

TEST(InteropSet, SaysWhatARefusalRowWasHeldTo) {
  EXPECT_EQ(refusalNote(ErrorStatus::NoAccess, 1), "");
  EXPECT_TRUE(mentions(refusalNote(std::nullopt, 1), "SNMPIO_INTEROP_SET_REFUSAL"));
  // The Simulator's refusal is non-compliant, and its row says so rather than passing silently.
  EXPECT_TRUE(mentions(refusalNote(ErrorStatus::ReadOnly, 1), "lcmscheid/snmp-fault-agent#10"));
  // Both at once, as the Simulator images give them, and neither hiding the other.
  const auto both = refusalNote(ErrorStatus::ReadOnly, 0);
  EXPECT_TRUE(mentions(both, "lcmscheid/snmp-fault-agent#10")) << both;
  EXPECT_TRUE(mentions(both, "blamed Varbind 0")) << both;
}

TEST(InteropSet, LabelsBothSetRowsByThePdu) {
  EXPECT_EQ(operationLabel(Operation::Set, "noAuthNoPriv"), "SET noAuthNoPriv");
  EXPECT_EQ(operationLabel(Operation::RefusedSet, "noAuthNoPriv"), "SET refused noAuthNoPriv");
}

}  // namespace
}  // namespace snmpio
