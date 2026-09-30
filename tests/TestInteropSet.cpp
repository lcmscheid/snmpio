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
using test::octetsOf;
using test::Operation;
using test::operationLabel;
using test::readOctets;
using test::refusalNote;
using test::refusalProblem;
using test::sysContact;
using test::sysDescr;

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

ExchangeResult timedOut() {
  ExchangeResult result;
  result.ec = make_error_code(Errc::Timeout);
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
  EXPECT_NE(refusalProblem(answered({{sysDescr, octetsOf("x")}}), ErrorStatus::NoAccess), "");
  EXPECT_NE(refusalProblem(answered({{sysDescr, octetsOf("x")}}), std::nullopt), "");
}

// A timeout is the Agent's silence, not its refusal -- even beside an error-index that would pass.
TEST(InteropSet, RejectsAFailureThatIsNotTheAgentsOwn) {
  auto silence = timedOut();
  silence.response.errorIndex = 1;
  EXPECT_NE(refusalProblem(silence, std::nullopt), "");
  EXPECT_NE(refusalProblem(silence, ErrorStatus::NoAccess), "");
}

// The request carries one Varbind, so RFC 3416 has the error-index name it. An Agent that names
// another is noted on the row, not failed: the status is what the test asserts.
TEST(InteropSet, NotesARefusalThatBlamesAnotherVarbind) {
  EXPECT_EQ(refusalProblem(refused(ErrorStatus::NoAccess, 0), ErrorStatus::NoAccess), "");
  EXPECT_EQ(refusalNote(refused(ErrorStatus::NoAccess, 1), ErrorStatus::NoAccess), "");
  EXPECT_TRUE(mentions(refusalNote(refused(ErrorStatus::NoAccess, 0), ErrorStatus::NoAccess),
                       "blamed Varbind 0"));
  EXPECT_TRUE(mentions(refusalNote(refused(ErrorStatus::NoAccess, 2), ErrorStatus::NoAccess),
                       "blamed Varbind 2"));
  // A refusal with the wrong status is still the Agent's own, so its index still says something.
  EXPECT_TRUE(mentions(refusalNote(refused(ErrorStatus::NotWritable, 0), ErrorStatus::NoAccess),
                       "blamed Varbind 0"));
}

// Only a refusal blames a Varbind. A SET the Agent took, or one it never answered, leaves the
// error-index at 0 -- and a failed row saying the Agent blamed Varbind 0 would send whoever reads
// it after a refusal that never happened.
TEST(InteropSet, NotesNoBlamedVarbindWhenNothingWasRefused) {
  const auto accepted = refusalNote(answered({{sysDescr, octetsOf("x")}}), ErrorStatus::NoAccess);
  EXPECT_FALSE(mentions(accepted, "blamed Varbind")) << accepted;
  const auto silent = refusalNote(timedOut(), ErrorStatus::NoAccess);
  EXPECT_FALSE(mentions(silent, "blamed Varbind")) << silent;
}

TEST(InteropSet, ReadsTheOctetsOfTheOneVarbindAskedFor) {
  const auto read = readOctets(answered({{sysContact, octetsOf("noc")}}), sysContact);
  EXPECT_EQ(read.problem, "");
  EXPECT_EQ(read.value, octetsOf("noc"));
}

TEST(InteropSet, RejectsAReadThatIsNotThatObjectsOctets) {
  EXPECT_NE(readOctets(answered({{sysDescr, octetsOf("noc")}}), sysContact).problem, "");
  EXPECT_NE(readOctets(answered({{sysContact, 4}}), sysContact).problem, "");
  EXPECT_NE(readOctets(answered({{sysContact, ValueException::NoSuchObject}}), sysContact).problem,
            "");
  EXPECT_NE(readOctets(answered({}), sysContact).problem, "");
  EXPECT_NE(readOctets(timedOut(), sysContact).problem, "");
}

// A write of the value already there would pass a read-back without ever landing.
TEST(InteropSet, WritesSomethingOtherThanWhatWasThere) {
  EXPECT_NE(differentFrom(octetsOf("")), octetsOf(""));
  EXPECT_NE(differentFrom(octetsOf("noc")), octetsOf("noc"));
  const auto usual = differentFrom(octetsOf(""));
  EXPECT_NE(differentFrom(usual), usual);
}

TEST(InteropSet, SaysWhatARefusalRowWasHeldTo) {
  EXPECT_EQ(refusalNote(refused(ErrorStatus::NoAccess), ErrorStatus::NoAccess), "");
  EXPECT_TRUE(mentions(refusalNote(refused(ErrorStatus::NotWritable), std::nullopt),
                       "SNMPIO_INTEROP_SET_REFUSAL"));
  // A readOnly refusal is non-compliant, and its row says so rather than passing silently.
  EXPECT_TRUE(mentions(refusalNote(refused(ErrorStatus::ReadOnly), ErrorStatus::ReadOnly),
                       "lcmscheid/snmp-fault-agent#10"));
  // Both at once, as an Agent with snmp-fault-agent#10 and #12 gives them, and neither hiding the
  // other.
  const auto both = refusalNote(refused(ErrorStatus::ReadOnly, 0), ErrorStatus::ReadOnly);
  EXPECT_TRUE(mentions(both, "lcmscheid/snmp-fault-agent#10")) << both;
  EXPECT_TRUE(mentions(both, "blamed Varbind 0")) << both;
}

TEST(InteropSet, LabelsBothSetRowsByThePdu) {
  EXPECT_EQ(operationLabel(Operation::Set, "noAuthNoPriv"), "SET noAuthNoPriv");
  EXPECT_EQ(operationLabel(Operation::RefusedSet, "noAuthNoPriv"), "SET refused noAuthNoPriv");
}

}  // namespace
}  // namespace snmpio
