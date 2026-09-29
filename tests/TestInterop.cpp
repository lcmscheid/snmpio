#include <gtest/gtest.h>

#include <optional>
#include <string>

#include <snmpio/Client.hpp>

#include "InteropOperations.hpp"
#include "InteropSet.hpp"
#include "InteropTarget.hpp"
#include "InteropWalk.hpp"

namespace snmpio {
namespace {

using test::envPort;
using test::envVar;
using test::expectedRefusal;
using test::getAndRecord;
using test::getNextAndGetBulkAndRecord;
using test::makeInteropTarget;
using test::Operation;
using test::operationLabel;
using test::recordSkip;
using test::refusedSetAndRecord;
using test::walkBothModesAndRecord;
using test::writerCommunityVariable;
using test::writeReadAndRestoreAndRecord;
using test::writerUnset;

// A live Agent that is not ours -- not the Scripted Agent of ScriptedAgent.hpp and not the
// Simulator either, but whatever answers at the Target, correct or not -- and a Response from it
// decoded by the same code path every other operation goes through.
//
// Every test skips when SNMPIO_INTEROP_TARGET is unset, so a checkout with no Agent in reach still
// runs green. That is not a hole -- an interop suite that invents its own Agent is a unit test. A
// SNMPIO_INTEROP_COMMUNITY naming a Community the Agent does not answer to fails, like any other
// variable that is set but unusable: the request times out.
class InteropV2c : public ::testing::Test {
 protected:
  void SetUp() override {
    const auto address = envVar("SNMPIO_INTEROP_TARGET");
    if (!address) GTEST_SKIP() << "set SNMPIO_INTEROP_TARGET=address to run the interop suite";

    // Configured and unusable fails rather than skips: a typo in either variable that quietly
    // skipped would leave the suite reporting green for an Agent it never reached.
    const auto target = makeInteropTarget(*address, envPort("SNMPIO_INTEROP_PORT"));
    ASSERT_TRUE(target.has_value())
        << "SNMPIO_INTEROP_TARGET/_PORT is not an address and a port: " << *address;
    m_target = *target;

    // `public` is what every Agent we configure answers to. A switch on the bench answers to
    // whatever someone chose for it, and that is a secret -- so a named one is used but never
    // printed, since the summary is meant to be copied into the README.
    const auto community = envVar("SNMPIO_INTEROP_COMMUNITY");
    m_community = Community(community.value_or("public"));
    m_label = community ? "v2c/named community" : "v2c/public";
  }

  Target m_target;
  Community m_community;
  std::string m_label;
};

TEST_F(InteropV2c, GetsSysDescrFromALiveAgent) {
  getAndRecord(m_target, m_community, m_label);
}

// Successor semantics as an Agent nobody here wrote reads RFC 3416: the Scripted Agent shares our
// reading, so it cannot catch a misreading of it. GETBULK carries non-repeaters and repetitions
// together, which is where the error-status and error-index slots are reused as counts -- checked
// against someone else's decoder.
TEST_F(InteropV2c, GetNextAndGetBulkReturnEachOidsSuccessor) {
  getNextAndGetBulkAndRecord(m_target, m_community, m_label);
}

// A Walk that needs several batches, in GETNEXT mode and in GETBULK mode, each streaming and
// collecting, against an Agent that is not misbehaving -- the misbehaviour suite is the only other
// place a Walk reaches a live Agent, and there it is told to go wrong. The two modes' OID lists
// are held to each other, so the Agent supplies the expected answer.
TEST_F(InteropV2c, WalksSeveralBatchesInBothModes) {
  walkBothModesAndRecord(m_target, m_community, m_label);
}

// The promise that a rejected SET surfaces the Agent's own error-status, held to an Agent that is
// not ours -- to the exact status its capability flag names, so that a Command Generator turning
// every refusal into one generic error fails. It writes sysDescr.0's own value back with the
// Community every test reads with, so it changes nothing and needs no writer.
TEST_F(InteropV2c, SurfacesTheAgentsRefusalOfASet) {
  std::optional<ErrorStatus> expected;
  ASSERT_NO_FATAL_FAILURE(expectedRefusal(expected));
  refusedSetAndRecord(m_target, m_community, m_label, expected);
}

// A write that lands, proven by reading it back, and then undone -- only with the writer Community
// the run names, since it changes the Target. A writer Community is a secret on a Target we did
// not configure, as the read one is, so the summary never prints it.
TEST_F(InteropV2c, WritesReadsBackAndRestoresSysContact) {
  const std::string label = "v2c/writer community";
  const auto writer = envVar(writerCommunityVariable);
  if (!writer) {
    const auto reason = writerUnset(writerCommunityVariable);
    recordSkip(operationLabel(Operation::Set, label), reason);
    GTEST_SKIP() << reason;
  }
  writeReadAndRestoreAndRecord(m_target, Community(*writer), label);
}

}  // namespace
}  // namespace snmpio
