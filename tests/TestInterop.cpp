#include <gtest/gtest.h>

#include <string>

#include <snmpio/Client.hpp>

#include "InteropOperations.hpp"
#include "InteropTarget.hpp"

namespace snmpio {
namespace {

using test::envPort;
using test::envVar;
using test::getAndRecord;
using test::getNextAndGetBulkAndRecord;
using test::makeInteropTarget;

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

}  // namespace
}  // namespace snmpio
