#include <gtest/gtest.h>

#include <snmpio/Client.hpp>

#include "InteropSummary.hpp"
#include "InteropTarget.hpp"

namespace snmpio {
namespace {

using test::envPort;
using test::envVar;
using test::getAndRecord;
using test::makeInteropTarget;

// One live exchange, which is the whole of what this file proves: a Response from an Agent that
// is not ours, decoded by the same code path every other operation goes through. Not the Scripted
// Agent of ScriptedAgent.hpp and not the Simulator either -- whatever answers at the Target,
// correct or not.
//
// It skips when SNMPIO_INTEROP_TARGET is unset, so a checkout with no Agent in reach still runs
// green. That is not a hole -- an interop suite that invents its own Agent is a unit test.
TEST(InteropV2c, GetsSysDescrFromALiveAgent) {
  const auto address = envVar("SNMPIO_INTEROP_TARGET");
  if (!address) GTEST_SKIP() << "set SNMPIO_INTEROP_TARGET=address to run the interop suite";

  // Configured and unusable fails rather than skips: a typo in either variable that quietly
  // skipped would leave the suite reporting green for an Agent it never reached.
  const auto target = makeInteropTarget(*address, envPort("SNMPIO_INTEROP_PORT"));
  ASSERT_TRUE(target.has_value()) << "SNMPIO_INTEROP_TARGET/_PORT is not an address and a port: "
                                  << *address;

  getAndRecord(*target, Community("public"), "v2c/public");
}

}  // namespace
}  // namespace snmpio
