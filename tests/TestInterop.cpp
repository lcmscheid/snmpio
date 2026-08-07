#include <gtest/gtest.h>

#include <iostream>
#include <string>

#include <snmpio/Client.hpp>

#include "InteropTarget.hpp"

namespace snmpio {
namespace {

using test::envPort;
using test::envVar;
using test::get;
using test::makeInteropTarget;
using test::sysDescr;

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

  const auto result = get(*target, Community("public"));
  ASSERT_FALSE(result.ec) << result.ec.category().name() << ": " << result.ec.message();
  ASSERT_EQ(result.response.varbinds.size(), 1U);
  EXPECT_EQ(result.response.varbinds[0].name, sysDescr);

  const auto* const descr = std::get_if<Octets>(&result.response.varbinds[0].val);
  ASSERT_NE(descr, nullptr) << "sysDescr.0 came back as something other than an OCTET STRING";
  EXPECT_FALSE(descr->empty());

  // Printed rather than asserted on: no two Agents say the same thing, and which one answered is
  // the first thing anyone reading a failed interop run wants to know.
  std::cout << "sysDescr.0: "
            << std::string(reinterpret_cast<const char*>(descr->data()), descr->size()) << "\n";
}

}  // namespace
}  // namespace snmpio
