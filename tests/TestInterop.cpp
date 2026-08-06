#include <gtest/gtest.h>

#include <iostream>
#include <string>

#include <snmpio/Client.hpp>

#include "InteropTarget.hpp"

namespace snmpio {
namespace {

using test::envVar;
using test::makeInteropTarget;

const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};

TEST(HarnessTarget, TakesAnAddressWithAndWithoutAPort) {
  const auto bare = makeInteropTarget("10.0.0.1");
  ASSERT_TRUE(bare.has_value());
  EXPECT_EQ(bare->endpoint.address().to_string(), "10.0.0.1");
  EXPECT_EQ(bare->endpoint.port(), defaultPort);

  const auto withPort = makeInteropTarget("127.0.0.1:16161");
  ASSERT_TRUE(withPort.has_value());
  EXPECT_EQ(withPort->endpoint.address().to_string(), "127.0.0.1");
  EXPECT_EQ(withPort->endpoint.port(), 16161);
}

TEST(HarnessTarget, TakesAnIpv6LiteralEitherWay) {
  const auto bare = makeInteropTarget("::1");
  ASSERT_TRUE(bare.has_value());
  EXPECT_EQ(bare->endpoint.address().to_string(), "::1");
  EXPECT_EQ(bare->endpoint.port(), defaultPort);

  const auto bracketed = makeInteropTarget("[fe80::1]:1161");
  ASSERT_TRUE(bracketed.has_value());
  EXPECT_EQ(bracketed->endpoint.address().to_string(), "fe80::1");
  EXPECT_EQ(bracketed->endpoint.port(), 1161);
}

// A hostname is not resolved here on purpose -- see makeInteropTarget. Rejecting it outright is
// what keeps that from looking like a bug in the harness the first time someone writes one.
TEST(HarnessTarget, RejectsWhatIsNotAnAddressAndAPort) {
  EXPECT_FALSE(makeInteropTarget("").has_value());
  EXPECT_FALSE(makeInteropTarget("localhost").has_value());
  EXPECT_FALSE(makeInteropTarget("agent.example:161").has_value());
  EXPECT_FALSE(makeInteropTarget(":161").has_value());
  EXPECT_FALSE(makeInteropTarget("10.0.0.1:").has_value());
  EXPECT_FALSE(makeInteropTarget("10.0.0.1:0").has_value());
  EXPECT_FALSE(makeInteropTarget("10.0.0.1:70000").has_value());
  EXPECT_FALSE(makeInteropTarget("10.0.0.1:161x").has_value());
  EXPECT_FALSE(makeInteropTarget("[fe80::1").has_value());
  EXPECT_FALSE(makeInteropTarget("[]:161").has_value());
  EXPECT_FALSE(makeInteropTarget("[fe80::1]161").has_value());
}

// One live exchange, which is the whole of what this file proves: a Response from an Agent that
// is not ours, decoded by the same code path every other operation goes through. Not the Scripted
// Agent of ScriptedAgent.hpp and not the Simulator either -- whatever answers at the Target,
// correct or not.
//
// It skips when SNMPIO_INTEROP_TARGET is unset, so a checkout with no Agent in reach still runs
// green. That is not a hole -- an interop suite that invents its own Agent is a unit test.
TEST(InteropV2c, GetsSysDescrFromALiveAgent) {
  const auto spec = envVar("SNMPIO_INTEROP_TARGET");
  if (!spec) GTEST_SKIP() << "set SNMPIO_INTEROP_TARGET=address[:port] to run the interop suite";

  // Configured and unusable fails rather than skips: a typo in the variable that quietly skipped
  // would leave the suite reporting green for an Agent it never reached.
  const auto target = makeInteropTarget(*spec);
  ASSERT_TRUE(target.has_value()) << "SNMPIO_INTEROP_TARGET is not address[:port]: " << *spec;

  net::IoContext io;
  Client client(io.get_executor());
  net::ErrorCode ec;
  Response response;
  bool completed = false;

  client.asyncGet(*target, Community("public"), {sysDescr}, [&](net::ErrorCode e, Response r) {
    ec = e;
    response = std::move(r);
    completed = true;
    client.stop();
  });
  io.run();

  ASSERT_TRUE(completed) << "the GET never completed";
  ASSERT_FALSE(ec) << ec.category().name() << ": " << ec.message();
  ASSERT_EQ(response.varbinds.size(), 1U);
  EXPECT_EQ(response.varbinds[0].name, sysDescr);

  const auto* const descr = std::get_if<Octets>(&response.varbinds[0].val);
  ASSERT_NE(descr, nullptr) << "sysDescr.0 came back as something other than an OCTET STRING";
  EXPECT_FALSE(descr->empty());

  // Printed rather than asserted on: no two Agents say the same thing, and which one answered is
  // the first thing anyone reading a failed interop run wants to know.
  std::cout << "sysDescr.0: "
            << std::string(reinterpret_cast<const char*>(descr->data()), descr->size()) << "\n";
}

}  // namespace
}  // namespace snmpio
