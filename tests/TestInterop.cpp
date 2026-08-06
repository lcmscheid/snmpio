#include <gtest/gtest.h>

#include <iostream>
#include <optional>
#include <string>

#include <snmpio/Client.hpp>

#include "InteropTarget.hpp"

namespace snmpio {
namespace {

using test::envVar;
using test::interopCommunity;
using test::makeInteropTarget;
using test::splitAddressPort;

const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};

TEST(HarnessAddressPort, DefaultsToTheSnmpPort) {
  const auto hp = splitAddressPort("10.0.0.1");
  ASSERT_TRUE(hp.has_value());
  EXPECT_EQ(hp->address, "10.0.0.1");
  EXPECT_EQ(hp->port, defaultPort);
}

TEST(HarnessAddressPort, TakesAnExplicitPort) {
  const auto hp = splitAddressPort("127.0.0.1:16161");
  ASSERT_TRUE(hp.has_value());
  EXPECT_EQ(hp->address, "127.0.0.1");
  EXPECT_EQ(hp->port, 16161);
}

TEST(HarnessAddressPort, ReadsABareIpv6LiteralAsAllAddress) {
  const auto hp = splitAddressPort("::1");
  ASSERT_TRUE(hp.has_value());
  EXPECT_EQ(hp->address, "::1");
  EXPECT_EQ(hp->port, defaultPort);
}

TEST(HarnessAddressPort, TakesAPortAfterABracketedIpv6Literal) {
  const auto hp = splitAddressPort("[fe80::1]:1161");
  ASSERT_TRUE(hp.has_value());
  EXPECT_EQ(hp->address, "fe80::1");
  EXPECT_EQ(hp->port, 1161);
}

TEST(HarnessAddressPort, RejectsWhatCannotBeAPort) {
  EXPECT_FALSE(splitAddressPort("").has_value());
  EXPECT_FALSE(splitAddressPort(":161").has_value());
  EXPECT_FALSE(splitAddressPort("host:").has_value());
  EXPECT_FALSE(splitAddressPort("host:0").has_value());
  EXPECT_FALSE(splitAddressPort("host:70000").has_value());
  EXPECT_FALSE(splitAddressPort("host:161x").has_value());
  EXPECT_FALSE(splitAddressPort("[fe80::1").has_value());
  EXPECT_FALSE(splitAddressPort("[]:161").has_value());
  EXPECT_FALSE(splitAddressPort("[fe80::1]161").has_value());
}

TEST(HarnessTarget, BuildsAnEndpointFromAnAddressAndPort) {
  const auto target = makeInteropTarget("127.0.0.1:16161");
  ASSERT_TRUE(target.has_value());
  EXPECT_EQ(target->endpoint.address().to_string(), "127.0.0.1");
  EXPECT_EQ(target->endpoint.port(), 16161);
}

TEST(HarnessTarget, TakesAnIpv6LiteralEitherWay) {
  const auto bare = makeInteropTarget("::1");
  ASSERT_TRUE(bare.has_value());
  EXPECT_EQ(bare->endpoint.port(), defaultPort);

  const auto bracketed = makeInteropTarget("[::1]:1161");
  ASSERT_TRUE(bracketed.has_value());
  EXPECT_EQ(bracketed->endpoint.address().to_string(), "::1");
  EXPECT_EQ(bracketed->endpoint.port(), 1161);
}

// A hostname is not resolved here on purpose -- see makeInteropTarget. Rejecting it outright is
// what keeps that from looking like a bug in the harness the first time someone writes one.
TEST(HarnessTarget, RejectsAHostname) {
  EXPECT_FALSE(makeInteropTarget("agent.example:161").has_value());
  EXPECT_FALSE(makeInteropTarget("localhost").has_value());
}

// One live exchange, which is the whole of what this file proves: a Response from an Agent that
// is not ours, decoded by the same code path every other operation goes through.
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

  client.asyncGet(*target, interopCommunity(), {sysDescr}, [&](net::ErrorCode e, Response r) {
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
  std::string text;
  for (const auto byte : *descr) text.push_back(static_cast<char>(byte));
  std::cout << "sysDescr.0: " << text << "\n";
}

}  // namespace
}  // namespace snmpio
