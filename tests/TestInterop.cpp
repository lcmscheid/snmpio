#include <gtest/gtest.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include <snmpio/Client.hpp>

namespace snmpio {
namespace {

const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};

std::optional<std::string> envVar(const char* name) {
  // NOLINTNEXTLINE(concurrency-mt-unsafe): read once, before any test thread exists.
  const char* const value = std::getenv(name);
  if (value == nullptr || *value == '\0') return std::nullopt;
  return std::string(value);
}

// The Target `spec` names -- "10.0.0.1", "10.0.0.1:1161", "::1" or "[::1]:1161" -- or nullopt when
// it is not an address and a port. The bracketed form is how a v6 literal carries a port, since
// the bare one is already all colons.
//
// An address, not a hostname: the library builds a Target from an endpoint precisely so that
// choosing a resolver stays the caller's business, and a test harness is a caller like any other.
// Everything this suite ever talks to -- a container with a published port, an `snmpd` on a spare
// port, a switch on the bench -- is reachable by address.
std::optional<Target> makeInteropTarget(std::string_view spec) {
  net::ErrorCode ec;
  auto address = net::asio::ip::make_address(std::string(spec), ec);
  std::uint16_t port = defaultPort;

  // Whatever did not parse whole carries a port, and the last colon is where it starts -- in
  // "[fe80::1]:1161" as much as in "10.0.0.1:1161", which is what the brackets are there for.
  if (ec) {
    const auto colon = spec.rfind(':');
    if (colon == std::string_view::npos) return std::nullopt;

    // A std::string, not the string_view: from_chars wants a pointer pair, and handing it one
    // taken off a view is what bugprone-suspicious-stringview-data-usage exists to stop.
    const std::string portText(spec.substr(colon + 1));
    const auto* const last = portText.data() + portText.size();
    const auto [end, portEc] = std::from_chars(portText.data(), last, port);
    if (portEc != std::errc{} || end != last || port == 0) return std::nullopt;

    auto addressText = spec.substr(0, colon);
    if (addressText.size() >= 2 && addressText.front() == '[' && addressText.back() == ']') {
      addressText = addressText.substr(1, addressText.size() - 2);
    }
    address = net::asio::ip::make_address(std::string(addressText), ec);
    if (ec) return std::nullopt;
  }

  Target target{net::UdpEndpoint(address, port)};
  // A container still coming up, or a switch across a WAN link, is slower than the loopback socket
  // every other test in this tree runs over. The library's defaults are for callers, not for a
  // bring-up suite.
  target.timeout = std::chrono::milliseconds(5000);
  target.retries = 2;
  return target;
}

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
