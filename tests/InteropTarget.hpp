#ifndef SNMPIO_TESTS_INTEROPTARGET_HPP
#define SNMPIO_TESTS_INTEROPTARGET_HPP

#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include <snmpio/Target.hpp>
#include <snmpio/detail/Net.hpp>

// Where the interop suite's Agent is, shared by its v2c and v3 halves.
//
// It comes from the environment rather than from a fixture constant because the Agent is not ours
// -- it is a container CI starts, an `snmpd` on a workstation, or a switch on the bench, and only
// whoever runs the suite knows which. With nothing set, every interop test skips: an unconfigured
// checkout must not fail its test run over a Target that was never there.
namespace snmpio::test {

[[nodiscard]] inline std::optional<std::string> envVar(const char* name) {
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
[[nodiscard]] inline std::optional<Target> makeInteropTarget(std::string_view spec) {
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

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPTARGET_HPP
