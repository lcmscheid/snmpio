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

// The interop suite's configuration: the Target a live Agent answers at, and what authorizes a
// request against it.
//
// It is read from the environment rather than from a fixture constant because the Agent is not
// ours -- it is a container CI starts, an `snmpd` on a workstation, or a switch on the bench, and
// only whoever runs the suite knows which. With nothing set, every interop test skips: an
// unconfigured checkout must not fail its test run over a Target that was never there.
//
// This is not the Scripted Agent of ScriptedAgent.hpp, and it is not the Simulator either. It is
// whatever answers at SNMPIO_INTEROP_TARGET, correct or not.
namespace snmpio::test {

// "10.0.0.1", "10.0.0.1:1161", "::1" or "[::1]:1161" -- the bracketed form is how a v6 literal
// carries a port, since the bare one is already all colons. Port defaults to SNMP's 161.
struct AddressPort {
  std::string address;
  std::uint16_t port = defaultPort;
};

[[nodiscard]] inline std::optional<std::uint16_t> parsePort(std::string_view text) {
  std::uint16_t port = 0;
  const auto* const last = text.data() + text.size();
  const auto [end, ec] = std::from_chars(text.data(), last, port);
  if (ec != std::errc{} || end != last || port == 0) return std::nullopt;
  return port;
}

[[nodiscard]] inline std::optional<AddressPort> splitAddressPort(std::string_view spec) {
  if (spec.empty()) return std::nullopt;

  if (spec.front() == '[') {
    const auto close = spec.find(']');
    if (close == std::string_view::npos || close == 1) return std::nullopt;
    const auto inside = spec.substr(1, close - 1);
    const auto rest = spec.substr(close + 1);
    if (rest.empty()) return AddressPort{std::string(inside)};
    if (rest.front() != ':') return std::nullopt;
    const auto port = parsePort(rest.substr(1));
    if (!port) return std::nullopt;
    return AddressPort{std::string(inside), *port};
  }

  const auto colon = spec.find(':');
  // More than one colon and no brackets is a bare IPv6 literal; there is no port in it to find.
  if (colon == std::string_view::npos || spec.find(':', colon + 1) != std::string_view::npos) {
    return AddressPort{std::string(spec)};
  }
  if (colon == 0) return std::nullopt;
  const auto port = parsePort(spec.substr(colon + 1));
  if (!port) return std::nullopt;
  return AddressPort{std::string(spec.substr(0, colon)), *port};
}

[[nodiscard]] inline std::optional<std::string> envVar(const char* name) {
  // NOLINTNEXTLINE(concurrency-mt-unsafe): read once, before any test thread exists.
  const char* const value = std::getenv(name);
  if (value == nullptr || *value == '\0') return std::nullopt;
  return std::string(value);
}

// The Target `spec` names, or nullopt when it is not an address and a port.
//
// An address, not a hostname: the library builds a Target from an endpoint precisely so that
// choosing a resolver stays the caller's business, and a test harness is a caller like any other.
// Everything this suite ever talks to -- a container with a published port, an `snmpd` on a spare
// port, a switch on the bench -- is reachable by address.
[[nodiscard]] inline std::optional<Target> makeInteropTarget(std::string_view spec) {
  const auto addressPort = splitAddressPort(spec);
  if (!addressPort) return std::nullopt;

  net::ErrorCode ec;
  const auto address = net::asio::ip::make_address(addressPort->address, ec);
  if (ec) return std::nullopt;

  Target target{net::UdpEndpoint(address, addressPort->port)};
  // A container still coming up, or a switch across a WAN link, is slower than the loopback socket
  // every other test in this tree runs over. The library's defaults are for callers, not for a
  // bring-up suite.
  target.timeout = std::chrono::milliseconds(5000);
  target.retries = 2;
  return target;
}

[[nodiscard]] inline Community interopCommunity() {
  return Community(envVar("SNMPIO_INTEROP_COMMUNITY").value_or("public"));
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPTARGET_HPP
