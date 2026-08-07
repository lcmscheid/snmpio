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
#include <utility>

#include <snmpio/Client.hpp>
#include <snmpio/Target.hpp>
#include <snmpio/detail/Net.hpp>

// Where the interop suite's Agent is, and the one GET every half of the suite is built on.
//
// The Target comes from the environment rather than from a fixture constant because the Agent is
// not ours -- it is a container CI starts, an `snmpd` on a workstation, or a switch on the bench,
// and only whoever runs the suite knows which. With nothing set, every interop test skips: an
// unconfigured checkout must not fail its test run over a Target that was never there.
namespace snmpio::test {

inline const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};

[[nodiscard]] inline std::optional<std::string> envVar(const char* name) {
  // NOLINTNEXTLINE(concurrency-mt-unsafe): read once, before any test thread exists.
  const char* const value = std::getenv(name);
  if (value == nullptr || *value == '\0') return std::nullopt;
  return std::string(value);
}

// The port `name` carries, `fallback` when it is unset, and 0 when it is set to something that is
// not a port -- which every caller fails on rather than skipping, since a typo that quietly used
// the default would aim the suite at a port no Agent is on and blame the library for the silence.
[[nodiscard]] inline std::uint16_t envPort(const char* name, std::uint16_t fallback = defaultPort) {
  const auto text = envVar(name);
  if (!text) return fallback;
  std::uint16_t port = 0;
  const auto* const last = text->data() + text->size();
  const auto [end, ec] = std::from_chars(text->data(), last, port);
  return (ec == std::errc{} && end == last) ? port : 0;
}

// An address, not a hostname: the library builds a Target from an endpoint precisely so that
// choosing a resolver stays the caller's business, and a test harness is a caller like any other.
// Everything this suite ever talks to -- a container with a published port, an `snmpd` on a spare
// port, a switch on the bench -- is reachable by address.
[[nodiscard]] inline std::optional<Target> makeInteropTarget(std::string_view address,
                                                             std::uint16_t port) {
  net::ErrorCode ec;
  const auto parsed = net::asio::ip::make_address(std::string(address), ec);
  if (ec || port == 0) return std::nullopt;

  Target target{net::UdpEndpoint(parsed, port)};
  // A container still coming up, or a switch across a WAN link, is slower than the loopback socket
  // every other test in this tree runs over. The library's defaults are for callers, not for a
  // bring-up suite.
  target.timeout = std::chrono::milliseconds(5000);
  target.retries = 2;
  return target;
}

// Runs one GET of sysDescr.0 to completion on its own io_context and Client, and hands back what
// the completion saw. A Client per call on purpose: the caches are the Client's (ADR-0003), so a
// fresh one is the only way to ask what an Engine costs the first time.
struct GetResult {
  net::ErrorCode ec;
  Response response;
};

// `auth` is a Community or a Credentials, which are two overloads rather than one type -- so the
// half of the suite each belongs to says which, and this stays one helper.
template <typename Auth>
GetResult get(const Target& target, const Auth& auth) {
  net::IoContext io;
  Client client(io.get_executor());
  GetResult result;

  client.asyncGet(target, auth, {sysDescr}, [&](net::ErrorCode ec, Response response) {
    result.ec = ec;
    result.response = std::move(response);
    client.stop();
  });
  io.run();
  return result;
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPTARGET_HPP
