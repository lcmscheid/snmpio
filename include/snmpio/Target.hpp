#ifndef SNMPIO_TARGET_HPP
#define SNMPIO_TARGET_HPP

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

#include <snmpio/detail/Net.hpp>

namespace snmpio {

inline constexpr std::uint16_t defaultPort = 161;

// A transport endpoint we send requests to, and how patiently we do it.
//
// CONTEXT.md is strict about this: a Target is an address and a port, not a device and not an
// Engine. It carries no identity and no credentials, which is why the same Target can be addressed
// with several different Credentials and why one Engine can sit behind several Targets.
struct Target {
  net::UdpEndpoint endpoint;
  // Per attempt, not for the operation as a whole.
  std::chrono::milliseconds timeout{2000};
  // Retransmissions after the first attempt. UDP loses datagrams; SNMP has no other recovery.
  int retries = 1;
};

// The shared string that authorizes an SNMPv2c request. A type of its own rather than a bare
// std::string so that it cannot be silently swapped with any of the other strings in a call --
// and so that stage 2's USM Credentials have an obvious sibling to sit beside.
struct Community {
  std::string value;

  Community() = default;
  explicit Community(std::string v) : value(std::move(v)) {}
};

// How a Walk traverses a Subtree.
struct WalkOptions {
  // GETBULK's max-repetitions. Zero means walk with GETNEXT instead -- one OID per round trip,
  // which is what a Target that mishandles GETBULK needs.
  std::int32_t maxRepetitions = 10;
};

}  // namespace snmpio

#endif  // SNMPIO_TARGET_HPP
