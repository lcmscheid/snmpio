#ifndef SNMPIO_TARGET_HPP
#define SNMPIO_TARGET_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include <snmpio/detail/Net.hpp>

namespace snmpio {

inline constexpr std::uint16_t defaultPort = 161;

// The largest Target::retries an operation accepts. Past it, or below zero, the operation
// completes with Errc::ArgumentOutOfRange rather than being clamped: eleven datagrams per request
// is already more than any lossy link repays, and a larger number is a bug in the caller, not a
// policy snmpio should quietly rewrite.
inline constexpr int retriesCeiling = 10;

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

// The largest max-repetitions a GETBULK, or a Walk, accepts. Past it, or below zero, the operation
// completes with Errc::ArgumentOutOfRange rather than being clamped. A thousand Varbinds already
// overflows most Agents' message size, which tooBig then walks back down (see WalkOptions).
inline constexpr std::int32_t maxRepetitionsCeiling = 1000;

// The Varbind limit asyncWalkCollect applies when WalkOptions::maxVarbinds is left unset. Finite
// because a collecting Walk buffers everything it is sent, and an Agent can send strictly
// increasing OIDs forever; large enough that no real table reaches it by accident.
inline constexpr std::size_t defaultCollectLimit = 100'000;

// How a Walk traverses a Subtree, and when it gives up on one that will not end.
//
// Not an aggregate, on purpose: a braced WalkOptions{2} naming only maxRepetitions is what most
// callers write, and as an aggregate it would trip -Wmissing-field-initializers -- under GCC and
// Clang alike, designated or not -- for every field after it. The limits are set by assignment.
struct WalkOptions {
  WalkOptions() = default;
  constexpr explicit WalkOptions(std::int32_t repetitions) noexcept : maxRepetitions(repetitions) {}

  // GETBULK's max-repetitions, at most maxRepetitionsCeiling. Zero means walk with GETNEXT instead
  // -- one OID per round trip, which is what a Target that mishandles GETBULK needs.
  std::int32_t maxRepetitions = 10;
  // The most Varbinds the Walk delivers. Unset means the operation's own default: no limit for
  // asyncWalk, whose Batch handler already decides when to stop, and defaultCollectLimit for
  // asyncWalkCollect. A Walk that reaches it without having seen the end of the Subtree ends with
  // Errc::WalkIncomplete, even if the next request would have found nothing more: a Walk that was
  // cut short must never look complete (ADR-0004). Zero is a limit like any other, not "none": the
  // Walk sends nothing and ends WalkIncomplete.
  std::optional<std::size_t> maxVarbinds;
  // How long the whole Walk may take, from its start; unset means no limit. Reaching it drops the
  // exchange in flight and ends the Walk with Errc::WalkIncomplete, keeping every Batch already
  // delivered -- including over a reason ADR-0008 would otherwise report at the exchange's own
  // deadline, such as AuthFailed: that deadline never came, and the limit the caller set did.
  // Per-attempt patience is still Target::timeout's.
  std::optional<std::chrono::milliseconds> timeLimit;
};

}  // namespace snmpio

#endif  // SNMPIO_TARGET_HPP
