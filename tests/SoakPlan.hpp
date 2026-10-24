#ifndef SNMPIO_TESTS_SOAKPLAN_HPP
#define SNMPIO_TESTS_SOAKPLAN_HPP

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

// What the soak (TestSoak.cpp) will do, decided by its seed before any thread starts.
//
// Threads make a soak's interleavings unrepeatable, so the seed decides everything else: which
// Client each request goes to, what it asks, how its Agent behaves, and every disruption with the
// moment and the thread it comes from. A failing seed then replays to the same sequence of
// disruptions, and the interleavings around them get another roll.
namespace snmpio::test::soak {

// Clients, each with its own Scripted Agent, all on the one io_context. Even slots speak v2c and
// odd ones v3, so every run mixes both.
inline constexpr int clientSlots = 8;
// The threads that initiate, cancel, stop and destroy, none of them one running an io_context.
inline constexpr int initiatorThreads = 4;

[[nodiscard]] constexpr bool isV3(int slot) noexcept {
  return slot % 2 == 1;
}

enum class Operation : std::uint8_t { Get, GetNext, GetBulk, Set, Walk, WalkCollect };

// How the Agent answers. The request carries it in its OID, so the Agent reads it from the
// datagram and needs nothing shared with the test.
enum class Behaviour : std::uint8_t {
  Prompt = 1,  // answers at once
  Late,        // answers, but only after a delay within the first attempt's deadline
  Never,       // stays silent
  Twice,       // answers twice
  Garbled,     // sends a truncated copy of its answer, then the answer
};

enum class Action : std::uint8_t { Initiate, CancelTerminal, CancelTotal, Stop, Destroy };

struct Request {
  int slot = 0;
  Operation operation = Operation::Get;
  Behaviour behaviour = Behaviour::Prompt;
  friend bool operator==(const Request&, const Request&) = default;
};

struct Event {
  std::chrono::microseconds at{};  // from the start of the soak
  int thread = 0;
  Action action = Action::Initiate;
  int slot = 0;      // the Client slot an Initiate, Stop or Destroy acts on
  int request = -1;  // an index into Plan::requests, for Initiate and both cancellations
  friend bool operator==(const Event&, const Event&) = default;
};

struct Plan {
  std::uint64_t seed = 0;
  std::chrono::milliseconds duration{};
  std::vector<Request> requests;
  std::vector<Event> events;  // in time order
  friend bool operator==(const Plan&, const Plan&) = default;
};

namespace detail {

// std::mt19937_64's output is fixed by the standard, the distributions' are not: libstdc++ and
// libc++ turn the same engine into different numbers. The reductions are written out here so a
// seed means the same plan on either.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : m_engine(seed) {}
  // In [0, n). The modulo bias is below one part in 2^50 for every n used here.
  std::uint64_t below(std::uint64_t n) { return m_engine() % n; }
  int below(int n) { return static_cast<int>(below(static_cast<std::uint64_t>(n))); }
  bool chance(int percent) { return below(100) < percent; }

 private:
  std::mt19937_64 m_engine;
};

// The shape of a run, per unit of time. About 400 requests a second, 2% of events a Stopping or a
// destruction, a quarter of requests cancelled.
inline constexpr std::uint64_t meanGapMicros = 2500;
inline constexpr int clientDisruptionPercent = 2;
inline constexpr int terminalOnlyPercent = 10;
inline constexpr int totalOnlyPercent = 10;
inline constexpr int bothPercent = 5;
// Late enough to land anywhere in a request's life, a Walk's included.
inline constexpr std::uint64_t maxCancelDelayMicros = 300'000;
inline constexpr std::uint64_t earlyCancelMicros = 20'000;

inline Behaviour drawBehaviour(Rng& rng) {
  // Prompt 40, Late 20, Never 10, Twice 15, Garbled 15.
  const int roll = rng.below(100);
  if (roll < 40) return Behaviour::Prompt;
  if (roll < 60) return Behaviour::Late;
  if (roll < 70) return Behaviour::Never;
  if (roll < 85) return Behaviour::Twice;
  return Behaviour::Garbled;
}

}  // namespace detail

// Drawn in time order from one stream, so a longer run with the same seed starts as the shorter
// one did. Every draw is a named local, never an argument, whose evaluation order would be the
// compiler's to choose.
[[nodiscard]] inline Plan makePlan(std::uint64_t seed, std::chrono::milliseconds duration) {
  using std::chrono::microseconds;
  detail::Rng rng(seed);
  Plan plan;
  plan.seed = seed;
  plan.duration = duration;

  microseconds at{0};
  while (true) {
    at += microseconds(rng.below(2 * detail::meanGapMicros + 1));
    if (at >= duration) break;
    const int thread = rng.below(initiatorThreads);
    const int slot = rng.below(clientSlots);

    if (rng.chance(detail::clientDisruptionPercent)) {
      const auto action = rng.chance(50) ? Action::Stop : Action::Destroy;
      plan.events.push_back(Event{at, thread, action, slot, -1});
      continue;
    }

    const auto operation = static_cast<Operation>(rng.below(6));
    const auto behaviour = detail::drawBehaviour(rng);
    const int request = static_cast<int>(plan.requests.size());
    plan.requests.push_back(Request{slot, operation, behaviour});
    plan.events.push_back(Event{at, thread, Action::Initiate, slot, request});

    // Each request's cancellations come from one thread, which need not be the one that
    // initiated it, and strictly after the initiation.
    const int roll = rng.below(100);
    const int canceller = rng.below(initiatorThreads);
    // Half land in a request's first moments, where a prompt reply is still in flight; the rest
    // anywhere in its life, a Walk's or a silent Target's included.
    const auto firstDelay = rng.chance(50) ? rng.below(detail::earlyCancelMicros)
                                           : rng.below(detail::maxCancelDelayMicros);
    const auto first = at + microseconds(1 + firstDelay);
    const auto second = first + microseconds(1 + rng.below(detail::maxCancelDelayMicros / 3));
    const bool terminalFirst = rng.chance(50);
    if (roll < detail::terminalOnlyPercent) {
      plan.events.push_back(Event{first, canceller, Action::CancelTerminal, slot, request});
    } else if (roll < detail::terminalOnlyPercent + detail::totalOnlyPercent) {
      plan.events.push_back(Event{first, canceller, Action::CancelTotal, slot, request});
    } else if (roll <
               detail::terminalOnlyPercent + detail::totalOnlyPercent + detail::bothPercent) {
      plan.events.push_back(Event{first, canceller,
                                  terminalFirst ? Action::CancelTerminal : Action::CancelTotal,
                                  slot, request});
      plan.events.push_back(Event{second, canceller,
                                  terminalFirst ? Action::CancelTotal : Action::CancelTerminal,
                                  slot, request});
    }
  }

  // Stable, so events at the same microsecond keep the order they were drawn in.
  std::ranges::stable_sort(plan.events, {}, &Event::at);
  return plan;
}

[[nodiscard]] inline std::optional<std::uint64_t> parseSeed(std::string_view text) {
  std::uint64_t seed = 0;
  const auto* const last = text.data() + text.size();
  const auto [end, ec] = std::from_chars(text.data(), last, seed);
  if (text.empty() || ec != std::errc{} || end != last) return std::nullopt;
  return seed;
}

// Seconds, fractions allowed, at least a millisecond and at most a year.
[[nodiscard]] inline std::optional<std::chrono::milliseconds> parseSeconds(std::string_view text) {
  double seconds = 0;
  const auto* const last = text.data() + text.size();
  const auto [end, ec] = std::from_chars(text.data(), last, seconds);
  if (text.empty() || ec != std::errc{} || end != last) return std::nullopt;
  // Written so that NaN, which compares false with everything, fails it.
  if (!(seconds >= 0.001 && seconds <= 365.0 * 24 * 3600)) return std::nullopt;
  return std::chrono::milliseconds(std::llround(seconds * 1000));
}

[[nodiscard]] inline std::string_view nameOf(Operation op) {
  switch (op) {
    case Operation::Get:
      return "Get";
    case Operation::GetNext:
      return "GetNext";
    case Operation::GetBulk:
      return "GetBulk";
    case Operation::Set:
      return "Set";
    case Operation::Walk:
      return "Walk";
    case Operation::WalkCollect:
      return "WalkCollect";
  }
  return "Unknown";
}

[[nodiscard]] inline std::string_view nameOf(Behaviour behaviour) {
  switch (behaviour) {
    case Behaviour::Prompt:
      return "answers at once";
    case Behaviour::Late:
      return "answers late";
    case Behaviour::Never:
      return "never answers";
    case Behaviour::Twice:
      return "answers twice";
    case Behaviour::Garbled:
      return "answers after a garbled copy";
  }
  return "unknown";
}

[[nodiscard]] inline std::string describe(const Request& r) {
  std::ostringstream out;
  out << "slot " << r.slot << (isV3(r.slot) ? " (v3) " : " (v2c) ") << nameOf(r.operation)
      << ", Agent " << nameOf(r.behaviour);
  return out.str();
}

// One line for the log, so that two runs of a seed can be seen to have planned the same thing.
[[nodiscard]] inline std::string summary(const Plan& plan) {
  std::array<std::size_t, 5> counts{};
  for (const auto& e : plan.events) ++counts.at(static_cast<std::size_t>(e.action));
  std::ostringstream out;
  out << counts[0] << " requests, " << counts[1] << " terminal and " << counts[2]
      << " total cancellations, " << counts[3] << " stops, " << counts[4] << " destructions";
  return out.str();
}

}  // namespace snmpio::test::soak

#endif  // SNMPIO_TESTS_SOAKPLAN_HPP
