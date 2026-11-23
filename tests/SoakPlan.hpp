#ifndef SNMPIO_TESTS_SOAKPLAN_HPP
#define SNMPIO_TESTS_SOAKPLAN_HPP

#include <algorithm>
#include <array>
#include <cassert>
#include <charconv>
#include <chrono>
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
// Client each request goes to -- the slot and the generation of it -- what it asks, how its Agent
// behaves, and every disruption with the Client it reaches, the moment it is due and the thread it
// comes from. A failing seed then replays to the same sequence of disruptions against the same
// Clients, and only the interleavings around them get another roll.
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
inline constexpr int operationCount = 6;
static_assert(static_cast<int>(Operation::WalkCollect) + 1 == operationCount);

// How the Agent answers. The request carries it in its OID, so the Agent reads it from the
// datagram and needs nothing shared with the test. From 1, so that it can name a MIB row's parent
// without a zero sub-identifier.
//
// Malformed is the issue's "attacking one Client beside another" (#32, and C3): what a broken Agent
// can send its own Client, beside Clients whose Agents behave.
enum class Behaviour : std::uint8_t {
  Prompt = 1,  // answers at once
  Late,        // answers, but only after a delay within the first attempt's deadline
  Never,       // stays silent
  Twice,       // answers twice
  Malformed,   // sends a datagram claiming four gigabytes and a truncated copy, then the answer
};
inline constexpr int behaviourCount = 5;
static_assert(static_cast<int>(Behaviour::Malformed) == behaviourCount);

// How often each Behaviour is drawn, in percent.
inline constexpr std::array<std::pair<Behaviour, int>, behaviourCount> behaviourWeights{{
    {Behaviour::Prompt, 40},
    {Behaviour::Late, 20},
    {Behaviour::Never, 10},
    {Behaviour::Twice, 15},
    {Behaviour::Malformed, 15},
}};
static_assert(
    [] {
      int total = 0;
      for (const auto& [behaviour, percent] : behaviourWeights) total += percent;
      return total;
    }() == 100,
    "the weights are percentages");

enum class Action : std::uint8_t { Initiate, CancelTerminal, CancelTotal, Stop, Destroy };
inline constexpr int actionCount = 5;
static_assert(static_cast<int>(Action::Destroy) + 1 == actionCount);

// One Client: a slot, and which of the Clients that have served it. A Stop or a Destroy ends the
// generation it reaches, and the slot's next request starts the next one.
struct ClientRef {
  int slot = 0;
  int generation = 0;
  friend bool operator==(const ClientRef&, const ClientRef&) = default;
};

struct Request {
  ClientRef client;
  Operation operation = Operation::Get;
  Behaviour behaviour = Behaviour::Prompt;
  friend bool operator==(const Request&, const Request&) = default;
};

struct Event {
  std::chrono::microseconds at{};  // from the start of the soak
  int thread = 0;
  Action action = Action::Initiate;
  ClientRef client;            // the Client it reaches; for a request's events, the request's own
  std::optional<int> request;  // an index into Plan::requests, for Initiate and both cancellations
  friend bool operator==(const Event&, const Event&) = default;
};

struct Plan {
  std::uint64_t seed = 0;
  std::chrono::milliseconds duration{};
  std::vector<Request> requests;
  std::vector<Event> events;  // in time order
  // For each slot, how many requests each of its generations is planned to take: one generation
  // more than the slot's Stops and Destroys, the last of which nothing ends.
  std::array<std::vector<int>, clientSlots> requestsPerGeneration;
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
  int roll = rng.below(100);
  for (const auto& [behaviour, percent] : behaviourWeights) {
    if (roll < percent) return behaviour;
    roll -= percent;
  }
  return behaviourWeights.back().first;  // unreachable while the weights sum to 100
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

  // Every Initiate, Stop and Destroy is drawn at a later moment than the last, so counting
  // generations as they are drawn counts them in time order.
  for (auto& generations : plan.requestsPerGeneration) generations.assign(1, 0);
  microseconds at{0};
  while (true) {
    at += microseconds(rng.below(2 * detail::meanGapMicros + 1));
    if (at >= duration) break;
    const int thread = rng.below(initiatorThreads);
    const int slot = rng.below(clientSlots);
    auto& generations = plan.requestsPerGeneration.at(static_cast<std::size_t>(slot));
    const ClientRef client{slot, static_cast<int>(generations.size()) - 1};

    if (rng.chance(detail::clientDisruptionPercent)) {
      const auto action = rng.chance(50) ? Action::Stop : Action::Destroy;
      plan.events.push_back(Event{at, thread, action, client, std::nullopt});
      generations.push_back(0);
      continue;
    }
    ++generations.back();

    const auto operation = static_cast<Operation>(rng.below(operationCount));
    const auto behaviour = detail::drawBehaviour(rng);
    const int request = static_cast<int>(plan.requests.size());
    plan.requests.push_back(Request{client, operation, behaviour});
    plan.events.push_back(Event{at, thread, Action::Initiate, client, request});

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
      plan.events.push_back(Event{first, canceller, Action::CancelTerminal, client, request});
    } else if (roll < detail::terminalOnlyPercent + detail::totalOnlyPercent) {
      plan.events.push_back(Event{first, canceller, Action::CancelTotal, client, request});
    } else if (roll <
               detail::terminalOnlyPercent + detail::totalOnlyPercent + detail::bothPercent) {
      plan.events.push_back(Event{first, canceller,
                                  terminalFirst ? Action::CancelTerminal : Action::CancelTotal,
                                  client, request});
      plan.events.push_back(Event{second, canceller,
                                  terminalFirst ? Action::CancelTotal : Action::CancelTerminal,
                                  client, request});
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

// A duration's text is decimal seconds with at most this many fraction digits kept, for
// parseSeconds and formatSeconds alike.
inline constexpr std::size_t millisDigits = 3;
inline constexpr std::uint64_t millisPerSecond = 1000;

// Seconds, fractions allowed, at least a millisecond and at most a year: digits, then optionally a
// point and more digits. Decimal only, the form formatSeconds prints, so no sign and no exponent.
// Read as two integers, because integer from_chars is all every standard library here has --
// libc++ before 20 has no floating-point overload (#44).
[[nodiscard]] inline std::optional<std::chrono::milliseconds> parseSeconds(std::string_view text) {
  constexpr std::uint64_t maxSeconds = 365ULL * 24 * 3600;
  const auto isDigits = [](std::string_view s) {
    return std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; });
  };
  const auto point = text.find('.');
  const auto whole = text.substr(0, point);
  const auto fraction =
      point == std::string_view::npos ? std::string_view{} : text.substr(point + 1);
  if (whole.empty() && fraction.empty()) return std::nullopt;
  if (!isDigits(whole) || !isDigits(fraction)) return std::nullopt;

  std::uint64_t seconds = 0;
  if (!whole.empty()) {
    const auto [end, ec] = std::from_chars(whole.data(), whole.data() + whole.size(), seconds);
    if (ec != std::errc{} || seconds > maxSeconds) return std::nullopt;
  }
  // The first three fraction digits are milliseconds, padded with zeros; the fourth rounds them.
  std::uint64_t millis = 0;
  for (std::size_t i = 0; i < millisDigits; ++i) {
    millis =
        millis * 10 + (i < fraction.size() ? static_cast<std::uint64_t>(fraction[i] - '0') : 0);
  }
  const auto truncatedMillis = (seconds * millisPerSecond) + millis;
  const bool roundUp = fraction.size() > millisDigits && fraction[millisDigits] >= '5';
  const auto rounded = truncatedMillis + (roundUp ? 1 : 0);
  if (truncatedMillis < 1 || rounded > maxSeconds * millisPerSecond) return std::nullopt;
  return std::chrono::milliseconds(static_cast<std::chrono::milliseconds::rep>(rounded));
}

// parseSeconds' inverse, for the replay line: whole seconds, then the milliseconds after a point
// with their trailing zeros dropped. Integers throughout, so that no duration parseSeconds accepts
// prints in a form it refuses -- a double streamed at its default precision writes 1e+06. It takes
// what parseSeconds returns, a positive duration; zero would print as "0", which is refused.
[[nodiscard]] inline std::string formatSeconds(std::chrono::milliseconds duration) {
  assert(duration.count() > 0);
  const auto whole = std::chrono::duration_cast<std::chrono::seconds>(duration);
  std::string text = std::to_string(whole.count());
  const auto millis = (duration - whole).count();
  if (millis == 0) return text;
  std::string fraction = std::to_string(millis);
  fraction.insert(0, millisDigits - fraction.size(), '0');
  while (fraction.back() == '0') fraction.pop_back();
  return text + '.' + fraction;
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
    case Behaviour::Malformed:
      return "answers after malformed datagrams";
  }
  return "unknown";
}

[[nodiscard]] inline std::string describe(const Request& r) {
  std::ostringstream out;
  out << "slot " << r.client.slot << (isV3(r.client.slot) ? " (v3)" : " (v2c)") << ", generation "
      << r.client.generation << ": " << nameOf(r.operation) << ", Agent " << nameOf(r.behaviour);
  return out.str();
}

// One line for the log, so that two runs of a seed can be seen to have planned the same thing.
[[nodiscard]] inline std::string summary(const Plan& plan) {
  std::array<std::size_t, actionCount> counts{};
  for (const auto& e : plan.events) ++counts.at(static_cast<std::size_t>(e.action));
  const auto count = [&counts](Action a) { return counts.at(static_cast<std::size_t>(a)); };
  std::ostringstream out;
  out << count(Action::Initiate) << " requests, " << count(Action::CancelTerminal)
      << " terminal and " << count(Action::CancelTotal) << " total cancellations, "
      << count(Action::Stop) << " stops, " << count(Action::Destroy) << " destructions";
  return out.str();
}

}  // namespace snmpio::test::soak

#endif  // SNMPIO_TESTS_SOAKPLAN_HPP
