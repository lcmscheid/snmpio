#ifndef SNMPIO_TESTS_INTEROPWALK_HPP
#define SNMPIO_TESTS_INTEROPWALK_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/Oid.hpp>
#include <snmpio/Target.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/detail/Net.hpp>

#include "InteropOperations.hpp"
#include "InteropTarget.hpp"

// A Walk against a live Agent, in both traversal modes and both of ADR-0004's shapes, asserted on
// structure alone: every OID inside the Subtree, strictly increasing, a clean end, and more than
// one batch. No MIB contents are pinned. What the Agent serves under the Subtree is whatever it
// serves, and the two modes are held to each other instead -- a GETNEXT-mode and a GETBULK-mode
// Walk of one Subtree are the same successor chain asked two ways, so they list the same OIDs.
// Values are not compared: counters and sysUpTime move between the two.
namespace snmpio::test {

// The Walk's Subtree, on every Agent. Several batches long on the three CI starts: `snmpd` in a
// container has a loopback and an Ethernet interface, 22 columns each, and
// tests/interop/fault-agent-values.sh gives the Simulator fifty instances under it, since the
// image's own configuration has two. Most other Targets have ports enough too; on one with too
// few interfaces the Walks fail rather than pass on a single batch.
inline const Oid interfacesGroup{1, 3, 6, 1, 2, 1, 2};

// A Walk's mode is its Operation, and these are the two, in the order they are walked.
inline constexpr std::initializer_list<Operation> walkModes{Operation::WalkGetNext,
                                                            Operation::WalkGetBulk};

// Zero max-repetitions is GETNEXT mode, what a Target that mishandles GETBULK depends on; GETBULK
// mode is the library's default, at its default max-repetitions. Only a Walk has a mode, so any
// other Operation here is a mistake in the suite rather than a GETBULK-mode Walk.
[[nodiscard]] inline std::int32_t walkRepetitions(Operation mode) {
  if (!isWalk(mode)) throw std::invalid_argument(operationLabel(mode, "is not a Walk"));
  return mode == Operation::WalkGetNext ? 0 : WalkOptions{}.maxRepetitions;
}

enum class WalkShape : std::uint8_t { Streaming, Collecting };

// How one Walk came back: its completion, the OIDs it delivered in order, and -- for a streaming
// Walk, the only shape that shows them -- how many batches they came in.
struct WalkRun {
  net::ErrorCode ec;
  std::vector<Oid> oids;
  std::optional<std::size_t> batches;
};

// The first thing structurally wrong with a Walk of interfacesGroup, or empty when there is
// nothing. `repetitions` is the max-repetitions it was sent with, zero in GETNEXT mode.
[[nodiscard]] inline std::string walkProblem(const WalkRun& run, std::int32_t repetitions) {
  if (run.ec) return errorText(run.ec);
  if (run.oids.empty()) return "the Walk of " + interfacesGroup.toString() + " came back empty";
  const Oid* previous = &interfacesGroup;
  for (std::size_t i = 0; i < run.oids.size(); ++i) {
    const auto& oid = run.oids[i];
    const std::string where = "OID " + std::to_string(i) + ": ";
    if (!interfacesGroup.isPrefixOf(oid)) {
      return where + oid.toString() + " is outside " + interfacesGroup.toString();
    }
    if (!(*previous < oid))
      return where + oid.toString() + " does not follow " + previous->toString();
    previous = &oid;
  }
  // The one place batching is the behaviour under test: a Walk that ended in one round trip never
  // continued from one Response to the next request. A streaming Walk shows its batches; a
  // collecting one does not, but more OIDs than one batch carries needed more than one.
  if (run.batches) {
    if (*run.batches > 1) return {};
    return "the Walk came in " + std::to_string(*run.batches) +
           " batch, so it never continued from one Response to the next request";
  }
  const auto perBatch = static_cast<std::size_t>(std::max(repetitions, 1));
  if (run.oids.size() > perBatch) return {};
  return "the Walk collected " + std::to_string(run.oids.size()) + " OIDs, which one batch of " +
         std::to_string(perBatch) + " carries, so it may never have needed a second request";
}

// Where `other` stops listing the OIDs `reference` lists, or empty when the two are the same list.
[[nodiscard]] inline std::string sameOidsProblem(const std::vector<Oid>& reference,
                                                 const std::vector<Oid>& other) {
  const auto [ref, oth] = std::ranges::mismatch(reference, other);
  if (ref == reference.end() && oth == other.end()) return {};
  const auto position = static_cast<std::size_t>(ref - reference.begin());
  const auto said = [](const std::vector<Oid>& oids, std::vector<Oid>::const_iterator it) {
    return it == oids.end() ? std::string("the end of the Walk") : it->toString();
  };
  return "OID " + std::to_string(position) + " is " + said(other, oth) + " but was " +
         said(reference, ref);
}

// One Walk of interfacesGroup on a Client of its own, run to completion. `auth` is a Community or
// a Credentials.
template <typename Auth>
WalkRun walk(const Target& target, const Auth& auth, Operation mode, WalkShape shape) {
  net::IoContext io;
  Client client(io.get_executor());
  WalkOptions options;
  options.maxRepetitions = walkRepetitions(mode);
  WalkRun run;

  if (shape == WalkShape::Streaming) {
    run.batches = 0;
    client.asyncWalk(
        target, auth, interfacesGroup, options,
        [&](std::span<const Varbind> batch) {
          ++*run.batches;
          for (const auto& varbind : batch) run.oids.push_back(varbind.name);
          return true;
        },
        [&](net::ErrorCode ec) {
          run.ec = ec;
          client.stop();
        });
  } else {
    client.asyncWalkCollect(target, auth, interfacesGroup, options,
                            [&](net::ErrorCode ec, std::vector<Varbind> varbinds) {
                              run.ec = ec;
                              for (auto& varbind : varbinds)
                                run.oids.push_back(std::move(varbind.name));
                              client.stop();
                            });
  }
  io.run();
  return run;
}

// One of the four Walks walkBothModesAndRecord runs, with what it was asked to do.
struct Walked {
  Operation mode;
  WalkShape shape;
  WalkRun run;
};

[[nodiscard]] inline std::string shapeName(WalkShape shape) {
  return shape == WalkShape::Streaming ? "streaming" : "collecting";
}

// A Walk as a failure message names it: `the GETBULK-mode collecting Walk`.
[[nodiscard]] inline std::string walkName(const Walked& walked) {
  return "the " + pduName(walked.mode) + "-mode " + shapeName(walked.shape) + " Walk";
}

[[nodiscard]] inline bool isSound(const Walked& walked) {
  return walkProblem(walked.run, walkRepetitions(walked.mode)).empty();
}

// The first thing wrong with one Walk: its own structure, then its OIDs against `reference`'s.
[[nodiscard]] inline std::string walkedProblem(const Walked& walked, const Walked& reference) {
  if (auto problem = walkProblem(walked.run, walkRepetitions(walked.mode)); !problem.empty()) {
    return problem;
  }
  if (auto problem = sameOidsProblem(reference.run.oids, walked.run.oids); !problem.empty()) {
    return "against " + walkName(reference) + ": " + problem;
  }
  return {};
}

// What one mode's summary row says: the first thing wrong with either of its two Walks, and what
// an ok row was held to when that was not the first Walk.
struct ModeOutcome {
  Operation mode;
  std::string problem;
  std::string note;
};

// Four Walks in walkBothModesAndRecord's order, judged per mode against one OID list: the first
// sound Walk's. That is the GETNEXT-mode streaming Walk's unless that one failed, when the next
// sound one stands in so the rest are still compared with something. The reference is compared
// with itself too, which is harmless. Only a sound Walk reaches the comparison, so when none is
// sound, what stands in is never read.
[[nodiscard]] inline std::vector<ModeOutcome> modeOutcomes(const std::vector<Walked>& walks) {
  const auto sound = std::ranges::find_if(walks, isSound);
  const Walked& reference = sound == walks.end() ? walks.front() : *sound;
  const bool standIn = sound != walks.begin() && sound != walks.end();
  const std::string note =
      standIn ? "held to " + walkName(*sound) + ", since " + walkName(walks.front()) + " failed"
              : std::string();
  std::vector<ModeOutcome> outcomes;
  for (const auto mode : walkModes) {
    std::string problem;
    for (const auto& walked : walks) {
      if (walked.mode != mode) continue;
      problem = walkedProblem(walked, reference);
      if (!problem.empty()) {
        problem = shapeName(walked.shape) + ": " + problem;
        break;
      }
    }
    outcomes.push_back({mode, std::move(problem), note});
  }
  return outcomes;
}

// Four Walks of interfacesGroup -- GETNEXT mode and GETBULK mode, each streaming and collecting --
// recorded as `GETNEXT Walk <label>` and `GETBULK Walk <label>`. Run together because they are
// held to one OID list.
template <typename Auth>
void walkBothModesAndRecord(const Target& target, const Auth& auth, const std::string& label) {
  std::vector<Walked> walks;
  for (const auto mode : walkModes) {
    for (const auto shape : {WalkShape::Streaming, WalkShape::Collecting}) {
      walks.push_back({mode, shape, walk(target, auth, mode, shape)});
    }
  }
  for (const auto& outcome : modeOutcomes(walks)) {
    recordOutcome(operationLabel(outcome.mode, label), outcome.problem, outcome.note);
  }
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPWALK_HPP
