#ifndef SNMPIO_TESTS_INTEROPWALK_HPP
#define SNMPIO_TESTS_INTEROPWALK_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
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

// The Walk's Subtree, on every Agent. Several batches long anywhere: `snmpd` in a container has a
// loopback and an Ethernet interface, 22 columns each; a switch on the bench has dozens of ports;
// and tests/interop/fault-agent-values.sh gives the Simulator fifty rows under it, since the
// image's own configuration has two.
inline const Oid interfacesGroup{1, 3, 6, 1, 2, 1, 2};

// What a Walk is asked to do. Zero max-repetitions is GETNEXT mode, what a Target that mishandles
// GETBULK depends on; GETBULK mode is the library's default, at its default max-repetitions.
enum class WalkMode : std::uint8_t { GetNext, GetBulk };
enum class WalkShape : std::uint8_t { Streaming, Collecting };

[[nodiscard]] inline std::int32_t maxRepetitions(WalkMode mode) {
  return mode == WalkMode::GetNext ? 0 : WalkOptions{}.maxRepetitions;
}

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
  if (run.ec) return std::string(run.ec.category().name()) + ": " + run.ec.message();
  if (run.oids.empty()) return "the Walk of " + interfacesGroup.toString() + " came back empty";
  const Oid* previous = &interfacesGroup;
  for (std::size_t i = 0; i < run.oids.size(); ++i) {
    const auto& oid = run.oids[i];
    const std::string where = "row " + std::to_string(i) + ": ";
    if (!interfacesGroup.isPrefixOf(oid)) {
      return where + oid.toString() + " is outside " + interfacesGroup.toString();
    }
    if (!(*previous < oid))
      return where + oid.toString() + " does not follow " + previous->toString();
    previous = &oid;
  }
  // The one place batching is the behaviour under test: a Walk that ended in one round trip never
  // continued from one Response to the next request. A streaming Walk shows its batches; a
  // collecting one does not, but more rows than one batch carries needed more than one.
  if (run.batches) {
    if (*run.batches > 1) return {};
    return "the Walk came in " + std::to_string(*run.batches) +
           " batch, so it never continued from one Response to the next request";
  }
  const auto perBatch = static_cast<std::size_t>(std::max(repetitions, 1));
  if (run.oids.size() > perBatch) return {};
  return "the Walk collected " + std::to_string(run.oids.size()) + " rows, which one batch of " +
         std::to_string(perBatch) + " carries, so it may never have needed a second request";
}

// Where `other` stops listing the OIDs `reference` lists, or empty when the two are the same list.
[[nodiscard]] inline std::string sameOidsProblem(const std::vector<Oid>& reference,
                                                 const std::vector<Oid>& other) {
  const auto [ref, oth] = std::ranges::mismatch(reference, other);
  if (ref == reference.end() && oth == other.end()) return {};
  const auto row = static_cast<std::size_t>(ref - reference.begin());
  const auto said = [](const std::vector<Oid>& oids, std::vector<Oid>::const_iterator it) {
    return it == oids.end() ? std::string("the end of the Walk") : it->toString();
  };
  return "row " + std::to_string(row) + " is " + said(other, oth) + " but was " +
         said(reference, ref);
}

// One Walk of interfacesGroup on a Client of its own, run to completion. `auth` is a Community or
// a Credentials.
template <typename Auth>
WalkRun walk(const Target& target, const Auth& auth, WalkMode mode, WalkShape shape) {
  net::IoContext io;
  Client client(io.get_executor());
  WalkOptions options;
  options.maxRepetitions = maxRepetitions(mode);
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
                            [&](net::ErrorCode ec, std::vector<Varbind> rows) {
                              run.ec = ec;
                              for (auto& varbind : rows)
                                run.oids.push_back(std::move(varbind.name));
                              client.stop();
                            });
  }
  io.run();
  return run;
}

// Both shapes of one mode's Walk: the first thing wrong with either, or with either's OIDs against
// `reference` -- the GETNEXT-mode streaming Walk, which every other Walk of the Subtree must list
// OID for OID -- when there is one to compare with.
[[nodiscard]] inline std::string walkModeProblem(const WalkRun& streaming,
                                                 const WalkRun& collecting, WalkMode mode,
                                                 const std::vector<Oid>* reference) {
  const auto repetitions = maxRepetitions(mode);
  for (const auto& [run, shape] :
       {std::pair{&streaming, "streaming"}, {&collecting, "collecting"}}) {
    if (auto problem = walkProblem(*run, repetitions); !problem.empty()) {
      return std::string(shape) + ": " + problem;
    }
    if (reference == nullptr) continue;
    if (auto problem = sameOidsProblem(*reference, run->oids); !problem.empty()) {
      return std::string(shape) + " against the GETNEXT-mode Walk: " + problem;
    }
  }
  return {};
}

// Four Walks of interfacesGroup -- GETNEXT mode and GETBULK mode, each streaming and collecting --
// recorded as `GETNEXT Walk <label>` and `GETBULK Walk <label>`. Run together because the
// GETNEXT-mode streaming Walk is what the other three are compared to.
template <typename Auth>
void walkBothModesAndRecord(const Target& target, const Auth& auth, const std::string& label) {
  const auto nextStreaming = walk(target, auth, WalkMode::GetNext, WalkShape::Streaming);
  const auto nextCollecting = walk(target, auth, WalkMode::GetNext, WalkShape::Collecting);
  const auto bulkStreaming = walk(target, auth, WalkMode::GetBulk, WalkShape::Streaming);
  const auto bulkCollecting = walk(target, auth, WalkMode::GetBulk, WalkShape::Collecting);
  // A GETNEXT-mode Walk that failed is no list to hold the others to; its own row fails, and the
  // GETBULK row says what it was not compared with rather than blaming GETBULK for the difference.
  const bool comparable = walkProblem(nextStreaming, maxRepetitions(WalkMode::GetNext)).empty();
  const auto* const reference = comparable ? &nextStreaming.oids : nullptr;
  recordOutcome(operationLabel(Operation::WalkGetNext, label),
                walkModeProblem(nextStreaming, nextCollecting, WalkMode::GetNext, reference), {});
  recordOutcome(operationLabel(Operation::WalkGetBulk, label),
                walkModeProblem(bulkStreaming, bulkCollecting, WalkMode::GetBulk, reference),
                comparable ? "" : "not compared with the GETNEXT-mode Walk, which failed");
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPWALK_HPP
