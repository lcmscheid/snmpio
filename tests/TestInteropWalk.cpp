#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <snmpio/Error.hpp>
#include <snmpio/Oid.hpp>

#include "InteropOperations.hpp"
#include "InteropWalk.hpp"

// The checks the interop suite holds a live Walk to, held here to Walks built by hand -- so that a
// check which passes a wrong Walk is caught without an Agent that produces one.
namespace snmpio {
namespace {

using test::interfacesGroup;
using test::modeOutcomes;
using test::Operation;
using test::sameOidsProblem;
using test::Walked;
using test::walkProblem;
using test::walkRepetitions;
using test::WalkRun;
using test::WalkShape;

// The max-repetitions each mode's Walk is sent with.
const std::int32_t bulkModeRepetitions = walkRepetitions(Operation::WalkGetBulk);
const std::int32_t nextModeRepetitions = walkRepetitions(Operation::WalkGetNext);

// ifTable's `column` for interface `index`: 1.3.6.1.2.1.2.2.1.<column>.<index>.
Oid ifEntry(std::uint32_t column, std::uint32_t index) {
  return Oid{1, 3, 6, 1, 2, 1, 2, 2, 1, column, index};
}

// ifTable's first `count` instances in MIB order over five interfaces: column 1 for every
// interface, then column 2.
std::vector<Oid> ifOids(std::uint32_t count) {
  constexpr std::uint32_t interfaces = 5;
  std::vector<Oid> oids;
  oids.reserve(count);
  for (std::uint32_t n = 0; n < count; ++n) {
    oids.push_back(ifEntry((n / interfaces) + 1, (n % interfaces) + 1));
  }
  return oids;
}

WalkRun streamed(std::vector<Oid> oids, std::size_t batches) {
  return WalkRun{{}, std::move(oids), batches};
}

WalkRun collected(std::vector<Oid> oids) {
  return WalkRun{{}, std::move(oids), std::nullopt};
}

TEST(InteropWalk, AcceptsAStreamingWalkOfSeveralBatches) {
  EXPECT_EQ(walkProblem(streamed(ifOids(25), 3), bulkModeRepetitions), "");
}

// Batching is the behaviour under test here: a Walk that ended in one round trip never continued
// from one Response to the next request, which is the whole reason the Subtree is long.
TEST(InteropWalk, RejectsAStreamingWalkOfOneBatch) {
  EXPECT_NE(walkProblem(streamed(ifOids(25), 1), bulkModeRepetitions), "");
}

// A collecting Walk hands back no batches to count, but more OIDs than one batch can carry needed
// more than one of them.
TEST(InteropWalk, HoldsACollectingWalkToMoreOidsThanOneBatchCarries) {
  EXPECT_EQ(walkProblem(collected(ifOids(11)), bulkModeRepetitions), "");
  EXPECT_NE(walkProblem(collected(ifOids(10)), bulkModeRepetitions), "");
  EXPECT_EQ(walkProblem(collected(ifOids(2)), nextModeRepetitions), "");
  EXPECT_NE(walkProblem(collected(ifOids(1)), nextModeRepetitions), "");
}

TEST(InteropWalk, RejectsAnEmptyWalk) {
  EXPECT_NE(walkProblem(streamed({}, 0), nextModeRepetitions), "");
}

TEST(InteropWalk, RejectsAWalkThatFailed) {
  WalkRun run = streamed(ifOids(25), 3);
  run.ec = make_error_code(Errc::Timeout);
  EXPECT_NE(walkProblem(run, bulkModeRepetitions), "");
}

TEST(InteropWalk, RejectsAnOidOutsideTheSubtree) {
  auto oids = ifOids(25);
  oids.push_back(Oid{1, 3, 6, 1, 2, 1, 3, 1});
  EXPECT_NE(walkProblem(streamed(oids, 3), bulkModeRepetitions), "");
  EXPECT_FALSE(interfacesGroup.isPrefixOf(oids.back()));
}

TEST(InteropWalk, RejectsOidsThatDoNotIncrease) {
  auto repeated = ifOids(25);
  repeated.push_back(repeated.back());
  EXPECT_NE(walkProblem(streamed(repeated, 3), bulkModeRepetitions), "");

  auto backwards = ifOids(25);
  std::swap(backwards[3], backwards[4]);
  EXPECT_NE(walkProblem(streamed(backwards, 3), bulkModeRepetitions), "");
}

TEST(InteropWalk, ComparesTwoWalksOidForOid) {
  EXPECT_EQ(sameOidsProblem(ifOids(25), ifOids(25)), "");
  EXPECT_NE(sameOidsProblem(ifOids(25), ifOids(24)), "");
  EXPECT_NE(sameOidsProblem(ifOids(24), ifOids(25)), "");

  auto other = ifOids(25);
  other[12] = ifEntry(9, 9);
  EXPECT_NE(sameOidsProblem(ifOids(25), other), "");
}

// Only a Walk has a mode. Anything else asked for one is a mistake in the suite, not a GETBULK-mode
// Walk.
TEST(InteropWalk, GivesMaxRepetitionsOnlyToAWalk) {
  EXPECT_EQ(nextModeRepetitions, 0);
  EXPECT_GT(bulkModeRepetitions, 0);
  EXPECT_THROW((void)walkRepetitions(Operation::GetBulk), std::invalid_argument);
  EXPECT_THROW((void)walkRepetitions(Operation::GetNext), std::invalid_argument);
  EXPECT_THROW((void)walkRepetitions(Operation::Get), std::invalid_argument);
}

// The four Walks walkBothModesAndRecord runs, in its order, each sound and listing the same OIDs.
std::vector<Walked> fourSoundWalks() {
  return {
      {Operation::WalkGetNext, WalkShape::Streaming, streamed(ifOids(25), 25)},
      {Operation::WalkGetNext, WalkShape::Collecting, collected(ifOids(25))},
      {Operation::WalkGetBulk, WalkShape::Streaming, streamed(ifOids(25), 3)},
      {Operation::WalkGetBulk, WalkShape::Collecting, collected(ifOids(25))},
  };
}

void timeOut(Walked& walked) {
  walked.run.ec = make_error_code(Errc::Timeout);
}

bool mentions(const std::string& text, const std::string& part) {
  return text.find(part) != std::string::npos;
}

TEST(InteropWalk, PassesFourWalksThatListTheSameOids) {
  const auto outcomes = modeOutcomes(fourSoundWalks());
  ASSERT_EQ(outcomes.size(), 2U);
  EXPECT_EQ(outcomes[0].mode, Operation::WalkGetNext);
  EXPECT_EQ(outcomes[1].mode, Operation::WalkGetBulk);
  for (const auto& outcome : outcomes) {
    EXPECT_EQ(outcome.problem, "");
    EXPECT_EQ(outcome.note, "");
  }
}

TEST(InteropWalk, HoldsEveryWalkToTheGetNextModeStreamingOne) {
  auto walks = fourSoundWalks();
  walks[3].run.oids.pop_back();
  const auto outcomes = modeOutcomes(walks);
  EXPECT_EQ(outcomes[0].problem, "");
  EXPECT_TRUE(mentions(outcomes[1].problem, "collecting"));
  EXPECT_TRUE(mentions(outcomes[1].problem, "against the GETNEXT-mode streaming Walk"));
}

// The fallback: a failed first Walk fails its own row, and the next sound one stands in, so the
// other mode is still compared with something -- and its ok row says what with.
TEST(InteropWalk, HoldsTheRestToTheNextSoundWalkWhenTheFirstFails) {
  auto walks = fourSoundWalks();
  timeOut(walks[0]);
  const auto outcomes = modeOutcomes(walks);
  EXPECT_TRUE(mentions(outcomes[0].problem, "streaming"));
  EXPECT_EQ(outcomes[1].problem, "");
  EXPECT_EQ(
      outcomes[1].note,
      "held to the GETNEXT-mode collecting Walk, since the GETNEXT-mode streaming Walk failed");
}

TEST(InteropWalk, FailsAWalkThatDisagreesWithTheStandIn) {
  auto walks = fourSoundWalks();
  timeOut(walks[0]);
  walks[2].run.oids.pop_back();
  const auto outcomes = modeOutcomes(walks);
  EXPECT_TRUE(mentions(outcomes[1].problem, "against the GETNEXT-mode collecting Walk"));
}

// With both GETNEXT-mode Walks failed, the GETBULK-mode ones are still held to each other.
TEST(InteropWalk, HoldsTheGetBulkModeWalksToEachOtherWhenNeitherGetNextOneIsSound) {
  auto walks = fourSoundWalks();
  timeOut(walks[0]);
  timeOut(walks[1]);
  walks[3].run.oids.pop_back();
  const auto outcomes = modeOutcomes(walks);
  EXPECT_NE(outcomes[0].problem, "");
  EXPECT_TRUE(mentions(outcomes[1].problem, "against the GETBULK-mode streaming Walk"));
}

TEST(InteropWalk, FailsBothRowsWhenNoWalkIsSound) {
  auto walks = fourSoundWalks();
  for (auto& walked : walks) timeOut(walked);
  const auto outcomes = modeOutcomes(walks);
  EXPECT_NE(outcomes[0].problem, "");
  EXPECT_NE(outcomes[1].problem, "");
}

}  // namespace
}  // namespace snmpio
