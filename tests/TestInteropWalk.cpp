#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
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
using test::Operation;
using test::sameOidsProblem;
using test::walkProblem;
using test::walkRepetitions;
using test::WalkRun;

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

}  // namespace
}  // namespace snmpio
