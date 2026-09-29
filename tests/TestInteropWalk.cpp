#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <vector>

#include <snmpio/Error.hpp>
#include <snmpio/Oid.hpp>
#include <snmpio/Target.hpp>

#include "InteropWalk.hpp"

// The checks the interop suite holds a live Walk to, held here to Walks built by hand -- so that a
// check which passes a wrong Walk is caught without an Agent that produces one.
namespace snmpio {
namespace {

using test::interfacesGroup;
using test::sameOidsProblem;
using test::walkProblem;
using test::WalkRun;

constexpr std::int32_t getBulkMode = WalkOptions{}.maxRepetitions;
constexpr std::int32_t getNextMode = 0;

// ifTable's `column` for interface `index`: 1.3.6.1.2.1.2.2.1.<column>.<index>.
Oid ifEntry(std::uint32_t column, std::uint32_t index) {
  return Oid{1, 3, 6, 1, 2, 1, 2, 2, 1, column, index};
}

// ifTable's first `rows` instances in MIB order: column 1 for every interface, then column 2.
std::vector<Oid> ifRows(std::uint32_t rows, std::uint32_t interfaces = 5) {
  std::vector<Oid> oids;
  oids.reserve(rows);
  for (std::uint32_t n = 0; n < rows; ++n) {
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
  EXPECT_EQ(walkProblem(streamed(ifRows(25), 3), getBulkMode), "");
}

// Batching is the behaviour under test here: a Walk that ended in one round trip never continued
// from one Response to the next request, which is the whole reason the Subtree is long.
TEST(InteropWalk, RejectsAStreamingWalkOfOneBatch) {
  EXPECT_NE(walkProblem(streamed(ifRows(25), 1), getBulkMode), "");
}

// A collecting Walk hands back no batches to count, but more rows than one batch can carry needed
// more than one of them.
TEST(InteropWalk, HoldsACollectingWalkToMoreRowsThanOneBatchCarries) {
  EXPECT_EQ(walkProblem(collected(ifRows(11)), getBulkMode), "");
  EXPECT_NE(walkProblem(collected(ifRows(10)), getBulkMode), "");
  EXPECT_EQ(walkProblem(collected(ifRows(2)), getNextMode), "");
  EXPECT_NE(walkProblem(collected(ifRows(1)), getNextMode), "");
}

TEST(InteropWalk, RejectsAnEmptyWalk) {
  EXPECT_NE(walkProblem(streamed({}, 0), getNextMode), "");
}

TEST(InteropWalk, RejectsAWalkThatFailed) {
  WalkRun run = streamed(ifRows(25), 3);
  run.ec = make_error_code(Errc::Timeout);
  EXPECT_NE(walkProblem(run, getBulkMode), "");
}

TEST(InteropWalk, RejectsAnOidOutsideTheSubtree) {
  auto oids = ifRows(25);
  oids.push_back(Oid{1, 3, 6, 1, 2, 1, 3, 1});
  EXPECT_NE(walkProblem(streamed(oids, 3), getBulkMode), "");
  EXPECT_FALSE(interfacesGroup.isPrefixOf(oids.back()));
}

TEST(InteropWalk, RejectsOidsThatDoNotIncrease) {
  auto repeated = ifRows(25);
  repeated.push_back(repeated.back());
  EXPECT_NE(walkProblem(streamed(repeated, 3), getBulkMode), "");

  auto backwards = ifRows(25);
  std::swap(backwards[3], backwards[4]);
  EXPECT_NE(walkProblem(streamed(backwards, 3), getBulkMode), "");
}

TEST(InteropWalk, ComparesTwoWalksOidForOid) {
  EXPECT_EQ(sameOidsProblem(ifRows(25), ifRows(25)), "");
  EXPECT_NE(sameOidsProblem(ifRows(25), ifRows(24)), "");
  EXPECT_NE(sameOidsProblem(ifRows(24), ifRows(25)), "");

  auto other = ifRows(25);
  other[12] = ifEntry(9, 9);
  EXPECT_NE(sameOidsProblem(ifRows(25), other), "");
}

}  // namespace
}  // namespace snmpio
