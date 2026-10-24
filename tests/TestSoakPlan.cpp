#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>

#include "SoakPlan.hpp"

// The soak's plan, on its own: the part of the soak that a seed decides, and so the part that has
// to replay exactly. The soak itself (TestSoak.cpp) runs the plan; whatever the threads then do to
// it is not the plan's to promise.

namespace snmpio::test::soak {
namespace {

using std::chrono::milliseconds;

constexpr milliseconds twoSeconds{2000};

TEST(SoakPlan, ASeedReplaysToTheSamePlan) {
  EXPECT_EQ(makePlan(12345, twoSeconds), makePlan(12345, twoSeconds));
}

TEST(SoakPlan, DifferentSeedsPlanDifferently) {
  EXPECT_NE(makePlan(1, twoSeconds).events, makePlan(2, twoSeconds).events);
}

// A replay that asks for more time sees the same opening: the plan is drawn in time order, so a
// failure found in a short run is still there when the same seed is run for longer.
TEST(SoakPlan, ALongerRunStartsWithTheShorterOnesInitiations) {
  const auto shorter = makePlan(7, milliseconds(500));
  const auto longer = makePlan(7, twoSeconds);
  ASSERT_LT(shorter.requests.size(), longer.requests.size());
  for (std::size_t i = 0; i < shorter.requests.size(); ++i)
    EXPECT_EQ(shorter.requests[i], longer.requests[i]) << "request " << i;
}

TEST(SoakPlan, EventsAreInTimeOrderAndWithinTheirThreadsAndSlots) {
  const auto plan = makePlan(99, twoSeconds);
  ASSERT_FALSE(plan.events.empty());
  for (std::size_t i = 1; i < plan.events.size(); ++i)
    EXPECT_LE(plan.events[i - 1].at, plan.events[i].at) << "event " << i;
  for (const auto& e : plan.events) {
    EXPECT_GE(e.thread, 0);
    EXPECT_LT(e.thread, initiatorThreads);
    EXPECT_GE(e.slot, 0);
    EXPECT_LT(e.slot, clientSlots);
  }
}

// The soak's executor relies on both: a cancellation waits for its initiation, and it is safe only
// because no two threads ever emit on one request's signal.
TEST(SoakPlan, EveryCancellationFollowsItsInitiationOnOneThread) {
  const auto plan = makePlan(4242, twoSeconds);
  std::set<int> initiated;
  std::map<int, int> cancellingThread;
  for (const auto& e : plan.events) {
    if (e.action == Action::Initiate) {
      EXPECT_TRUE(initiated.insert(e.request).second) << "request " << e.request << " twice";
      continue;
    }
    if (e.action != Action::CancelTerminal && e.action != Action::CancelTotal) continue;
    EXPECT_TRUE(initiated.contains(e.request))
        << "request " << e.request << " is cancelled before it is initiated";
    const auto [it, first] = cancellingThread.emplace(e.request, e.thread);
    EXPECT_EQ(it->second, e.thread) << "request " << e.request << " is cancelled from two threads";
  }
  EXPECT_EQ(initiated.size(), plan.requests.size());
}

// Two seconds is the default run, and it has to exercise the whole shape the issue names, or a
// green default run says less than it looks like it does.
TEST(SoakPlan, TwoSecondsCoverEveryOperationBehaviourAndDisruption) {
  const auto plan = makePlan(2026, twoSeconds);
  std::set<Operation> operations;
  std::set<Behaviour> behaviours;
  std::set<Action> actions;
  std::set<int> slots;
  for (const auto& r : plan.requests) {
    operations.insert(r.operation);
    behaviours.insert(r.behaviour);
    slots.insert(r.slot);
  }
  for (const auto& e : plan.events) actions.insert(e.action);

  EXPECT_EQ(operations.size(), 6U);
  EXPECT_EQ(behaviours.size(), 5U);
  EXPECT_EQ(actions.size(), 5U);
  EXPECT_EQ(slots.size(), static_cast<std::size_t>(clientSlots));
}

TEST(SoakPlan, EvenSlotsSpeakV2cAndOddOnesV3) {
  EXPECT_FALSE(isV3(0));
  EXPECT_TRUE(isV3(1));
  EXPECT_FALSE(isV3(2));
  EXPECT_TRUE(isV3(clientSlots - 1));
}

// An unparseable value fails the soak rather than falling back to the default: a typo that quietly
// ran a different seed would replay nothing, and one that quietly ran two seconds would say an hour
// passed clean.
TEST(SoakEnvironment, ParsesASeed) {
  EXPECT_EQ(parseSeed("0"), std::optional<std::uint64_t>(0));
  EXPECT_EQ(parseSeed("18446744073709551615"), std::optional<std::uint64_t>(UINT64_MAX));
  EXPECT_FALSE(parseSeed("").has_value());
  EXPECT_FALSE(parseSeed("-1").has_value());
  EXPECT_FALSE(parseSeed("12x").has_value());
  EXPECT_FALSE(parseSeed("18446744073709551616").has_value());
}

TEST(SoakEnvironment, ParsesADurationInSeconds) {
  EXPECT_EQ(parseSeconds("2"), std::optional<milliseconds>(2000));
  EXPECT_EQ(parseSeconds("0.25"), std::optional<milliseconds>(250));
  EXPECT_EQ(parseSeconds("3600"), std::optional<milliseconds>(3'600'000));
  EXPECT_FALSE(parseSeconds("").has_value());
  EXPECT_FALSE(parseSeconds("0").has_value());
  EXPECT_FALSE(parseSeconds("-2").has_value());
  EXPECT_FALSE(parseSeconds("2s").has_value());
  EXPECT_FALSE(parseSeconds("nan").has_value());
}

TEST(SoakPlan, DescribesARequestForAFailureMessage) {
  Request r;
  r.slot = 3;
  r.operation = Operation::WalkCollect;
  r.behaviour = Behaviour::Late;
  EXPECT_EQ(describe(r), "slot 3 (v3) WalkCollect, Agent answers late");
}

}  // namespace
}  // namespace snmpio::test::soak
