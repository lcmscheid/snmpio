#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

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
    EXPECT_GE(e.client.slot, 0);
    EXPECT_LT(e.client.slot, clientSlots);
  }
}

// The soak's executor relies on both: a cancellation waits for its initiation, and it is safe only
// because no two threads ever emit on one request's signal.
TEST(SoakPlan, EveryCancellationFollowsItsInitiationOnOneThread) {
  const auto plan = makePlan(4242, twoSeconds);
  std::set<int> initiated;
  std::map<int, int> cancellingThread;
  for (const auto& e : plan.events) {
    if (!e.request) continue;
    const int request = *e.request;
    if (e.action == Action::Initiate) {
      EXPECT_TRUE(initiated.insert(request).second) << "request " << request << " twice";
      continue;
    }
    EXPECT_TRUE(initiated.contains(request))
        << "request " << request << " is cancelled before it is initiated";
    const auto [it, first] = cancellingThread.emplace(request, e.thread);
    EXPECT_EQ(it->second, e.thread) << "request " << request << " is cancelled from two threads";
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
    slots.insert(r.client.slot);
  }
  for (const auto& e : plan.events) actions.insert(e.action);

  EXPECT_EQ(operations.size(), static_cast<std::size_t>(operationCount));
  EXPECT_EQ(behaviours.size(), static_cast<std::size_t>(behaviourCount));
  EXPECT_EQ(actions.size(), static_cast<std::size_t>(actionCount));
  EXPECT_EQ(slots.size(), static_cast<std::size_t>(clientSlots));
}

// The seed decides which Client each request and disruption reaches, not only which slot: a
// request lands on the generation of its slot that every Stop and Destroy planned before it left
// there, and each of those ends the generation it finds. A thread that falls behind the plan then
// still reaches the same Client it did on the run being replayed.
TEST(SoakPlan, EachRequestAndDisruptionNamesTheGenerationOfItsSlot) {
  const auto plan = makePlan(31337, twoSeconds);
  std::map<int, int> generation;
  int disruptions = 0;
  for (const auto& e : plan.events) {
    const int current = generation[e.client.slot];
    switch (e.action) {
      case Action::Initiate:
      case Action::CancelTerminal:
      case Action::CancelTotal: {
        ASSERT_TRUE(e.request.has_value());
        const auto& r = plan.requests.at(static_cast<std::size_t>(*e.request));
        EXPECT_EQ(e.client, r.client) << "request " << *e.request;
        if (e.action == Action::Initiate) {
          EXPECT_EQ(r.client.generation, current) << "request " << *e.request;
        }
        break;
      }
      case Action::Stop:
      case Action::Destroy:
        EXPECT_FALSE(e.request.has_value());
        EXPECT_EQ(e.client.generation, current);
        generation[e.client.slot] = current + 1;
        ++disruptions;
        break;
    }
  }
  EXPECT_GT(disruptions, 0);

  // And the Plan counts each generation's requests as the soak's slots will need them.
  std::array<std::vector<int>, clientSlots> counted;
  for (int slot = 0; slot < clientSlots; ++slot)
    counted.at(static_cast<std::size_t>(slot))
        .assign(static_cast<std::size_t>(generation[slot]) + 1, 0);
  for (const auto& r : plan.requests) {
    ++counted.at(static_cast<std::size_t>(r.client.slot))
          .at(static_cast<std::size_t>(r.client.generation));
  }
  EXPECT_EQ(plan.requestsPerGeneration, counted);
}

TEST(SoakPlan, BehaviourWeightsCoverEveryBehaviourOnce) {
  std::set<Behaviour> seen;
  int total = 0;
  for (const auto& [behaviour, percent] : behaviourWeights) {
    EXPECT_TRUE(seen.insert(behaviour).second) << nameOf(behaviour);
    EXPECT_GT(percent, 0) << nameOf(behaviour);
    total += percent;
  }
  EXPECT_EQ(total, 100);
  EXPECT_EQ(seen.size(), static_cast<std::size_t>(behaviourCount));
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
  EXPECT_EQ(parseSeconds("0.001"), std::optional<milliseconds>(1));
  EXPECT_EQ(parseSeconds("31536000"), std::optional<milliseconds>(31'536'000'000));
  EXPECT_EQ(parseSeconds("0.0015"), std::optional<milliseconds>(2));
  EXPECT_FALSE(parseSeconds("0.0004").has_value());
  EXPECT_FALSE(parseSeconds("31536001").has_value());
  EXPECT_FALSE(parseSeconds("99999999999999999999").has_value());
  EXPECT_FALSE(parseSeconds(".").has_value());
  EXPECT_FALSE(parseSeconds("1.2.3").has_value());
  EXPECT_FALSE(parseSeconds("+2").has_value());
  EXPECT_FALSE(parseSeconds(" 2").has_value());
  EXPECT_EQ(parseSeconds(".5"), std::optional<milliseconds>(500));
  EXPECT_EQ(parseSeconds("5."), std::optional<milliseconds>(5000));
  EXPECT_EQ(parseSeconds("31536000.0004"), std::optional<milliseconds>(31'536'000'000));
  EXPECT_FALSE(parseSeconds("31536000.0005").has_value());
  // Decimal only, as the replay line prints it: an exponent is not a form formatSeconds writes.
  EXPECT_FALSE(parseSeconds("1e3").has_value());
  EXPECT_FALSE(parseSeconds("1.5e3").has_value());
}

TEST(SoakEnvironment, FormatsADurationAsDecimalSeconds) {
  EXPECT_EQ(formatSeconds(milliseconds(2000)), "2");
  EXPECT_EQ(formatSeconds(milliseconds(1500)), "1.5");
  EXPECT_EQ(formatSeconds(milliseconds(250)), "0.25");
  EXPECT_EQ(formatSeconds(milliseconds(1)), "0.001");
  EXPECT_EQ(formatSeconds(milliseconds(1'000'000'000)), "1000000");
  EXPECT_EQ(formatSeconds(milliseconds(1'234'567'891)), "1234567.891");
}

// The replay line is printed with formatSeconds and read back with parseSeconds, so every
// duration the soak accepts has to survive the trip -- a million seconds and up included, which a
// double streamed with its default precision writes as 1e+06.
TEST(SoakEnvironment, APrintedDurationReadsBackUnchanged) {
  for (const auto ms :
       {1LL, 10LL, 999LL, 2000LL, 1'000'000'000LL, 1'234'567'891LL, 31'536'000'000LL}) {
    EXPECT_EQ(parseSeconds(formatSeconds(milliseconds(ms))), std::optional<milliseconds>(ms))
        << ms << " ms";
  }
}

TEST(SoakPlan, DescribesARequestForAFailureMessage) {
  Request r;
  r.client = ClientRef{3, 2};
  r.operation = Operation::WalkCollect;
  r.behaviour = Behaviour::Late;
  EXPECT_EQ(describe(r), "slot 3 (v3), generation 2: WalkCollect, Agent answers late");
}

TEST(SoakPlan, SummarisesEachActionUnderItsOwnName) {
  Plan plan;
  const auto add = [&plan](Action action, int times) {
    for (int i = 0; i < times; ++i) plan.events.push_back(Event{{}, 0, action, {}, std::nullopt});
  };
  add(Action::Initiate, 5);
  add(Action::CancelTerminal, 4);
  add(Action::CancelTotal, 3);
  add(Action::Stop, 2);
  add(Action::Destroy, 1);
  EXPECT_EQ(summary(plan),
            "5 requests, 4 terminal and 3 total cancellations, 2 stops, 1 destructions");
}

}  // namespace
}  // namespace snmpio::test::soak
