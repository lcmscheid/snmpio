#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>

#include "AfterHops.hpp"
#include "Deadlines.hpp"
#include "ScriptedAgent.hpp"

namespace snmpio {
namespace {

using test::afterHops;
using test::atOnceLimit;
using test::longDeadline;
using test::longDeadlineTarget;
using test::respondWith;
using test::respondWithError;
using test::ScriptedAgent;
using test::sweepHops;
using test::tableAgent;
using test::targetFor;

const Community publicCommunity{Community("public")};
const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};
const Oid sysUpTime{1, 3, 6, 1, 2, 1, 1, 3, 0};

// Everything runs on one io_context in the test thread, so there is nothing to synchronise and a
// hung operation shows up as a hung test rather than as a flake.
struct Fixture {
  net::IoContext io;
  Client client{io.get_executor()};
  // Set before initiating. Closed on completion, together with the Client, so that run() returns
  // exactly when the operation under test is done rather than on a timer.
  ScriptedAgent* agent = nullptr;

  net::ErrorCode ec;
  Response response;
  std::vector<Varbind> collected;
  bool completed = false;
  std::chrono::steady_clock::time_point completedAt;

  auto requestToken() {
    return [this](net::ErrorCode e, Response r) {
      ec = e;
      response = std::move(r);
      finish();
    };
  }

  auto walkToken() {
    return [this](net::ErrorCode e) {
      ec = e;
      finish();
    };
  }

  auto collectToken() {
    return [this](net::ErrorCode e, std::vector<Varbind> vbs) {
      ec = e;
      collected = std::move(vbs);
      finish();
    };
  }

  void finish() {
    completed = true;
    completedAt = std::chrono::steady_clock::now();
    client.stop();
    if (agent != nullptr) agent->close();
  }

  void run() {
    io.run();
    EXPECT_TRUE(completed) << "the operation never completed";
  }
};

TEST(ClientGet, ReturnsTheVarbindsTheAgentSent) {
  Fixture f;
  ScriptedAgent agent(f.io, [](const V2cMessage& msg) {
    EXPECT_EQ(msg.pdu.type, PduType::Get);
    EXPECT_EQ(msg.community, "public");
    return respondWith({Varbind{sysDescr, Octets{std::byte{'o'}, std::byte{'k'}}}});
  });
  f.agent = &agent;

  f.client.asyncGet(targetFor(agent), publicCommunity, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  ASSERT_EQ(f.response.varbinds.size(), 1U);
  EXPECT_EQ(f.response.varbinds[0].name, sysDescr);
}

TEST(ClientGet, RetransmitsAndThenTimesOut) {
  Fixture f;
  // Silence is what a lost datagram and a dead Target look like from here; both must end as a
  // Timeout rather than as a hang.
  ScriptedAgent agent(f.io, [](const V2cMessage&) { return std::nullopt; });
  f.agent = &agent;

  f.client.asyncGet(targetFor(agent, 2), publicCommunity, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::Timeout);
  EXPECT_EQ(agent.requestsSeen(), 3);  // the first attempt plus two retransmissions
}

TEST(ClientGet, IgnoresAResponseQuotingTheWrongCommunity) {
  Fixture f;
  // The request-id is guessable and UDP is spoofable, so a Response that does not quote the
  // Community we used is not ours -- it must be dropped, not delivered.
  ScriptedAgent agent(
      f.io, [](const V2cMessage&) { return respondWith({Varbind{sysDescr, TimeTicks{1}}}); });
  agent.setCommunityOverride("elsewhere");
  f.agent = &agent;

  f.client.asyncGet(targetFor(agent, 0), publicCommunity, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::Timeout);
}

TEST(ClientSet, SurfacesTheAgentsErrorStatusAndTheVarbindItNamed) {
  Fixture f;
  ScriptedAgent agent(f.io, [](const V2cMessage& msg) {
    EXPECT_EQ(msg.pdu.type, PduType::Set);
    return respondWithError(ErrorStatus::NotWritable, 2);
  });
  f.agent = &agent;

  f.client.asyncSet(targetFor(agent), publicCommunity,
                    {Varbind{sysDescr, Octets{}}, Varbind{sysUpTime, TimeTicks{0}}},
                    f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, ErrorStatus::NotWritable);
  EXPECT_NE(f.ec.category(), errorCategory()) << "an Agent's error-status is not one of ours";
  EXPECT_EQ(f.response.errorIndex, 2);
}

TEST(ClientGetBulk, SendsNonRepeatersAndMaxRepetitionsInThePduSlotsThatCarryThem) {
  Fixture f;
  ScriptedAgent agent(f.io, [](const V2cMessage& msg) {
    EXPECT_EQ(msg.pdu.type, PduType::GetBulk);
    EXPECT_EQ(msg.pdu.nonRepeaters(), 1);
    EXPECT_EQ(msg.pdu.maxRepetitions(), 7);
    return respondWith({});
  });
  f.agent = &agent;

  f.client.asyncGetBulk(targetFor(agent), publicCommunity, {sysDescr}, 1, 7, f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
}

// ---------------------------------------------------------------------------
// Walks
// ---------------------------------------------------------------------------

const Oid systemGroup{1, 3, 6, 1, 2, 1, 1};

std::vector<Varbind> smallTable() {
  // emplace_back, not push_back of a Varbind temporary: moving a Varbind moves the Value variant,
  // and GCC 13 mis-analyses that move as reading the Opaque alternative's uninitialised vector.
  // Constructing in place sidesteps a false positive that -Werror turns into a build failure.
  std::vector<Varbind> table;
  for (std::uint32_t i = 1; i <= 5; ++i) {
    table.emplace_back(systemGroup.child(i).child(0), Gauge32{i});
  }
  return table;
}

TEST(ClientWalk, CollectsTheWholeSubtreeAcrossSeveralRounds) {
  Fixture f;
  ScriptedAgent agent(f.io, tableAgent(smallTable()));
  f.agent = &agent;

  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, WalkOptions{2},
                            f.collectToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(f.collected, smallTable());
  EXPECT_GT(agent.requestsSeen(), 1) << "maxRepetitions 2 over five rows is not one round trip";
}

TEST(ClientWalk, WalksWithGetNextWhenMaxRepetitionsIsZero) {
  Fixture f;
  ScriptedAgent agent(f.io, [](const V2cMessage& msg) {
    EXPECT_EQ(msg.pdu.type, PduType::GetNext);
    return tableAgent(smallTable())(msg);
  });
  f.agent = &agent;

  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, WalkOptions{0},
                            f.collectToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(f.collected, smallTable());
}

TEST(ClientWalk, StopsAtTheSubtreeBoundary) {
  Fixture f;
  // No endOfMibView here: the Agent keeps answering, and only the Subtree test ends the Walk.
  ScriptedAgent agent(f.io, [](const V2cMessage& msg) {
    const Oid& from = msg.pdu.varbinds.at(0).name;
    for (const auto& vb : smallTable()) {
      if (from < vb.name) return respondWith({vb});
    }
    return respondWith({Varbind{Oid{1, 3, 6, 1, 2, 1, 2, 1, 0}, Gauge32{99}}});
  });
  f.agent = &agent;

  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, WalkOptions{0},
                            f.collectToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(f.collected, smallTable());
}

TEST(ClientWalk, RejectsANonIncreasingOid) {
  Fixture f;
  // ADR-0004: an Agent that repeats an OID would otherwise walk forever. Only a misbehaving
  // Agent produces this, which is exactly why it has to be scripted.
  ScriptedAgent agent(f.io, [](const V2cMessage& msg) {
    return respondWith({Varbind{msg.pdu.varbinds.at(0).name, Gauge32{1}}});
  });
  f.agent = &agent;

  f.client.asyncWalk(
      targetFor(agent), publicCommunity, systemGroup, WalkOptions{0},
      [](std::span<const Varbind>) { return true; }, f.walkToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::NonIncreasingOid);
}

TEST(ClientWalk, HalvesMaxRepetitionsWhenTheAgentSaysTooBig) {
  Fixture f;
  std::vector<std::int32_t> asked;
  ScriptedAgent agent(f.io, [&asked](const V2cMessage& msg) -> std::optional<Pdu> {
    asked.push_back(msg.pdu.maxRepetitions());
    // tooBig means the Response did not fit, not that the request was wrong.
    if (msg.pdu.maxRepetitions() > 2) return respondWithError(ErrorStatus::TooBig, 0);
    return tableAgent(smallTable())(msg);
  });
  f.agent = &agent;

  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, WalkOptions{8},
                            f.collectToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(f.collected, smallTable());
  ASSERT_GE(asked.size(), 3U);
  EXPECT_EQ(asked[0], 8);
  EXPECT_EQ(asked[1], 4);
  EXPECT_EQ(asked[2], 2);
}

TEST(ClientWalk, GivesUpWhenTooBigSurvivesEveryReduction) {
  Fixture f;
  ScriptedAgent agent(f.io,
                      [](const V2cMessage&) { return respondWithError(ErrorStatus::TooBig, 0); });
  f.agent = &agent;

  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, WalkOptions{4},
                            f.collectToken());
  f.run();

  EXPECT_EQ(f.ec, ErrorStatus::TooBig);
  EXPECT_TRUE(f.collected.empty());
}

TEST(ClientWalk, StreamsBatchesAndReportsAnEarlyStopAsIncomplete) {
  Fixture f;
  ScriptedAgent agent(f.io, tableAgent(smallTable()));

  std::vector<Varbind> seen;
  f.agent = &agent;
  f.client.asyncWalk(
      targetFor(agent), publicCommunity, systemGroup, WalkOptions{2},
      [&seen](std::span<const Varbind> batch) {
        seen.insert(seen.end(), batch.begin(), batch.end());
        return seen.size() < 3;  // stop partway: ADR-0004's "total" shape, driven by the handler
      },
      f.walkToken());
  f.run();

  // A partially consumed Walk must never look like a whole one.
  EXPECT_EQ(f.ec, Errc::WalkIncomplete);
  EXPECT_EQ(seen.size(), 4U);
}

TEST(ClientWalk, ACancelledWalkAgainstASilentTargetIsIncompleteNotTimedOut) {
  Fixture f;
  // The Agent answers once, then goes quiet at the same moment the Walk is cancelled. The
  // exchange dies of the timeout, but the reason the Walk ended is the cancellation, and a
  // caller must be able to tell "I stopped this" from "the Target is dead".
  net::asio::cancellation_signal signal;
  auto table = tableAgent(smallTable());
  int seen = 0;
  ScriptedAgent agent(f.io, [&](const V2cMessage& msg) -> std::optional<Pdu> {
    if (++seen > 1) {
      signal.emit(net::asio::cancellation_type::total);
      return std::nullopt;
    }
    return table(msg);
  });
  f.agent = &agent;

  f.client.asyncWalkCollect(targetFor(agent, 0), publicCommunity, systemGroup, WalkOptions{2},
                            net::asio::bind_cancellation_slot(signal.slot(), f.collectToken()));
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete);
  EXPECT_NE(f.ec, Errc::Timeout);
  EXPECT_EQ(f.collected.size(), 2U) << "the batch that did arrive is kept";
}

// A cancellation signal that remembers when it emitted terminal, so that a test can time a
// request's end against the signal that should have dropped it at once, whatever else it emits.
struct TimedSignal {
  net::asio::cancellation_signal signal;
  std::chrono::steady_clock::time_point terminalAt;

  void emit(net::asio::cancellation_type type) {
    if (type == net::asio::cancellation_type::terminal) {
      terminalAt = std::chrono::steady_clock::now();
    }
    signal.emit(type);
  }

  template <typename Token>
  auto bind(Token token) {
    return net::asio::bind_cancellation_slot(signal.slot(), std::move(token));
  }
};

// The rest of Client.hpp's cancellation rule -- every wait, under both types -- and Stopping are
// TestDisruptionMatrix.cpp's. These are the cases it does not cover: a reply that counts, a
// terminal signal landing between two steps of an exchange rather than inside a wait, and the two
// types arriving one after the other.
TEST(ClientCancel, ATotalSignalStillTakesTheReplyAlreadyOnItsWay) {
  Fixture f;
  // The half that separates total from terminal: the exchange in flight is allowed to finish.
  net::asio::cancellation_signal signal;
  ScriptedAgent agent(f.io, [&signal](const V2cMessage&) {
    signal.emit(net::asio::cancellation_type::total);
    return respondWith({Varbind{sysDescr, TimeTicks{7}}});
  });
  f.agent = &agent;

  f.client.asyncGet(targetFor(agent, 0), publicCommunity, {sysDescr},
                    net::asio::bind_cancellation_slot(signal.slot(), f.requestToken()));
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  ASSERT_EQ(f.response.varbinds.size(), 1U);
}

// A terminal signal that reaches the Client's strand after the send has completed, but before the
// request has gone on to wait for the reply, finds no operation of its own to cancel. The request
// has to notice it was dropped anyway, rather than arm its timer and sit out the deadline.
TEST(ClientCancel, ATerminalSignalAsTheSendCompletesStillDropsAtOnce) {
  for (int hops = 0; hops < sweepHops; ++hops) {
    SCOPED_TRACE(testing::Message() << "emitted " << hops << " hops after initiating");
    Fixture f;
    ScriptedAgent agent(f.io, [](const V2cMessage&) { return std::optional<Pdu>{}; });
    f.agent = &agent;
    TimedSignal signal;

    f.client.asyncGet(longDeadlineTarget(agent), publicCommunity, {sysDescr},
                      signal.bind(f.requestToken()));
    afterHops(f.io, hops, [&] { signal.emit(net::asio::cancellation_type::terminal); });
    f.run();

    EXPECT_EQ(f.ec, net::asio::error::operation_aborted) << f.ec.message();
    EXPECT_LT(f.completedAt - signal.terminalAt, atOnceLimit(longDeadline))
        << "waited for the deadline";
  }
}

// A total signal leaves the request waiting out the rest of its deadline, so a reply on its way
// still counts. That wait must not be deaf to a terminal signal that follows: terminal drops the
// request at once, wherever the request is. The sweep starts as the Agent hears the request, while
// the request is waiting for the reply, and carries the terminal signal past the moment the total
// one wakes it and into the wait it then goes back to.
TEST(ClientCancel, ATerminalSignalAfterATotalOneStillDropsAtOnce) {
  for (int hops = 0; hops < sweepHops; ++hops) {
    SCOPED_TRACE(testing::Message() << "terminal " << hops << " hops after total");
    Fixture f;
    TimedSignal signal;
    ScriptedAgent agent(f.io, [&](const V2cMessage&) {
      signal.emit(net::asio::cancellation_type::total);
      afterHops(f.io, hops, [&] { signal.emit(net::asio::cancellation_type::terminal); });
      return std::optional<Pdu>{};
    });
    f.agent = &agent;

    f.client.asyncGet(longDeadlineTarget(agent), publicCommunity, {sysDescr},
                      signal.bind(f.requestToken()));
    f.run();

    EXPECT_EQ(f.ec, net::asio::error::operation_aborted) << f.ec.message();
    EXPECT_LT(f.completedAt - signal.terminalAt, atOnceLimit(longDeadline))
        << "waited for the deadline";
  }
}

// The same wait, with the reply on its way as well. Whichever reaches the request first decides
// it: a request still outstanding when terminal is emitted completes with operation_aborted, even
// with the reply already in hand, and only one that completed before it delivers the reply.
TEST(ClientCancel, ATerminalSignalAfterATotalOneDropsTheReplyInHand) {
  int dropped = 0;
  int delivered = 0;
  for (int hops = 0; hops < sweepHops; ++hops) {
    SCOPED_TRACE(testing::Message() << "terminal " << hops << " hops after total");
    Fixture f;
    TimedSignal signal;
    bool completedBeforeTerminal = false;
    ScriptedAgent agent(f.io, [&](const V2cMessage&) {
      signal.emit(net::asio::cancellation_type::total);
      afterHops(f.io, hops, [&] {
        completedBeforeTerminal = f.completed;
        signal.emit(net::asio::cancellation_type::terminal);
      });
      return respondWith({Varbind{sysDescr, TimeTicks{7}}});
    });
    f.agent = &agent;

    f.client.asyncGet(longDeadlineTarget(agent), publicCommunity, {sysDescr},
                      signal.bind(f.requestToken()));
    f.run();

    if (completedBeforeTerminal) {
      ++delivered;
      EXPECT_FALSE(f.ec) << f.ec.message();
      EXPECT_EQ(f.response.varbinds.size(), 1U);
    } else {
      ++dropped;
      EXPECT_EQ(f.ec, net::asio::error::operation_aborted) << f.ec.message();
      EXPECT_TRUE(f.response.varbinds.empty()) << "the reply in hand counted";
    }
  }
  // Both sides of the race, or the sweep is not crossing it.
  EXPECT_GT(dropped, 0);
  EXPECT_GT(delivered, 0);
}

// The other order. A terminal signal has already dropped the request; a total one that follows,
// before the request has acted on the first, must not soften it back into waiting out the deadline.
TEST(ClientCancel, ATotalSignalAfterATerminalOneStillDropsAtOnce) {
  Fixture f;
  TimedSignal signal;
  ScriptedAgent agent(f.io, [&](const V2cMessage&) {
    signal.emit(net::asio::cancellation_type::terminal);
    signal.emit(net::asio::cancellation_type::total);
    return std::optional<Pdu>{};
  });
  f.agent = &agent;

  f.client.asyncGet(longDeadlineTarget(agent), publicCommunity, {sysDescr},
                    signal.bind(f.requestToken()));
  f.run();

  EXPECT_EQ(f.ec, net::asio::error::operation_aborted) << f.ec.message();
  EXPECT_LT(f.completedAt - signal.terminalAt, atOnceLimit(longDeadline))
      << "waited for the deadline";
}

// A Walk reads the same state to choose its code, so the same order must not turn a dropped Walk
// into an incomplete one.
TEST(ClientCancel, ATotalSignalAfterATerminalOneStillAbortsAWalk) {
  Fixture f;
  TimedSignal signal;
  auto table = tableAgent(smallTable());
  int seen = 0;
  ScriptedAgent agent(f.io, [&](const V2cMessage& msg) -> std::optional<Pdu> {
    if (++seen > 1) {
      signal.emit(net::asio::cancellation_type::terminal);
      signal.emit(net::asio::cancellation_type::total);
      return std::nullopt;
    }
    return table(msg);
  });
  f.agent = &agent;

  f.client.asyncWalkCollect(longDeadlineTarget(agent), publicCommunity, systemGroup, WalkOptions{2},
                            signal.bind(f.collectToken()));
  f.run();

  EXPECT_EQ(f.ec, net::asio::error::operation_aborted) << f.ec.message();
  EXPECT_TRUE(f.collected.empty()) << "a dropped Walk keeps nothing";
}

// ---------------------------------------------------------------------------
// Walk limits
// ---------------------------------------------------------------------------

// The successor of an OID inside a Subtree that never ends: one arc longer, and once that would
// pass the 128 sub-identifiers an OID may carry, the last arc one higher instead. Every answer is
// inside the Subtree and strictly increasing, so neither of ADR-0004's checks ends the Walk.
Oid longerOid(const Oid& from) {
  if (from.size() < Oid::maxSubids) return from.child(1);
  Oid::Container subids(from.begin(), from.end());
  ++subids.back();
  return Oid(std::move(subids));
}

// An Agent answering every GETNEXT -- and every repetition of a GETBULK -- with longerOid of the
// name before it: a Walk of it ends only at a limit (research §1.4.3).
ScriptedAgent::Responder endlessAgent() {
  return [](const V2cMessage& msg) -> std::optional<Pdu> {
    const auto count = msg.pdu.type == PduType::GetBulk ? msg.pdu.maxRepetitions() : 1;
    std::vector<Varbind> out;
    out.reserve(static_cast<std::size_t>(count));
    Oid name = msg.pdu.varbinds.at(0).name;
    for (std::int32_t i = 0; i < count; ++i) {
      name = longerOid(name);
      out.emplace_back(name, Gauge32{static_cast<std::uint32_t>(i)});
    }
    return respondWith(std::move(out));
  };
}

// The same endless Subtree, flat: base.1, base.2, base.3, ... -- short enough names that a
// GETBULK's thousand repetitions still fit in one datagram.
ScriptedAgent::Responder endlessFlatAgent(const Oid& base) {
  return [base](const V2cMessage& msg) -> std::optional<Pdu> {
    const auto count = msg.pdu.type == PduType::GetBulk ? msg.pdu.maxRepetitions() : 1;
    const Oid& from = msg.pdu.varbinds.at(0).name;
    std::uint32_t next = from.size() > base.size() ? from[base.size()] + 1 : 1;
    std::vector<Varbind> out;
    out.reserve(static_cast<std::size_t>(count));
    for (std::int32_t i = 0; i < count; ++i) out.emplace_back(base.child(next++), Gauge32{1});
    return respondWith(std::move(out));
  };
}

// The names an endless Walk from systemGroup should have delivered, in order.
std::vector<Oid> firstLongerOids(std::size_t n) {
  std::vector<Oid> names;
  names.reserve(n);
  Oid name = systemGroup;
  for (std::size_t i = 0; i < n; ++i) names.push_back(name = longerOid(name));
  return names;
}

std::vector<Oid> namesOf(const std::vector<Varbind>& varbinds) {
  std::vector<Oid> names;
  names.reserve(varbinds.size());
  for (const auto& vb : varbinds) names.push_back(vb.name);
  return names;
}

TEST(ClientWalkLimits, AVarbindLimitEndsAnEndlessWalkWithWhatItGathered) {
  Fixture f;
  ScriptedAgent agent(f.io, endlessAgent());
  f.agent = &agent;

  WalkOptions options{0};
  options.maxVarbinds = 50;
  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, options,
                            f.collectToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete) << f.ec.message();
  EXPECT_EQ(namesOf(f.collected), firstLongerOids(50));
  EXPECT_EQ(agent.requestsSeen(), 50) << "nothing is asked for once the limit is reached";
}

TEST(ClientWalkLimits, AVarbindLimitCutsTheBatchThatCrossesIt) {
  Fixture f;
  ScriptedAgent agent(f.io, endlessAgent());
  f.agent = &agent;

  std::vector<std::size_t> batches;
  WalkOptions options{8};
  options.maxVarbinds = 20;
  f.client.asyncWalk(
      targetFor(agent), publicCommunity, systemGroup, options,
      [&batches](std::span<const Varbind> batch) {
        batches.push_back(batch.size());
        return true;
      },
      f.walkToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete) << f.ec.message();
  EXPECT_EQ(batches, (std::vector<std::size_t>{8, 8, 4}));
}

TEST(ClientWalkLimits, AWalkWhoseEndArrivesWithItsLastAllowedVarbindIsComplete) {
  Fixture f;
  ScriptedAgent agent(f.io, tableAgent(smallTable()));
  f.agent = &agent;

  // One GETBULK brings all five rows and the endOfMibView after them, so the limit and the end of
  // the Subtree arrive together, and the end is what the Walk saw.
  WalkOptions options{10};
  options.maxVarbinds = smallTable().size();
  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, options,
                            f.collectToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(f.collected, smallTable());
}

TEST(ClientWalkLimits, AWalkThatFillsItsLimitWithoutSeeingTheEndIsIncomplete) {
  Fixture f;
  ScriptedAgent agent(f.io, tableAgent(smallTable()));
  f.agent = &agent;

  // GETNEXT: the fifth row comes alone, and finding out that nothing follows it would take a sixth
  // request the limit does not allow. Incomplete is the honest answer; complete might be a lie.
  WalkOptions options{0};
  options.maxVarbinds = smallTable().size();
  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, options,
                            f.collectToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete) << f.ec.message();
  EXPECT_EQ(f.collected, smallTable());
}

TEST(ClientWalkLimits, CollectingStopsAtItsDefaultLimit) {
  Fixture f;
  ScriptedAgent agent(f.io, endlessFlatAgent(systemGroup));
  f.agent = &agent;

  // No limit given: asyncWalkCollect still has one, where asyncWalk has none.
  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup,
                            WalkOptions{maxRepetitionsCeiling}, f.collectToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete) << f.ec.message();
  ASSERT_EQ(f.collected.size(), defaultCollectLimit);
  EXPECT_EQ(f.collected.back().name,
            systemGroup.child(static_cast<std::uint32_t>(defaultCollectLimit)));
}

TEST(ClientWalkLimits, ACollectingWalkMayRaiseItsLimit) {
  Fixture f;
  ScriptedAgent agent(f.io, endlessFlatAgent(systemGroup));
  f.agent = &agent;

  WalkOptions options{maxRepetitionsCeiling};
  options.maxVarbinds = defaultCollectLimit + 500;
  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, options,
                            f.collectToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete) << f.ec.message();
  EXPECT_EQ(f.collected.size(), defaultCollectLimit + 500);
}

TEST(ClientWalkLimits, AStreamingWalkHasNoDefaultLimit) {
  Fixture f;
  ScriptedAgent agent(f.io, endlessFlatAgent(systemGroup));
  f.agent = &agent;

  // Past the collecting default, and stopped only by its own handler.
  constexpr std::size_t enough = defaultCollectLimit + (std::size_t{2} * maxRepetitionsCeiling);
  std::size_t seen = 0;
  f.client.asyncWalk(
      targetFor(agent), publicCommunity, systemGroup, WalkOptions{maxRepetitionsCeiling},
      [&seen](std::span<const Varbind> batch) {
        seen += batch.size();
        return seen < enough;
      },
      f.walkToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete) << f.ec.message();
  EXPECT_EQ(seen, enough);
}

TEST(ClientWalkLimits, ATimeLimitEndsAnEndlessWalkWithWhatItGathered) {
  Fixture f;
  ScriptedAgent agent(f.io, endlessAgent());
  f.agent = &agent;

  constexpr auto limit = std::chrono::milliseconds(200);
  WalkOptions options{0};
  options.timeLimit = limit;
  const auto start = std::chrono::steady_clock::now();
  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, options,
                            f.collectToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete) << f.ec.message();
  EXPECT_FALSE(f.collected.empty());
  EXPECT_EQ(namesOf(f.collected), firstLongerOids(f.collected.size()));
  EXPECT_GE(f.completedAt - start, limit);
  EXPECT_LT(f.completedAt - start, limit + atOnceLimit(longDeadline));
}

TEST(ClientWalkLimits, ATimeLimitDropsTheExchangeInFlight) {
  Fixture f;
  // One Batch, then silence against a Target that would wait five seconds for the next. The Walk's
  // own limit is what ends it, not the exchange's deadline.
  auto table = tableAgent(smallTable());
  int seen = 0;
  ScriptedAgent agent(f.io, [&](const V2cMessage& msg) -> std::optional<Pdu> {
    if (++seen > 1) return std::nullopt;
    return table(msg);
  });
  f.agent = &agent;

  constexpr auto limit = std::chrono::milliseconds(200);
  WalkOptions options{2};
  options.timeLimit = limit;
  const auto start = std::chrono::steady_clock::now();
  f.client.asyncWalkCollect(longDeadlineTarget(agent), publicCommunity, systemGroup, options,
                            f.collectToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete) << f.ec.message();
  EXPECT_EQ(f.collected.size(), 2U) << "the Batch that did arrive is kept";
  EXPECT_GE(f.completedAt - start, limit);
  EXPECT_LT(f.completedAt - start, atOnceLimit(longDeadline));
}

TEST(ClientWalkLimits, AWalkInsideItsTimeLimitIsUntouchedByIt) {
  Fixture f;
  ScriptedAgent agent(f.io, tableAgent(smallTable()));
  f.agent = &agent;

  // run() returns once the Client and the Agent are closed, so a deadline timer the Walk left
  // armed would hold it for the whole limit.
  WalkOptions options{2};
  options.timeLimit = longDeadline;
  const auto start = std::chrono::steady_clock::now();
  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, options,
                            f.collectToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(f.collected, smallTable());
  EXPECT_LT(std::chrono::steady_clock::now() - start, atOnceLimit(longDeadline));
}

// A time-limited Walk runs each request on a slot of its own, so these two hold the caller's
// signals to reaching the exchange underneath, and to meaning what they meant without the limit.
TEST(ClientWalkLimits, ACallersTerminalSignalStillDropsATimeLimitedWalkAtOnce) {
  Fixture f;
  net::asio::cancellation_signal signal;
  auto table = tableAgent(smallTable());
  int seen = 0;
  ScriptedAgent agent(f.io, [&](const V2cMessage& msg) -> std::optional<Pdu> {
    if (++seen > 1) {
      signal.emit(net::asio::cancellation_type::terminal);
      return std::nullopt;
    }
    return table(msg);
  });
  f.agent = &agent;

  WalkOptions options{2};
  options.timeLimit = longDeadline;
  const auto start = std::chrono::steady_clock::now();
  f.client.asyncWalkCollect(longDeadlineTarget(agent), publicCommunity, systemGroup, options,
                            net::asio::bind_cancellation_slot(signal.slot(), f.collectToken()));
  f.run();

  EXPECT_EQ(f.ec, net::asio::error::operation_aborted) << f.ec.message();
  EXPECT_TRUE(f.collected.empty()) << "a dropped Walk keeps nothing";
  EXPECT_LT(f.completedAt - start, atOnceLimit(longDeadline));
}

TEST(ClientWalkLimits, ACallersTotalSignalStillEndsATimeLimitedWalkIncomplete) {
  Fixture f;
  net::asio::cancellation_signal signal;
  auto table = tableAgent(smallTable());
  int seen = 0;
  ScriptedAgent agent(f.io, [&](const V2cMessage& msg) -> std::optional<Pdu> {
    if (++seen > 1) {
      signal.emit(net::asio::cancellation_type::total);
      return std::nullopt;
    }
    return table(msg);
  });
  f.agent = &agent;

  WalkOptions options{2};
  options.timeLimit = longDeadline;
  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, options,
                            net::asio::bind_cancellation_slot(signal.slot(), f.collectToken()));
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete) << f.ec.message();
  EXPECT_EQ(f.collected.size(), 2U) << "the batch that did arrive is kept";
  EXPECT_EQ(agent.requestsSeen(), 2) << "total retransmits nothing";
}

// ---------------------------------------------------------------------------
// Argument bounds
// ---------------------------------------------------------------------------

auto answerAnything() {
  return [](const V2cMessage& msg) { return respondWith(msg.pdu.varbinds); };
}

TEST(ClientArguments, RetriesPastTheCeilingAreRefusedBeforeAnythingIsSent) {
  for (const int retries : {retriesCeiling + 1, -1}) {
    Fixture f;
    ScriptedAgent agent(f.io, answerAnything());
    f.agent = &agent;

    f.client.asyncGet(targetFor(agent, retries), publicCommunity, {sysDescr}, f.requestToken());
    f.run();

    EXPECT_EQ(f.ec, Errc::ArgumentOutOfRange) << retries << ": " << f.ec.message();
    EXPECT_EQ(agent.requestsSeen(), 0) << retries;
  }
}

TEST(ClientArguments, RetriesAtTheCeilingAreAccepted) {
  Fixture f;
  ScriptedAgent agent(f.io, answerAnything());
  f.agent = &agent;

  f.client.asyncGet(targetFor(agent, retriesCeiling), publicCommunity, {sysDescr},
                    f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
}

TEST(ClientArguments, MaxRepetitionsPastTheCeilingAreRefusedBeforeAnythingIsSent) {
  for (const std::int32_t maxRepetitions : {maxRepetitionsCeiling + 1, -1}) {
    Fixture f;
    ScriptedAgent agent(f.io, answerAnything());
    f.agent = &agent;

    f.client.asyncGetBulk(targetFor(agent), publicCommunity, {sysDescr}, 0, maxRepetitions,
                          f.requestToken());
    f.run();

    EXPECT_EQ(f.ec, Errc::ArgumentOutOfRange) << maxRepetitions << ": " << f.ec.message();
    EXPECT_EQ(agent.requestsSeen(), 0) << maxRepetitions;
  }
}

TEST(ClientArguments, MaxRepetitionsAtTheCeilingAreAccepted) {
  Fixture f;
  ScriptedAgent agent(f.io, answerAnything());
  f.agent = &agent;

  f.client.asyncGetBulk(targetFor(agent), publicCommunity, {sysDescr}, 0, maxRepetitionsCeiling,
                        f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
}

TEST(ClientArguments, AWalkPastEitherCeilingIsRefusedBeforeAnythingIsSent) {
  struct Case {
    int retries;
    std::int32_t maxRepetitions;
  };
  for (const auto& c :
       {Case{retriesCeiling + 1, 10}, Case{1, maxRepetitionsCeiling + 1}, Case{1, -1}}) {
    Fixture f;
    ScriptedAgent agent(f.io, tableAgent(smallTable()));
    f.agent = &agent;

    f.client.asyncWalkCollect(targetFor(agent, c.retries), publicCommunity, systemGroup,
                              WalkOptions{c.maxRepetitions}, f.collectToken());
    f.run();

    EXPECT_EQ(f.ec, Errc::ArgumentOutOfRange)
        << c.retries << "/" << c.maxRepetitions << ": " << f.ec.message();
    EXPECT_EQ(agent.requestsSeen(), 0);
  }
}

TEST(ClientArguments, AWalkAtBothCeilingsIsAccepted) {
  Fixture f;
  ScriptedAgent agent(f.io, tableAgent(smallTable()));
  f.agent = &agent;

  f.client.asyncWalkCollect(targetFor(agent, retriesCeiling), publicCommunity, systemGroup,
                            WalkOptions{maxRepetitionsCeiling}, f.collectToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(f.collected, smallTable());
}

TEST(ClientArguments, AStoppedClientSaysSoAheadOfABadArgument) {
  Fixture f;
  ScriptedAgent agent(f.io, answerAnything());
  f.agent = &agent;

  f.client.stop();
  f.client.asyncGet(targetFor(agent, retriesCeiling + 1), publicCommunity, {sysDescr},
                    f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::ClientStopped) << f.ec.message();
}

}  // namespace
}  // namespace snmpio
