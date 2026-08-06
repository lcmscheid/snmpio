#include <gtest/gtest.h>

#include <optional>
#include <vector>

#include <snmpio/Client.hpp>

#include "ScriptedAgent.hpp"

namespace snmpio {
namespace {

using test::respondWith;
using test::respondWithError;
using test::ScriptedAgent;
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

// An Agent serving a small in-order table, honouring GETNEXT and GETBULK alike.
ScriptedAgent::Responder tableAgent(std::vector<Varbind> table) {
  return [table = std::move(table)](const V2cMessage& msg) -> std::optional<Pdu> {
    const Oid& from = msg.pdu.varbinds.at(0).name;
    const auto count = msg.pdu.type == PduType::GetBulk
                           ? static_cast<std::size_t>(msg.pdu.maxRepetitions())
                           : std::size_t{1};

    std::vector<Varbind> out;
    for (const auto& vb : table) {
      if (out.size() >= count) break;
      if (from < vb.name) out.push_back(vb);
    }
    if (out.size() < count) {
      out.push_back(Varbind{Oid{1, 3, 6, 1, 2, 1, 2}, ValueException::EndOfMibView});
    }
    return respondWith(std::move(out));
  };
}

std::vector<Varbind> smallTable() {
  std::vector<Varbind> table;
  for (std::uint32_t i = 1; i <= 5; ++i) {
    table.push_back(Varbind{systemGroup.child(i).child(0), Gauge32{i}});
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

TEST(ClientWalk, ATotalCancellationFinishesTheBatchAndKeepsWhatItGot) {
  Fixture f;
  // ADR-0004's `total`: stop cleanly at a batch boundary, keep what arrived, and say so. The
  // Agent fires the signal itself while answering the second round, so there is no timer to race.
  net::asio::cancellation_signal signal;
  auto table = tableAgent(smallTable());
  ScriptedAgent agent(f.io, [&signal, &table](const V2cMessage& msg) {
    auto reply = table(msg);
    signal.emit(net::asio::cancellation_type::total);
    return reply;
  });
  f.agent = &agent;

  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, WalkOptions{2},
                            net::asio::bind_cancellation_slot(signal.slot(), f.collectToken()));
  f.run();

  EXPECT_EQ(f.ec, Errc::WalkIncomplete);
  // The in-flight batch was finished, not dropped -- but the Walk did not reach the end.
  EXPECT_EQ(f.collected.size(), 2U);
}

TEST(ClientWalk, ATerminalCancellationDropsTheWalkImmediately) {
  Fixture f;
  // The other half of ADR-0004's split. Terminal does not wait for a boundary, and the caller is
  // told the operation was aborted rather than that the Subtree ended.
  net::asio::cancellation_signal signal;
  auto table = tableAgent(smallTable());
  ScriptedAgent agent(f.io, [&signal, &table](const V2cMessage& msg) {
    auto reply = table(msg);
    signal.emit(net::asio::cancellation_type::terminal);
    return reply;
  });
  f.agent = &agent;

  f.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, WalkOptions{2},
                            net::asio::bind_cancellation_slot(signal.slot(), f.collectToken()));
  f.run();

  EXPECT_EQ(f.ec, net::asio::error::operation_aborted);
  EXPECT_NE(f.ec, Errc::WalkIncomplete) << "aborted is not the same as incomplete";
  EXPECT_TRUE(f.collected.empty()) << "terminal drops everything, it does not hand back a prefix";
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

TEST(Client, FailsOutstandingRequestsWhenItStops) {
  Fixture f;
  ScriptedAgent agent(f.io, [](const V2cMessage&) { return std::nullopt; });

  Target target = targetFor(agent);
  target.timeout = std::chrono::seconds(30);  // long enough that only stop() can end this
  f.agent = &agent;
  f.client.asyncGet(target, publicCommunity, {sysDescr}, f.requestToken());

  net::SteadyTimer fuse(f.io, std::chrono::milliseconds(20));
  fuse.async_wait([&f](net::ErrorCode) { f.client.stop(); });

  f.run();
  EXPECT_EQ(f.ec, Errc::ClientStopped);
}

}  // namespace
}  // namespace snmpio
