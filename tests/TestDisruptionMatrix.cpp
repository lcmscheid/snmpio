#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>

#include "CompletionOracle.hpp"
#include "ScriptedAgent.hpp"
#include "ScriptedV3Agent.hpp"

namespace snmpio {
namespace {

using test::CompletionOracle;
using test::ScriptedAgent;
using test::ScriptedV3Agent;
using test::targetFor;

const Community publicCommunity{Community("public")};
const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};
const Oid systemGroup{1, 3, 6, 1, 2, 1, 1};

Credentials credentials() {
  return Credentials{"bert",       SecurityLevel::AuthNoPriv, AuthProtocol::Sha256,
                     "maplesyrup", PrivProtocol::None,        ""};
}

// ---------------------------------------------------------------------------
// The oracle, against handlers misbehaving on purpose. Without these, a matrix that passed would
// say nothing about whether the oracle could have failed it.
// ---------------------------------------------------------------------------

TEST(CompletionOracle, AcceptsOneCompletionOnTheCallerExecutor) {
  net::IoContext io;
  CompletionOracle oracle(io);
  net::asio::dispatch(
      oracle.callerExecutor(),
      [h = oracle.handler([](net::ErrorCode) {})]() mutable { h(net::ErrorCode{}); });
  io.run();
  EXPECT_TRUE(oracle.completedExactlyOnce({net::ErrorCode{}}));
}

TEST(CompletionOracle, RejectsASecondInvocation) {
  net::IoContext io;
  CompletionOracle oracle(io);
  net::asio::dispatch(oracle.callerExecutor(),
                      [h = oracle.handler([](net::ErrorCode) {})]() mutable {
                        h(net::ErrorCode{});
                        h(make_error_code(Errc::ClientStopped));
                      });
  io.run();
  EXPECT_FALSE(oracle.completedExactlyOnce({net::ErrorCode{}}));
  ASSERT_EQ(oracle.invocations().size(), 2U);
  EXPECT_EQ(oracle.invocations()[1].ordinal, 2);
}

TEST(CompletionOracle, RejectsAHandlerDroppedWithoutBeingCalled) {
  net::IoContext io;
  CompletionOracle oracle(io);
  {
    auto dropped = oracle.handler([](net::ErrorCode) {});
  }
  EXPECT_EQ(oracle.destructions(), 1);
  EXPECT_FALSE(oracle.completedExactlyOnce({net::ErrorCode{}}));
}

TEST(CompletionOracle, RejectsACompletionOffTheCallerExecutor) {
  net::IoContext io;
  CompletionOracle oracle(io);
  // Called straight from io's own executor, not through the strand it was bound to -- which is
  // what a Client invoking it on its own strand would look like.
  net::asio::post(io,
                  [h = oracle.handler([](net::ErrorCode) {})]() mutable { h(net::ErrorCode{}); });
  io.run();
  ASSERT_EQ(oracle.invocations().size(), 1U);
  EXPECT_FALSE(oracle.invocations()[0].onCallerExecutor);
  EXPECT_FALSE(oracle.completedExactlyOnce({net::ErrorCode{}}));
}

TEST(CompletionOracle, RejectsACodeOutsideTheAllowedSet) {
  net::IoContext io;
  CompletionOracle oracle(io);
  net::asio::dispatch(
      oracle.callerExecutor(),
      [h = oracle.handler([](net::ErrorCode) {})]() mutable { h(make_error_code(Errc::Timeout)); });
  io.run();
  EXPECT_FALSE(oracle.completedExactlyOnce({net::asio::error::operation_aborted}));
  EXPECT_TRUE(oracle.completedExactlyOnce(
      {net::asio::error::operation_aborted, make_error_code(Errc::Timeout)}));
}

TEST(CompletionOracle, CountsOnlyTheLiveHandlerAcrossMoves) {
  net::IoContext io;
  CompletionOracle oracle(io);
  {
    auto first = oracle.handler([](net::ErrorCode) {});
    auto second = std::move(first);
    auto third = std::move(second);
    net::asio::dispatch(oracle.callerExecutor(),
                        [h = std::move(third)]() mutable { h(net::ErrorCode{}); });
  }
  io.run();
  EXPECT_TRUE(oracle.completedExactlyOnce({net::ErrorCode{}}));
}

// ---------------------------------------------------------------------------
// The disruption matrix: the three waits an Outstanding Request can be in (CONTEXT.md), plus the
// first of them inside a Walk, where ADR-0004 reads `total` differently -- crossed with the three
// disruptions the Client supports today. Destruction is the fourth disruption, and its column
// arrives with ADR-0009's implementation (#31).
//
// Every cell runs through the public API against a scripted Agent on loopback, and every one is
// disrupted from inside the Agent, at the moment the datagram that marks its wait arrives -- so
// which wait a cell exercises is decided by the script, never by a timer racing the Client.
//
// After completing, a cell stays up for a quiet period longer than every deadline the request could
// still have running, with the Agent listening, and only then stops the Client. Anything the
// request left behind -- a retransmission, a Walk's next round, an exchange of its own after the
// discovery it was cancelled out of -- has to show itself to the Agent in that time.
// ---------------------------------------------------------------------------

enum class Wait : std::uint8_t {
  AwaitingAReply,  // the first attempt is out and the Target is silent
  // The first deadline passed and a retransmission went out. A request has no suspension between
  // attempts other than the send itself, so this is the wait a retransmitting request sits in.
  BetweenRetransmissions,
  QueuedBehindDiscovery,  // parked on an Engine Discovery, before any exchange of its own
  MidWalk,                // a Walk's second round is in flight, its first batch delivered
};

enum class Disruption : std::uint8_t { Terminal, Total, Stop };

// Client.hpp's cancellation rule and ADR-0004's Walk rule, as a table. Stopping is ClientStopped
// in every wait; a cancellation is operation_aborted wherever no reply counted; and a Walk reads
// `total` as finish the batch in flight, then report that the Walk is incomplete.
net::ErrorCode expectedCode(Wait wait, Disruption disruption) {
  if (disruption == Disruption::Stop) return make_error_code(Errc::ClientStopped);
  if (disruption == Disruption::Total && wait == Wait::MidWalk) {
    return make_error_code(Errc::WalkIncomplete);
  }
  return net::asio::error::operation_aborted;
}

// Four deadlines: the three attempts silentTarget allows, and one to spare.
constexpr auto quietPeriod = std::chrono::milliseconds(200);

// One cell's world: one io_context on the test thread, so a hung operation is a hung test rather
// than a flake.
struct Rig {
  explicit Rig(Disruption d) : disruption(d) {}

  net::IoContext io;
  Client client{io.get_executor()};
  CompletionOracle oracle{io};
  net::asio::cancellation_signal signal;
  Disruption disruption;
  std::function<void()> closeAgent = [] {};
  net::SteadyTimer quiet{io};

  void disrupt() {
    switch (disruption) {
      case Disruption::Terminal:
        signal.emit(net::asio::cancellation_type::terminal);
        break;
      case Disruption::Total:
        signal.emit(net::asio::cancellation_type::total);
        break;
      case Disruption::Stop:
        client.stop();
        break;
    }
  }

  // The token every cell initiates with: the oracle's handler, under a cancellation slot the
  // disruption can reach. Completing starts the quiet period, after which the Client is stopped
  // and the Agent closed so that run() returns -- and a stop that found something still holding
  // the handler would force it out where the oracle counts it.
  template <typename Then>
  auto token(Then then) {
    return net::asio::bind_cancellation_slot(
        signal.slot(),
        oracle.handler([this, then = std::move(then)](net::ErrorCode ec, auto&&... rest) mutable {
          then(ec, std::forward<decltype(rest)>(rest)...);
          quiet.expires_after(quietPeriod);
          quiet.async_wait([this](net::ErrorCode) {
            client.stop();
            closeAgent();
          });
        }));
  }
  auto token() {
    return token([](net::ErrorCode, auto&&...) {});
  }
};

// A GET against a silent Target, disrupted as attempt `disruptAt` reaches it.
void silentTarget(Rig& rig, int disruptAt) {
  ScriptedAgent agent(rig.io, [&rig, disruptAt, seen = 0](const V2cMessage&) mutable {
    if (++seen == disruptAt) rig.disrupt();
    return std::optional<Pdu>{};
  });
  rig.closeAgent = [&agent] { agent.close(); };

  rig.client.asyncGet(targetFor(agent, 2), publicCommunity, {sysDescr}, rig.token());
  rig.io.run();

  EXPECT_EQ(agent.requestsSeen(), disruptAt) << "an attempt went out after the disruption";
}

// A GET queued behind the Engine Discovery it set off, disrupted as the discovery's first datagram
// reaches the Agent -- the moment the request is parked on the discovery rather than on a reply.
void queuedBehindDiscovery(Rig& rig) {
  int answered = 0;
  ScriptedV3Agent agent(rig.io, credentials(), [&answered](const Pdu& request) {
    ++answered;
    Pdu p;
    p.type = PduType::Response;
    p.varbinds = request.varbinds;
    return p;
  });
  agent.setOnDatagram([&rig, seen = 0](std::span<const std::byte>) mutable {
    if (seen++ == 0) rig.disrupt();
  });
  rig.closeAgent = [&agent] { agent.close(); };

  rig.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, rig.token());
  rig.io.run();

  // The data plane is answered only for an exchange of the request's own. Reaching it would mean
  // the request was let through after the disruption had already ended it.
  EXPECT_EQ(answered, 0) << "the request sent an exchange of its own after the disruption";
}

// A Walk over six rows two at a time, disrupted as its second round reaches the Agent, which
// still answers it.
void midWalk(Rig& rig) {
  std::vector<Varbind> rows;
  for (std::uint32_t i = 1; i <= 6; ++i)
    rows.emplace_back(systemGroup.child(i).child(0), Gauge32{i});

  ScriptedAgent agent(
      rig.io, [&rig, table = test::tableAgent(rows), seen = 0](const V2cMessage& msg) mutable {
        auto reply = table(msg);
        if (++seen == 2) rig.disrupt();
        return reply;
      });
  rig.closeAgent = [&agent] { agent.close(); };

  std::vector<Varbind> collected;
  rig.client.asyncWalkCollect(targetFor(agent), publicCommunity, systemGroup, WalkOptions{2},
                              rig.token([&collected](net::ErrorCode, std::vector<Varbind> vbs) {
                                collected = std::move(vbs);
                              }));
  rig.io.run();

  EXPECT_EQ(agent.requestsSeen(), 2) << "the Walk went on to a third round";
  // ADR-0004: `total` finishes the batch in flight and keeps it, and a partial Walk is never
  // passed off as a whole one; `terminal` drops everything.
  if (rig.disruption == Disruption::Total) {
    EXPECT_EQ(collected.size(), 4U) << "the batch in flight was not finished and kept";
  }
  if (rig.disruption == Disruption::Terminal) {
    EXPECT_TRUE(collected.empty()) << "terminal handed back a prefix";
  }
}

class DisruptionMatrix : public testing::TestWithParam<std::tuple<Wait, Disruption>> {};

TEST_P(DisruptionMatrix, CompletesExactlyOnceWithTheRulesCode) {
  const auto [wait, disruption] = GetParam();
  Rig rig(disruption);

  switch (wait) {
    case Wait::AwaitingAReply:
      silentTarget(rig, 1);
      break;
    case Wait::BetweenRetransmissions:
      silentTarget(rig, 2);
      break;
    case Wait::QueuedBehindDiscovery:
      queuedBehindDiscovery(rig);
      break;
    case Wait::MidWalk:
      midWalk(rig);
      break;
  }

  EXPECT_TRUE(rig.oracle.completedExactlyOnce({expectedCode(wait, disruption)}));
}

// Switches rather than tables indexed by the enum, so that reordering one cannot mislabel a cell.
std::string_view nameOf(Wait wait) {
  switch (wait) {
    case Wait::AwaitingAReply:
      return "AwaitingAReply";
    case Wait::BetweenRetransmissions:
      return "BetweenRetransmissions";
    case Wait::QueuedBehindDiscovery:
      return "QueuedBehindDiscovery";
    case Wait::MidWalk:
      return "MidWalk";
  }
  return "Unknown";
}

std::string_view nameOf(Disruption disruption) {
  switch (disruption) {
    case Disruption::Terminal:
      return "Terminal";
    case Disruption::Total:
      return "Total";
    case Disruption::Stop:
      return "Stop";
  }
  return "Unknown";
}

std::string cellName(const testing::TestParamInfo<std::tuple<Wait, Disruption>>& info) {
  return std::string(nameOf(std::get<0>(info.param))) + "_" +
         std::string(nameOf(std::get<1>(info.param)));
}

INSTANTIATE_TEST_SUITE_P(
    Client, DisruptionMatrix,
    testing::Combine(testing::Values(Wait::AwaitingAReply, Wait::BetweenRetransmissions,
                                     Wait::QueuedBehindDiscovery, Wait::MidWalk),
                     testing::Values(Disruption::Terminal, Disruption::Total, Disruption::Stop)),
    cellName);

}  // namespace
}  // namespace snmpio
