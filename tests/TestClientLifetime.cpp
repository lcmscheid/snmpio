#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <thread>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>

#include "CompletionOracle.hpp"
#include "ScriptedAgent.hpp"

// ADR-0009: destroying a Client stops it. Each test here ends a Client some way the disruption
// matrix does not -- from inside a completion, from another thread, before the io_context ever ran
// -- and holds its Outstanding Requests to the same rule as stop(): exactly one completion, with
// ClientStopped, on the caller's executor. The ASan and TSan presets are what turn a use of the
// freed Client into a failure here; without them most of these would pass by luck.

namespace snmpio {
namespace {

using test::CompletionOracle;
using test::respondWith;
using test::ScriptedAgent;
using test::tableAgent;
using test::targetFor;

const Community publicCommunity{Community("public")};
const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};
const Oid sysUpTime{1, 3, 6, 1, 2, 1, 1, 3, 0};
const Oid systemGroup{1, 3, 6, 1, 2, 1, 1};

// Long enough that a request ended by its deadline rather than by the Client going away shows up
// as Timeout instead of passing, short enough not to hang the suite if it does.
constexpr auto longDeadline = std::chrono::seconds(5);

// Answers sysDescr and nothing else, so one request completes and any other stays outstanding.
std::optional<Pdu> answerOnlySysDescr(const V2cMessage& msg) {
  if (msg.pdu.varbinds.empty() || msg.pdu.varbinds.front().name != sysDescr) return std::nullopt;
  return respondWith({Varbind{sysDescr, Octets{std::byte{'o'}, std::byte{'k'}}}});
}

Target slowTarget(const ScriptedAgent& agent) {
  auto t = targetFor(agent, 0);
  t.timeout = longDeadline;
  return t;
}

// Nothing listens here and nothing is sent: every request in these tests is over before it would
// reach the wire.
Target unreachableTarget() {
  Target t;
  t.endpoint = {net::asio::ip::make_address("127.0.0.1"), 9};
  t.timeout = longDeadline;
  return t;
}

Credentials credentials() {
  return Credentials{"bert",       SecurityLevel::AuthNoPriv, AuthProtocol::Sha256,
                     "maplesyrup", PrivProtocol::None,        ""};
}

TEST(ClientLifetime, DestroyedFromItsOwnCompletionHandlerStopsTheRest) {
  net::IoContext io;
  ScriptedAgent agent(io, answerOnlySysDescr);
  CompletionOracle answered(io);
  CompletionOracle outstanding(io);
  auto client = std::make_unique<Client>(io.get_executor());

  client->asyncGet(
      slowTarget(agent), publicCommunity, {sysUpTime},
      outstanding.handler([&agent](net::ErrorCode, const Response&) { agent.close(); }));
  client->asyncGet(
      slowTarget(agent), publicCommunity, {sysDescr},
      answered.handler([&client](net::ErrorCode, const Response&) { client.reset(); }));
  io.run();

  EXPECT_TRUE(answered.completedExactlyOnce({net::ErrorCode{}}));
  EXPECT_TRUE(outstanding.completedExactlyOnce({make_error_code(Errc::ClientStopped)}));
}

// A token with no associated executor completes on the Client's own strand (Client.hpp), so here
// the destructor runs on the strand, mid-way through the Client's own work.
TEST(ClientLifetime, DestroyedFromACompletionOnItsOwnStrandStopsTheRest) {
  net::IoContext io;
  ScriptedAgent agent(io, answerOnlySysDescr);
  auto client = std::make_unique<Client>(io.get_executor());
  std::vector<net::ErrorCode> outstanding;
  int answered = 0;

  client->asyncGet(slowTarget(agent), publicCommunity, {sysUpTime},
                   [&](net::ErrorCode ec, const Response&) {
                     outstanding.push_back(ec);
                     agent.close();
                   });
  client->asyncGet(slowTarget(agent), publicCommunity, {sysDescr},
                   [&](net::ErrorCode ec, const Response&) {
                     ++answered;
                     EXPECT_FALSE(ec) << ec.message();
                     client.reset();
                   });
  io.run();

  EXPECT_EQ(answered, 1);
  ASSERT_EQ(outstanding.size(), 1U);
  EXPECT_EQ(outstanding.front(), Errc::ClientStopped);
}

TEST(ClientLifetime, DestroyedFromAnotherThreadStopsItsOutstandingRequests) {
  net::IoContext io;
  std::promise<void> seen;
  ScriptedAgent agent(io, [&seen, once = false](const V2cMessage&) mutable {
    if (!once) seen.set_value();
    once = true;
    return std::optional<Pdu>{};
  });
  CompletionOracle oracle(io);
  std::promise<void> completed;
  auto client = std::make_unique<Client>(io.get_executor());

  client->asyncGet(
      slowTarget(agent), publicCommunity, {sysDescr},
      oracle.handler([&completed](net::ErrorCode, const Response&) { completed.set_value(); }));
  std::thread runner([&io] { io.run(); });

  // Destroyed here, on the test thread, while the io_context's own thread is running it and the
  // request is waiting on a Target that will never answer.
  const bool reached = seen.get_future().wait_for(longDeadline) == std::future_status::ready;
  client.reset();
  const bool finished = completed.get_future().wait_for(longDeadline) == std::future_status::ready;
  net::asio::post(io, [&agent] { agent.close(); });
  runner.join();

  ASSERT_TRUE(reached) << "the request never reached the Agent";
  ASSERT_TRUE(finished) << "the request was still outstanding after the Client was destroyed";
  // Well before the request's own deadline, or it was the deadline that ended it.
  EXPECT_TRUE(oracle.completedExactlyOnce({make_error_code(Errc::ClientStopped)}));
}

// Runs `then` after `hops` trips through the io_context. Nothing in the public API lands an event
// at a chosen step inside the Client, so the sweeps below try every step in turn: which hop count
// lands in which step is Asio's business and may change, and the rule has to hold at all of them.
void afterHops(net::IoContext& io, int hops, std::function<void()> then) {
  // Built inside out, one post wrapped around the next, so that nothing here recurses.
  for (int i = 0; i < hops; ++i) {
    then = [&io, next = std::move(then)]() mutable { net::asio::post(io, std::move(next)); };
  }
  then();
}

constexpr int sweepHops = 8;

// The matrix's mid-Walk cell destroys the Client before the Agent answers, and its cleanup then
// reaches the strand ahead of the reply. The case worth guarding is the other order: the reply
// already read, or already accepted with the Walk not yet resumed to hand it on, when destruction
// begins. So destruction is put off by a sweep of hops after the reply has gone, which walks it
// across the reply's own path through the Client one scheduler step at a time.
TEST(ClientLifetime, ABatchHandlerIsNeverCalledOnceDestructionHasBegun) {
  // More rounds than the sweep has hops, so that every Walk is still going when destruction begins.
  std::vector<Varbind> rows;
  for (std::uint32_t i = 1; i <= 40; ++i)
    rows.emplace_back(systemGroup.child(i).child(0), Gauge32{i});

  for (int hops = 0; hops < sweepHops; ++hops) {
    SCOPED_TRACE(testing::Message() << "destroyed " << hops << " hops after the reply");
    net::IoContext io;
    std::optional<Client> client{std::in_place, io.get_executor()};
    bool destroying = false;
    int batches = 0;
    int lateBatches = 0;
    std::optional<net::ErrorCode> result;

    // The second round's reply is sent as soon as this returns; destruction follows it.
    ScriptedAgent agent(io, [&, table = tableAgent(rows), seen = 0](const V2cMessage& msg) mutable {
      if (++seen == 2) {
        net::asio::post(io, [&, hops] {
          afterHops(io, hops, [&] {
            destroying = true;
            client.reset();
          });
        });
      }
      return table(msg);
    });

    client->asyncWalk(
        targetFor(agent), publicCommunity, systemGroup, WalkOptions{2},
        [&](std::span<const Varbind>) {
          ++batches;
          if (destroying) ++lateBatches;
          return true;
        },
        [&](net::ErrorCode ec) {
          result = ec;
          agent.close();
        });
    io.run();

    // How many batches arrived before destruction began depends on the hop; none may arrive after.
    EXPECT_EQ(lateBatches, 0);
    EXPECT_GE(batches, 1);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Errc::ClientStopped);
  }
}

// The same sweep for a single request. A reply accepted as destruction begins leaves the request
// outstanding until it resumes, and it then completes with ClientStopped like every other one. The
// completion runs on the strand straight after the request ends, with no hop between, so a success
// seen once destruction had begun is a request that ended after it.
TEST(ClientLifetime, AReplyAcceptedAsDestructionBeginsDoesNotCount) {
  for (int hops = 0; hops < sweepHops; ++hops) {
    SCOPED_TRACE(testing::Message() << "destroyed " << hops << " hops after the reply");
    net::IoContext io;
    std::optional<Client> client{std::in_place, io.get_executor()};
    bool destroying = false;
    std::optional<net::ErrorCode> result;
    bool lateSuccess = false;

    ScriptedAgent agent(io, [&, hops](const V2cMessage& msg) {
      net::asio::post(io, [&, hops] {
        afterHops(io, hops, [&] {
          destroying = true;
          client.reset();
        });
      });
      return answerOnlySysDescr(msg);
    });

    client->asyncGet(slowTarget(agent), publicCommunity, {sysDescr},
                     [&](net::ErrorCode ec, const Response&) {
                       result = ec;
                       lateSuccess = destroying && !ec;
                       agent.close();
                     });
    io.run();

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(lateSuccess) << "a request still outstanding as destruction began succeeded";
  }
}

// Research §3.1 rule 7: Stopping while a request's send is still in flight has already cancelled a
// timer the request has yet to arm, so a request that armed it afterwards would sit out a whole
// deadline before reporting ClientStopped. The same sweep, over the request's first steps.
TEST(ClientLifetime, StoppingAsTheSendCompletesStillCompletesAtOnce) {
  for (int hops = 0; hops < sweepHops; ++hops) {
    SCOPED_TRACE(testing::Message() << "stopped " << hops << " hops after initiating");
    net::IoContext io;
    ScriptedAgent agent(io, [](const V2cMessage&) { return std::optional<Pdu>{}; });
    std::optional<Client> client{std::in_place, io.get_executor()};
    std::optional<net::ErrorCode> result;
    std::chrono::steady_clock::time_point stoppedAt;
    std::chrono::steady_clock::time_point completedAt;

    client->asyncGet(slowTarget(agent), publicCommunity, {sysDescr},
                     [&](net::ErrorCode ec, const Response&) {
                       completedAt = std::chrono::steady_clock::now();
                       result = ec;
                       agent.close();
                     });
    afterHops(io, hops, [&] {
      stoppedAt = std::chrono::steady_clock::now();
      client->stop();
    });
    io.run();

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Errc::ClientStopped);
    EXPECT_LT(completedAt - stoppedAt, longDeadline / 2) << "waited for the deadline";
  }
}

TEST(ClientLifetime, ACompletedRequestNeverLaterReportsClientStopped) {
  net::IoContext io;
  ScriptedAgent agent(io, answerOnlySysDescr);
  CompletionOracle oracle(io);
  std::optional<Client> client{std::in_place, io.get_executor()};

  client->asyncGet(slowTarget(agent), publicCommunity, {sysDescr},
                   oracle.handler([&](net::ErrorCode, const Response&) {
                     client->stop();
                     client.reset();
                     agent.close();
                   }));
  io.run();

  EXPECT_TRUE(oracle.completedExactlyOnce({net::ErrorCode{}}));
}

TEST(ClientLifetime, StoppingTwiceAndThenDestroyingCompletesOnce) {
  net::IoContext io;
  ScriptedAgent agent(io, [](const V2cMessage&) { return std::optional<Pdu>{}; });
  CompletionOracle oracle(io);
  std::optional<Client> client{std::in_place, io.get_executor()};

  client->asyncGet(slowTarget(agent), publicCommunity, {sysDescr},
                   oracle.handler([&agent](net::ErrorCode, const Response&) { agent.close(); }));
  client->stop();
  client->stop();
  client.reset();
  io.run();

  EXPECT_TRUE(oracle.completedExactlyOnce({make_error_code(Errc::ClientStopped)}));
  EXPECT_EQ(agent.requestsSeen(), 0) << "a request went out after Stopping";
}

TEST(ClientLifetime, ARequestInitiatedAfterStoppingCompletesWithClientStopped) {
  net::IoContext io;
  CompletionOracle v2c(io);
  CompletionOracle v3(io);
  CompletionOracle walk(io);
  Client client(io.get_executor());

  client.stop();
  client.asyncGet(unreachableTarget(), publicCommunity, {sysDescr},
                  v2c.handler([](net::ErrorCode, const Response&) {}));
  client.asyncGet(unreachableTarget(), credentials(), {sysDescr},
                  v3.handler([](net::ErrorCode, const Response&) {}));
  client.asyncWalkCollect(unreachableTarget(), publicCommunity, systemGroup, WalkOptions{},
                          walk.handler([](net::ErrorCode, const std::vector<Varbind>&) {}));
  io.run();

  EXPECT_TRUE(v2c.completedExactlyOnce({make_error_code(Errc::ClientStopped)}));
  EXPECT_TRUE(v3.completedExactlyOnce({make_error_code(Errc::ClientStopped)}));
  EXPECT_TRUE(walk.completedExactlyOnce({make_error_code(Errc::ClientStopped)}));
}

TEST(ClientLifetime, DestroyedBeforeTheIoContextRunsStillCompletesWithClientStopped) {
  net::IoContext io;
  CompletionOracle oracle(io);
  {
    Client client(io.get_executor());
    client.asyncGet(unreachableTarget(), publicCommunity, {sysDescr},
                    oracle.handler([](net::ErrorCode, const Response&) {}));
  }
  io.run();

  EXPECT_TRUE(oracle.completedExactlyOnce({make_error_code(Errc::ClientStopped)}));
}

// Research §3.1 rule 4: "completes exactly once" holds only while the executor runs. An io_context
// destroyed without running destroys the handler instead of invoking it -- and with it the last
// hold on the Client's state, which LSan, under the ASan preset, checks is not leaked.
//
// Counted by hand rather than by the oracle: the oracle's caller strand would outlive the
// io_context it belongs to here.
TEST(ClientLifetime, AnIoContextDestroyedUnrunDestroysTheHandlerUninvoked) {
  struct Tally {
    int invocations = 0;
    int destructions = 0;
  };
  class Handler {
   public:
    explicit Handler(std::shared_ptr<Tally> tally) : m_tally(std::move(tally)) {}
    Handler(Handler&& other) noexcept : m_tally(std::exchange(other.m_tally, nullptr)) {}
    Handler(const Handler&) = delete;
    Handler& operator=(const Handler&) = delete;
    Handler& operator=(Handler&&) = delete;
    ~Handler() {
      if (m_tally) ++m_tally->destructions;
    }
    void operator()(net::ErrorCode /*ec*/, const Response& /*response*/) {
      if (m_tally) ++m_tally->invocations;
    }

   private:
    std::shared_ptr<Tally> m_tally;
  };

  const auto tally = std::make_shared<Tally>();
  {
    net::IoContext io;
    Client client(io.get_executor());
    client.asyncGet(unreachableTarget(), publicCommunity, {sysDescr}, Handler(tally));
  }

  EXPECT_EQ(tally->invocations, 0);
  EXPECT_EQ(tally->destructions, 1);
}

}  // namespace
}  // namespace snmpio
