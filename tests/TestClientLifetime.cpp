#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <latch>
#include <memory>
#include <optional>
#include <semaphore>
#include <span>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>

#include "CompletionOracle.hpp"
#include "ScriptedAgent.hpp"
#include "ScriptedV3Agent.hpp"

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
using test::ScriptedV3Agent;
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

// A countdown that can be waited on with a limit, which std::latch cannot, so a signal that never
// comes is a failure rather than a hang. Counting down past zero does nothing more.
class Countdown {
 public:
  explicit Countdown(int count) : m_left(count) {}
  void countDown() {
    if (--m_left == 0) m_done.set_value();
  }
  [[nodiscard]] bool waitFor(std::chrono::milliseconds limit) const {
    return m_reached.wait_for(limit) == std::future_status::ready;
  }

 private:
  std::atomic<int> m_left;
  std::promise<void> m_done;
  std::shared_future<void> m_reached = m_done.get_future().share();
};

// The disruption matrix's four waits, in the order the test below holds a request in each.
constexpr std::array<const char*, 4> waitNames = {"AwaitingAReply", "BetweenRetransmissions",
                                                  "QueuedBehindDiscovery", "MidWalk"};

constexpr int runnerThreads = 4;
// Requests thread B initiates on the doomed Client as it hands off, one per runner, so that some
// may still be queued on the strand, not yet started, when destruction begins.
constexpr std::size_t lastMinuteRequests = runnerThreads;
// The survivor's Outstanding Requests at once: enough that B is always initiating, few enough that
// the loop cannot run away while a sanitizer slows the destruction down.
constexpr std::ptrdiff_t survivorOutstanding = 4;
// Rounds, tuned to about a second under the default preset.
constexpr int destructionRounds = 40;

// Research §3.1's last case: ~Client on thread A while four threads run the io_context and thread
// B initiates requests. When A destroys it, the doomed Client has an Outstanding Request in each of
// the disruption matrix's four waits, and B's last requests may not have started; B goes on
// initiating on a second Client sharing the io_context, the README's topology, which must not
// notice. The runners vary the interleavings from round to round; there is no jitter and no seed,
// which are the soak's (#32).
void destroyWhileOthersRunAndInitiate(int round) {
  SCOPED_TRACE(testing::Message() << "round " << round);
  net::IoContext io;
  // Each Agent signals once the request it holds is in its wait. Their responders run on the
  // Agent's own strand, so the attempt counts in them need nothing more.
  std::array<Countdown, waitNames.size()> inWait{Countdown(1), Countdown(1), Countdown(1),
                                                 Countdown(1)};
  ScriptedAgent silent(io, [&inWait, attempts = 0](const V2cMessage&) mutable {
    if (++attempts == 1) inWait[0].countDown();
    return std::optional<Pdu>{};
  });
  ScriptedAgent retransmitted(io, [&inWait, attempts = 0](const V2cMessage&) mutable {
    if (++attempts == 2) inWait[1].countDown();
    return std::optional<Pdu>{};
  });
  ScriptedV3Agent withholding(io, credentials(), [](const Pdu& request) { return request; });
  withholding.setResponder([](const ScriptedV3Agent::Request&) { return std::nullopt; });
  withholding.setOnDatagram([&inWait, datagrams = 0](std::span<const std::byte>) mutable {
    if (++datagrams == 1) inWait[2].countDown();
  });
  std::vector<Varbind> rows;
  for (std::uint32_t i = 1; i <= 6; ++i)
    rows.emplace_back(systemGroup.child(i).child(0), Gauge32{i});
  // Answers the first round and falls silent on the second, so the Walk stays mid-way.
  ScriptedAgent walked(io,
                       [&inWait, table = tableAgent(rows),
                        rounds = 0](const V2cMessage& msg) mutable -> std::optional<Pdu> {
                         if (++rounds == 1) return table(msg);
                         if (rounds == 2) inWait[3].countDown();
                         return std::nullopt;
                       });
  ScriptedAgent answering(io, answerOnlySysDescr);

  // A short attempt so the second goes out early, and enough of them that the request is still
  // retransmitting at the long deadline.
  auto retransmitting = targetFor(retransmitted, 250);
  retransmitting.timeout = std::chrono::milliseconds(20);
  auto discovering = targetFor(withholding, 0);
  discovering.timeout = longDeadline;

  std::optional<Client> doomed{std::in_place, io.get_executor()};
  Client survivor(io.get_executor());

  // The doomed Client's four waits, then B's last-minute requests. Each completes exactly once with
  // ClientStopped, at destruction rather than at its deadline.
  std::vector<CompletionOracle> doomedOracles;
  doomedOracles.reserve(waitNames.size() + lastMinuteRequests);
  for (std::size_t i = 0; i < waitNames.size() + lastMinuteRequests; ++i)
    doomedOracles.emplace_back(io);
  Countdown doomedCompleted(static_cast<int>(doomedOracles.size()));
  const auto completes = [&doomedCompleted](net::ErrorCode, const auto&) {
    doomedCompleted.countDown();
  };

  std::vector<std::thread> runners;
  runners.reserve(runnerThreads);
  for (int i = 0; i < runnerThreads; ++i) runners.emplace_back([&io] { io.run(); });

  // Everything a completion handler signals lives out here rather than on B's stack, so that B
  // returning cannot cut short a signal still being raised on a runner.
  Countdown handedOff(1);
  std::atomic<bool> destroyed = false;
  std::counting_semaphore<survivorOutstanding> outstanding(survivorOutstanding);
  Countdown answered(1);
  std::vector<CompletionOracle> survivorOracles;
  std::optional<CompletionOracle> afterDestruction;
  bool afterDestructionCompleted = false;

  // Thread B. It touches the doomed Client only before it hands off, and A destroys it only after,
  // so the handoff is the one thing keeping B off freed memory and it hides no race in the Client.
  std::thread initiator([&] {
    doomed->asyncGet(slowTarget(silent), publicCommunity, {sysDescr},
                     doomedOracles[0].handler(completes));
    doomed->asyncGet(retransmitting, publicCommunity, {sysDescr},
                     doomedOracles[1].handler(completes));
    doomed->asyncGet(discovering, credentials(), {sysDescr}, doomedOracles[2].handler(completes));
    doomed->asyncWalkCollect(slowTarget(walked), publicCommunity, systemGroup, WalkOptions{2},
                             doomedOracles[3].handler(completes));
    for (const auto& wait : inWait) std::ignore = wait.waitFor(longDeadline);
    for (std::size_t i = 0; i < lastMinuteRequests; ++i) {
      doomed->asyncGet(slowTarget(silent), publicCommunity, {sysDescr},
                       doomedOracles[waitNames.size() + i].handler(completes));
    }
    const auto initiateOnSurvivor = [&] {
      survivorOracles.emplace_back(io);
      survivor.asyncGet(
          slowTarget(answering), publicCommunity, {sysDescr},
          survivorOracles.back().handler(
              [&outstanding](net::ErrorCode, const Response&) { outstanding.release(); }));
    };
    // One of the survivor's requests is outstanding before the handoff, so destruction always has
    // one to disturb however B is scheduled after it. Nothing is in flight yet, so this never
    // waits.
    outstanding.acquire();
    initiateOnSurvivor();
    handedOff.countDown();

    while (!destroyed && outstanding.try_acquire_for(longDeadline)) initiateOnSurvivor();

    afterDestruction.emplace(io);
    survivor.asyncGet(slowTarget(answering), publicCommunity, {sysDescr},
                      afterDestruction->handler(
                          [&answered](net::ErrorCode, const Response&) { answered.countDown(); }));
    afterDestructionCompleted = answered.waitFor(longDeadline);
    // The loop's last requests may still be outstanding; the survivor is stopped only once they
    // are not, or one would complete with ClientStopped for a reason that is not this test's. The
    // limit outlasts their deadlines, so one that never had a reply shows up as Timeout.
    for (std::ptrdiff_t i = 0; i < survivorOutstanding; ++i)
      std::ignore = outstanding.try_acquire_for(2 * longDeadline);
  });

  // Thread A, this one.
  std::array<bool, waitNames.size()> reached{};
  for (std::size_t i = 0; i < inWait.size(); ++i)
    reached.at(i) = inWait.at(i).waitFor(longDeadline);
  const bool wasHandedOff = handedOff.waitFor(longDeadline);
  doomed.reset();
  destroyed = true;
  // Well before any of the deadlines, or it was a deadline that ended a request.
  const bool doomedFinished = doomedCompleted.waitFor(longDeadline / 2);

  initiator.join();
  survivor.stop();
  for (auto* agent : {&silent, &retransmitted, &walked, &answering})
    net::asio::dispatch(agent->executor(), [agent] { agent->close(); });
  net::asio::dispatch(withholding.executor(), [&withholding] { withholding.close(); });
  for (auto& runner : runners) runner.join();

  for (std::size_t i = 0; i < reached.size(); ++i)
    EXPECT_TRUE(reached.at(i)) << "the doomed Client's request never reached " << waitNames.at(i);
  if (testing::Test::HasFailure()) return;
  ASSERT_TRUE(wasHandedOff) << "thread B never handed off";
  EXPECT_TRUE(doomedFinished) << "the doomed Client's requests were still outstanding";
  for (std::size_t i = 0; i < doomedOracles.size(); ++i) {
    EXPECT_TRUE(doomedOracles[i].completedExactlyOnce({make_error_code(Errc::ClientStopped)}))
        << "the doomed Client's request " << i;
  }
  for (std::size_t i = 0; i < survivorOracles.size(); ++i) {
    EXPECT_TRUE(survivorOracles[i].completedExactlyOnce({net::ErrorCode{}}))
        << "the survivor's request " << i;
  }
  EXPECT_TRUE(afterDestructionCompleted) << "the survivor's request after destruction never ended";
  ASSERT_TRUE(afterDestruction.has_value());
  EXPECT_TRUE(afterDestruction->completedExactlyOnce({net::ErrorCode{}}))
      << "the survivor's request after destruction";
}

TEST(ClientLifetime, DestroyedWhileOtherThreadsRunAndInitiate) {
  for (int round = 0; round < destructionRounds; ++round) {
    destroyWhileOthersRunAndInitiate(round);
    // One failing round says what the rest would, and each waits out its limits to say it.
    if (testing::Test::HasFailure()) return;
  }
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

// Five Batches' worth at WalkOptions{2}, so a Walk is still going after its first.
std::vector<Varbind> tenRows() {
  std::vector<Varbind> rows;
  for (std::uint32_t i = 1; i <= 10; ++i)
    rows.emplace_back(systemGroup.child(i).child(0), Gauge32{i});
  return rows;
}

// What happened to a Walk whose first Batch handler was blocked while another thread stopped the
// Client, as seen by each of the three threads involved.
struct BlockedBatchOutcome {
  bool stopperReturnedBeforeHandler = false;
  int batches = 0;
  std::optional<net::ErrorCode> result;
};

// ADR-0009's amendment: Stopping on one thread waits for a Batch already being delivered on
// another, so that once it returns the handler has finished and none follows. The handler signals
// that it has started and then blocks until released; `stopClient` stops the Client meanwhile, on a
// thread of its own. The release is held back long enough for a Stopping that does not wait to
// have returned, so that one fails here unless its thread stalls for longer. A Stopping that does
// wait passes however long the release takes, because it cannot return before the handler does.
BlockedBatchOutcome stopWhileABatchIsBlocked(
    const std::function<void(std::optional<Client>&)>& stopClient) {
  net::IoContext io;
  ScriptedAgent agent(io, tableAgent(tenRows()));
  std::optional<Client> client{std::in_place, io.get_executor()};
  std::latch started{1};
  std::latch release{1};
  std::atomic<int> batches = 0;
  std::atomic<bool> handlerReturned = false;
  std::promise<net::ErrorCode> result;

  client->asyncWalk(
      targetFor(agent), publicCommunity, systemGroup, WalkOptions{2},
      [&](std::span<const Varbind>) {
        if (++batches == 1) {
          started.count_down();
          release.wait();
          handlerReturned = true;
        }
        return true;
      },
      [&](net::ErrorCode ec) {
        result.set_value(ec);
        agent.close();
      });
  std::thread runner([&io] { io.run(); });

  BlockedBatchOutcome outcome;
  started.wait();
  std::promise<void> ended;
  std::thread stopper([&] {
    stopClient(client);
    outcome.stopperReturnedBeforeHandler = !handlerReturned;
    ended.set_value();
  });
  std::ignore = ended.get_future().wait_for(std::chrono::milliseconds(200));
  release.count_down();
  stopper.join();

  auto completion = result.get_future();
  if (completion.wait_for(longDeadline) == std::future_status::ready)
    outcome.result = completion.get();
  net::asio::post(io, [&agent] { agent.close(); });
  runner.join();
  outcome.batches = batches;
  return outcome;
}

TEST(ClientLifetime, DestructionWaitsForABatchBeingDeliveredOnAnotherThread) {
  const auto outcome = stopWhileABatchIsBlocked([](std::optional<Client>& c) { c.reset(); });

  EXPECT_FALSE(outcome.stopperReturnedBeforeHandler)
      << "~Client returned while the Batch handler was running";
  EXPECT_EQ(outcome.batches, 1) << "a Batch was delivered after destruction began";
  ASSERT_TRUE(outcome.result.has_value()) << "the Walk never completed";
  EXPECT_EQ(*outcome.result, Errc::ClientStopped);
}

TEST(ClientLifetime, StopWaitsForABatchBeingDeliveredOnAnotherThread) {
  const auto outcome = stopWhileABatchIsBlocked([](std::optional<Client>& c) { c->stop(); });

  EXPECT_FALSE(outcome.stopperReturnedBeforeHandler)
      << "stop() returned while the Batch handler was running";
  EXPECT_EQ(outcome.batches, 1) << "a Batch was delivered after stop()";
  ASSERT_TRUE(outcome.result.has_value()) << "the Walk never completed";
  EXPECT_EQ(*outcome.result, Errc::ClientStopped);
}

// The other half of the rule: the delivering thread never waits for itself, or destroying a Client
// from its own Batch handler would deadlock.
TEST(ClientLifetime, DestroyedFromItsOwnBatchHandlerDoesNotWaitForIt) {
  net::IoContext io;
  ScriptedAgent agent(io, tableAgent(tenRows()));
  std::optional<Client> client{std::in_place, io.get_executor()};
  int batches = 0;
  std::optional<net::ErrorCode> result;

  client->asyncWalk(
      targetFor(agent), publicCommunity, systemGroup, WalkOptions{2},
      [&](std::span<const Varbind>) {
        ++batches;
        client.reset();
        return true;
      },
      [&](net::ErrorCode ec) {
        result = ec;
        agent.close();
      });
  io.run();

  EXPECT_EQ(batches, 1);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, Errc::ClientStopped);
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
