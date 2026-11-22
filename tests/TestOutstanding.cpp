#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <future>
#include <latch>
#include <optional>
#include <span>
#include <thread>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/detail/OutstandingView.hpp>

#include "Deadlines.hpp"
#include "DeriverHold.hpp"
#include "OutstandingReads.hpp"
#include "ScriptedAgent.hpp"
#include "ScriptedV3Agent.hpp"

// detail::OutstandingView, the tests' window onto what a Client still holds for its Outstanding
// Requests (#51). The disruption matrix, the soak and the destruction tests assert that it reads
// zero once they are done; these pin that it reads more than zero while there is something to
// hold, so that a view stuck at zero cannot pass them. Every read is from a handler on the one
// io_context the Client runs on, or after run() has returned, as the view requires.
namespace snmpio {
namespace {

using detail::OutstandingCounts;
using detail::OutstandingView;
using test::DeriverHold;
using test::echoAnswer;
using test::longDeadlineTarget;
using test::readOnStrand;
using test::respondWith;
using test::ScriptedAgent;
using test::ScriptedV3Agent;

const Community publicCommunity{Community("public")};
const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};

Credentials credentials() {
  return Credentials{"bert",       SecurityLevel::AuthPriv, AuthProtocol::Sha256,
                     "maplesyrup", PrivProtocol::Aes128,    "privatepass"};
}

// One io_context on the test thread, stopped once every request has completed.
struct Fixture {
  net::IoContext io;
  Client client{io.get_executor()};
  std::function<void()> closeAgent = [] {};
  int expected = 1;
  int completions = 0;

  // Read at the last completion, before stop(), so that what it says settled on its own rather
  // than being cleared by Stopping.
  std::optional<OutstandingCounts> heldAtTheEnd;

  void completed() {
    if (++completions < expected) return;
    heldAtTheEnd = OutstandingView::counts(client);
    client.stop();
    closeAgent();
  }

  auto token() {
    return [this](net::ErrorCode ec, const Response&) {
      EXPECT_FALSE(ec) << ec.message();
      completed();
    };
  }

  void run() {
    io.run();
    EXPECT_EQ(completions, expected) << "a request never completed";
    ASSERT_TRUE(heldAtTheEnd.has_value());
    EXPECT_EQ(*heldAtTheEnd, OutstandingCounts{}) << "still held at the last completion";
  }
};

// Reads the view on the test's one io_context until it says `expected`, or until the limit, and
// hands over what it last read. A read at a fixed moment would race a slow runner to the state it
// expects; this waits for the state, and only one that never comes fails the comparison after.
class Poll {
 public:
  Poll(net::IoContext& io, const Client& client) : m_timer(io), m_client(&client) {}

  void until(const OutstandingCounts& expected, std::function<void(OutstandingCounts)> then) {
    m_expected = expected;
    m_then = std::move(then);
    m_giveUpAt = std::chrono::steady_clock::now() + test::longDeadline;
    step();
  }

 private:
  void step() {
    const auto counts = OutstandingView::counts(*m_client);
    if (counts == m_expected || std::chrono::steady_clock::now() >= m_giveUpAt) {
      // Moved out first, so that `then` may start the next poll.
      const auto then = std::exchange(m_then, nullptr);
      then(counts);
      return;
    }
    m_timer.expires_after(std::chrono::milliseconds(1));
    m_timer.async_wait([this](net::ErrorCode ec) {
      if (!ec) step();
    });
  }

  net::SteadyTimer m_timer;
  const Client* m_client;
  OutstandingCounts m_expected;
  std::function<void(OutstandingCounts)> m_then;
  std::chrono::steady_clock::time_point m_giveUpAt;
};

TEST(Outstanding, AnExchangeAwaitingAReplyIsHeldUntilItIsAnswered) {
  Fixture f;
  std::optional<OutstandingCounts> whileAsked;
  ScriptedAgent agent(f.io, [&](const V2cMessage& msg) {
    whileAsked = OutstandingView::counts(f.client);
    return respondWith({Varbind{msg.pdu.varbinds.at(0).name, null}});
  });
  f.closeAgent = [&agent] { agent.close(); };

  f.client.asyncGet(longDeadlineTarget(agent), publicCommunity, {sysDescr}, f.token());
  f.run();

  ASSERT_TRUE(whileAsked.has_value());
  EXPECT_EQ(*whileAsked, (OutstandingCounts{.exchanges = 1}));
}

// One exchange however many Message IDs it has been sent under: a retransmission maps a second.
TEST(Outstanding, ARetransmittedExchangeIsStillOne) {
  Fixture f;
  std::optional<OutstandingCounts> atRetransmission;
  ScriptedAgent* self = nullptr;
  ScriptedAgent agent(f.io, [&, attempts = 0](const V2cMessage& msg) mutable -> std::optional<Pdu> {
    if (++attempts == 1) return std::nullopt;
    atRetransmission = OutstandingView::counts(f.client);
    self->answerLate(msg, respondWith({Varbind{msg.pdu.varbinds.at(0).name, null}}));
    return std::nullopt;
  });
  self = &agent;
  f.closeAgent = [&agent] { agent.close(); };

  auto target = test::targetFor(agent, 1);
  target.timeout = std::chrono::milliseconds(50);
  f.client.asyncGet(target, publicCommunity, {sysDescr}, f.token());
  f.run();

  ASSERT_TRUE(atRetransmission.has_value());
  EXPECT_EQ(*atRetransmission, (OutstandingCounts{.exchanges = 1}));
}

// Two requests to an undiscovered Engine queue behind one Engine Discovery, as its waiters; the
// exchange is the identity phase's.
TEST(Outstanding, RequestsQueuedBehindADiscoveryAreItsWaiters) {
  Fixture f;
  f.expected = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  std::optional<OutstandingCounts> atIdentityPhase;
  agent.setOnDatagram([&, datagrams = 0](std::span<const std::byte>) mutable {
    if (datagrams++ == 0) atIdentityPhase = OutstandingView::counts(f.client);
  });
  f.closeAgent = [&agent] { agent.close(); };

  const auto target = longDeadlineTarget(agent);
  f.client.asyncGet(target, credentials(), {sysDescr}, f.token());
  f.client.asyncGet(target, credentials(), {sysDescr}, f.token());
  f.run();

  ASSERT_TRUE(atIdentityPhase.has_value());
  EXPECT_EQ(*atIdentityPhase, (OutstandingCounts{.exchanges = 1, .discoveries = 1, .waiters = 2}));
}

// With the Deriver held, the discovery gets past its identity phase and then parks on the Master
// Key its time-sync phase needs: the derivation's waiter, beside the two requests parked on the
// discovery. The Deriver is let go only once that has been read.
TEST(Outstanding, ADiscoveryWaitingOnADerivationIsTheDerivationsWaiter) {
  Fixture f;
  f.expected = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.closeAgent = [&agent] { agent.close(); };
  DeriverHold hold(f.client);

  const auto target = longDeadlineTarget(agent);
  f.client.asyncGet(target, credentials(), {sysDescr}, f.token());
  f.client.asyncGet(target, credentials(), {sysDescr}, f.token());
  const OutstandingCounts parked{.discoveries = 1, .derivations = 1, .waiters = 3};
  std::optional<OutstandingCounts> whileHeld;
  Poll poll(f.io, f.client);
  poll.until(parked, [&](OutstandingCounts counts) {
    whileHeld = counts;
    hold.release();
  });
  f.run();

  ASSERT_TRUE(whileHeld.has_value());
  EXPECT_EQ(*whileHeld, parked);
}

// A request cancelled out of a discovery leaves at once, and stops being its waiter; the discovery
// carries on (ADR-0003), and once it has settled nothing is held. The cancellation goes out only
// once both requests are parked, and the Deriver is let go only once the cancelled one has left.
TEST(Outstanding, ARequestCancelledOutOfADiscoveryStopsWaitingOnIt) {
  Fixture f;
  f.expected = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.closeAgent = [&agent] { agent.close(); };
  DeriverHold hold(f.client);

  net::asio::cancellation_signal signal;
  const auto target = longDeadlineTarget(agent);
  f.client.asyncGet(
      target, credentials(), {sysDescr},
      net::asio::bind_cancellation_slot(signal.slot(), [&f](net::ErrorCode ec, const Response&) {
        EXPECT_EQ(ec, net::asio::error::operation_aborted) << ec.message();
        f.completed();
      }));
  f.client.asyncGet(target, credentials(), {sysDescr}, f.token());
  const OutstandingCounts bothParked{.discoveries = 1, .derivations = 1, .waiters = 3};
  const OutstandingCounts oneLeft{.discoveries = 1, .derivations = 1, .waiters = 2};
  std::optional<OutstandingCounts> beforeCancel;
  std::optional<OutstandingCounts> afterCancel;
  Poll poll(f.io, f.client);
  poll.until(bothParked, [&](OutstandingCounts counts) {
    beforeCancel = counts;
    signal.emit(net::asio::cancellation_type::terminal);
    poll.until(oneLeft, [&](OutstandingCounts after) {
      afterCancel = after;
      hold.release();
    });
  });
  f.run();

  ASSERT_TRUE(beforeCancel.has_value());
  EXPECT_EQ(*beforeCancel, bothParked);
  ASSERT_TRUE(afterCancel.has_value());
  EXPECT_EQ(*afterCancel, oneLeft);
}

// The read the soak and the destruction tests make while other threads run the Client: posted to
// its strand, from a thread that is not running it. It sees an exchange still awaiting its reply,
// and nothing once the request has completed -- before stop(), so settled rather than cleared.
TEST(Outstanding, AReadOnTheStrandSeesWhatOtherThreadsLeaveHeld) {
  net::IoContext io;
  auto work = net::asio::make_work_guard(io);
  Client client(io.get_executor());
  std::latch asked(1);
  std::optional<V2cMessage> question;
  ScriptedAgent agent(io, [&](const V2cMessage& msg) -> std::optional<Pdu> {
    question = msg;
    asked.count_down();
    return std::nullopt;
  });
  constexpr int runnerCount = 4;
  std::vector<std::thread> runners;
  runners.reserve(runnerCount);
  for (int i = 0; i < runnerCount; ++i) runners.emplace_back([&io] { io.run(); });

  std::promise<net::ErrorCode> completed;
  client.asyncGet(longDeadlineTarget(agent), publicCommunity, {sysDescr},
                  [&completed](net::ErrorCode ec, const Response&) { completed.set_value(ec); });
  asked.wait();
  const auto whileAsked = readOnStrand(client);
  net::asio::dispatch(agent.executor(),
                      [&] { agent.answerLate(*question, respondWith({Varbind{sysDescr, null}})); });
  auto answer = completed.get_future();
  const bool answered = answer.wait_for(test::longDeadline) == std::future_status::ready;
  const auto afterAnswer = readOnStrand(client);

  client.stop();
  net::asio::dispatch(agent.executor(), [&agent] { agent.close(); });
  work.reset();
  for (auto& runner : runners) runner.join();

  ASSERT_TRUE(whileAsked.has_value()) << "the strand never ran the read";
  EXPECT_EQ(*whileAsked, (OutstandingCounts{.exchanges = 1}));
  ASSERT_TRUE(answered) << "the request never completed";
  EXPECT_FALSE(answer.get()) << "the request failed";
  ASSERT_TRUE(afterAnswer.has_value()) << "the strand never ran the read";
  EXPECT_EQ(*afterAnswer, OutstandingCounts{});
}

}  // namespace
}  // namespace snmpio
