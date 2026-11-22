#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <optional>
#include <span>

#include <snmpio/Client.hpp>
#include <snmpio/detail/OutstandingView.hpp>

#include "Deadlines.hpp"
#include "DeriverHold.hpp"
#include "OutstandingPrinter.hpp"
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
using test::derivationHeld;
using test::DeriverHold;
using test::longDeadlineTarget;
using test::respondWith;
using test::ScriptedAgent;
using test::ScriptedV3Agent;

const Community publicCommunity{Community("public")};
const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};

Credentials credentials() {
  return Credentials{"bert",       SecurityLevel::AuthPriv, AuthProtocol::Sha256,
                     "maplesyrup", PrivProtocol::Aes128,    "privatepass"};
}

Pdu echoAnswer(const Pdu& request) {
  Pdu p;
  p.type = PduType::Response;
  p.varbinds = request.varbinds;
  return p;
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
// Key its time-sync phase needs: a waiter too, beside the two requests parked on the discovery.
TEST(Outstanding, ADiscoveryWaitingOnADerivationIsOneOfItsWaiters) {
  Fixture f;
  f.expected = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.closeAgent = [&agent] { agent.close(); };
  DeriverHold hold(f.client);
  hold.releaseAfter(f.io, derivationHeld);

  const auto target = longDeadlineTarget(agent);
  f.client.asyncGet(target, credentials(), {sysDescr}, f.token());
  f.client.asyncGet(target, credentials(), {sysDescr}, f.token());
  std::optional<OutstandingCounts> whileHeld;
  net::SteadyTimer check(f.io, derivationHeld / 2);
  check.async_wait([&](net::ErrorCode) { whileHeld = OutstandingView::counts(f.client); });
  f.run();

  ASSERT_TRUE(whileHeld.has_value());
  EXPECT_EQ(*whileHeld, (OutstandingCounts{.discoveries = 1, .derivations = 1, .waiters = 3}));
}

// A request cancelled out of a discovery leaves at once, and stops being its waiter; the discovery
// carries on (ADR-0003), and once it has settled nothing is held.
TEST(Outstanding, ARequestCancelledOutOfADiscoveryStopsWaitingOnIt) {
  Fixture f;
  f.expected = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.closeAgent = [&agent] { agent.close(); };
  DeriverHold hold(f.client);
  hold.releaseAfter(f.io, derivationHeld);

  net::asio::cancellation_signal signal;
  const auto target = longDeadlineTarget(agent);
  f.client.asyncGet(
      target, credentials(), {sysDescr},
      net::asio::bind_cancellation_slot(signal.slot(), [&f](net::ErrorCode ec, const Response&) {
        EXPECT_EQ(ec, net::asio::error::operation_aborted) << ec.message();
        f.completed();
      }));
  f.client.asyncGet(target, credentials(), {sysDescr}, f.token());
  std::optional<OutstandingCounts> afterCancel;
  net::SteadyTimer cancelAt(f.io, derivationHeld / 4);
  cancelAt.async_wait(
      [&signal](net::ErrorCode) { signal.emit(net::asio::cancellation_type::terminal); });
  net::SteadyTimer check(f.io, derivationHeld / 2);
  check.async_wait([&](net::ErrorCode) { afterCancel = OutstandingView::counts(f.client); });
  f.run();

  ASSERT_TRUE(afterCancel.has_value());
  EXPECT_EQ(*afterCancel, (OutstandingCounts{.discoveries = 1, .derivations = 1, .waiters = 2}));
}

}  // namespace
}  // namespace snmpio
