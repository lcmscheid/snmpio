#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/Usm.hpp>
#include <snmpio/detail/MessageIdView.hpp>

#include "CompletionOracle.hpp"
#include "Deadlines.hpp"
#include "FailingAllocation.hpp"
#include "ScriptedAgent.hpp"
#include "ScriptedV3Agent.hpp"

// Threat model L7: an exception escaping the Client's own coroutines leaves io_context::run(),
// and never strands an Outstanding Request in silence. Nothing in the Client throws by design, so
// these tests make an allocation fail on purpose (FailingAllocation.hpp), or an executor throw.

namespace snmpio {
namespace {

using test::FailingAllocation;
using test::longDeadline;
using test::longDeadlineTarget;
using test::ScriptedAgent;
using test::ScriptedV3Agent;

const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};

// The size of a SHA-224 Master Key, 28 bytes, which nothing else on the Client's thread allocates
// before the discovery derives one for its time-sync phase. The passwords and the user name below
// are short enough to stay inside std::string, and no Client type is 28 bytes. A decoded Oid can
// be: the decoder reserves one 32-bit word per content byte plus one, so any OID encoded in 6
// bytes takes 28. sysDescr and the usmStats Reports encode in 8 and 10, which is why they are
// safe here; one of 6 decoded first would take the failure, and the test would fail, not pass.
const std::size_t masterKeySize = keySize(AuthProtocol::Sha224);

Credentials credentials() {
  return Credentials{"bert",       SecurityLevel::AuthNoPriv, AuthProtocol::Sha224,
                     "maplesyrup", PrivProtocol::None,        ""};
}

Pdu echoAnswer(const Pdu& request) {
  Pdu p;
  p.type = PduType::Response;
  for (const auto& vb : request.varbinds) {
    p.varbinds.push_back(Varbind{vb.name, Octets{std::byte{'o'}, std::byte{'k'}}});
  }
  return p;
}

TEST(ClientExceptions, ADiscoveryThatThrowsSurfacesForEachWaiterAndLeavesNoneQueued) {
  if (!FailingAllocation::available()) GTEST_SKIP() << "this build cannot replace operator new";
  net::IoContext agentIo;
  ScriptedV3Agent agent(agentIo, credentials(), echoAnswer);
  // On a thread of its own, so that nothing the Agent allocates can be the allocation that fails:
  // it holds the same key, and copies it to answer each request.
  // Only an Engine Discovery's first message names no engineID, so counting those counts
  // discoveries. Set before the Agent's thread starts, which is what orders it with the reads
  // there.
  int discoveries = 0;
  agent.setResponder([&agent, &discoveries](const ScriptedV3Agent::Request& req) {
    if (req.message.security.engineId.empty()) ++discoveries;
    return agent.behaveLikeACompliantAgent(req);
  });
  std::thread agentThread([&agentIo] { agentIo.run(); });

  net::IoContext io;
  Client client(io.get_executor());
  int queuedCompletions = 0;
  const auto queued = [&queuedCompletions](net::ErrorCode, const Response&) {
    ++queuedCompletions;
  };
  // The first starts the discovery and the second queues behind it. Both wait on it.
  client.asyncGet(longDeadlineTarget(agent), credentials(), {sysDescr}, queued);
  client.asyncGet(longDeadlineTarget(agent), credentials(), {sysDescr}, queued);

  std::optional<net::ErrorCode> later;
  int thrown = 0;
  {
    const FailingAllocation failing(masterKeySize);
    const auto deadline = std::chrono::steady_clock::now() + longDeadline;
    while (!later && std::chrono::steady_clock::now() < deadline) {
      try {
        io.run_until(deadline);
      } catch (const std::bad_alloc&) {
        // Issued once the discovery has thrown, so it either starts a discovery of its own or
        // queues behind the one that threw, which will never finish.
        if (++thrown > 1) continue;
        client.asyncGet(longDeadlineTarget(agent), credentials(), {sysDescr},
                        [&later, &client](net::ErrorCode ec, const Response&) {
                          later = ec;
                          client.stop();
                        });
      }
    }
    EXPECT_TRUE(failing.fired()) << "no allocation of the key's size was made";
  }
  net::asio::post(agentIo, [&agent] { agent.close(); });
  agentThread.join();

  // Once for the discovery and once for each request waiting on it, each on its own call to run().
  EXPECT_EQ(thrown, 3);
  EXPECT_EQ(queuedCompletions, 0) << "a request waiting on the discovery completed instead";
  ASSERT_TRUE(later.has_value()) << "a later request queued behind the discovery that threw";
  EXPECT_FALSE(*later) << later->message();
  EXPECT_EQ(discoveries, 2) << "the later request did not start a discovery of its own";
}

// The size of the one OCTET STRING the Agent below answers with, which the decoder copies into a
// vector of exactly that many bytes. Odd, so nothing holding a pointer is this size, and nothing
// else on the Client's thread is: the request it encodes is a few dozen bytes, and the receive
// buffer is a whole datagram.
constexpr std::size_t oversizedValueSize = 333;

const Oid oversizedInstance{1, 3, 6, 1, 4, 1, 99999, 1};

// A receive loop belongs to a socket, not to any one Target, so the fault is the Client's own and
// it stops (CONTEXT.md, Stopping; #63).
TEST(ClientExceptions, AReceiveLoopThatThrowsStopsTheClient) {
  if (!FailingAllocation::available()) GTEST_SKIP() << "this build cannot replace operator new";
  net::IoContext agentIo;
  // Answers only the request for oversizedInstance, with a value whose decoding fails, and leaves
  // the other outstanding. On a thread of its own, because it encodes the same value to answer.
  ScriptedAgent agent(agentIo, [](const V2cMessage& msg) -> std::optional<Pdu> {
    if (msg.pdu.varbinds.at(0).name != oversizedInstance) return std::nullopt;
    return test::respondWith(
        {Varbind{oversizedInstance, Octets(oversizedValueSize, std::byte{'x'})}});
  });
  std::thread agentThread([&agentIo] { agentIo.run(); });

  net::IoContext io;
  Client client(io.get_executor());
  const auto target = longDeadlineTarget(agent);
  std::vector<net::ErrorCode> completions;
  const auto record = [&completions](net::ErrorCode ec, const Response&) {
    completions.push_back(ec);
  };
  // The one whose reply throws, and one on the same socket left waiting behind it.
  client.asyncGet(target, Community("public"), {oversizedInstance}, record);
  client.asyncGet(target, Community("public"), {sysDescr}, record);

  int thrown = 0;
  {
    const FailingAllocation failing(oversizedValueSize);
    const auto deadline = std::chrono::steady_clock::now() + longDeadline;
    while (completions.size() < 3 && std::chrono::steady_clock::now() < deadline) {
      try {
        io.run_until(deadline);
      } catch (const std::bad_alloc&) {
        // Issued once the loop has thrown: it must be refused, not sent on a socket nobody reads.
        if (++thrown == 1) client.asyncGet(target, Community("public"), {sysDescr}, record);
      }
    }
    EXPECT_TRUE(failing.fired()) << "no allocation of the value's size was made";
  }
  net::asio::post(agentIo, [&agent] { agent.close(); });
  agentThread.join();

  EXPECT_EQ(thrown, 1);
  ASSERT_EQ(completions.size(), 3U) << "a request was left waiting out its deadline";
  for (const auto& ec : completions) EXPECT_EQ(ec, Errc::ClientStopped) << ec.message();
  EXPECT_EQ(agent.requestsSeen(), 2) << "the request after the throw was sent";
}

// ber::Writer's opening reservation for a v2c message: the first allocation encoding one makes,
// whatever the request-id. Between the first transmission and the retransmission nothing else on
// the Client's thread asks for 256 bytes -- the Agent is silent and runs on a thread of its own,
// and Asio's timers do not allocate through operator new -- and failing.fired() checks it.
constexpr std::size_t v2cEncoderReservation = 256;

// An exception thrown encoding a retransmission leaves run() (L7), and takes no ID with it: the
// first transmission's must not stay mapped for the rest of the Client's life.
TEST(ClientExceptions, ARetransmissionThatThrowsLeavesNoIdMapped) {
  if (!FailingAllocation::available()) GTEST_SKIP() << "this build cannot replace operator new";
  net::IoContext agentIo;
  std::atomic<int> seen{0};
  ScriptedAgent agent(agentIo, [&seen](const V2cMessage&) -> std::optional<Pdu> {
    ++seen;
    return std::nullopt;
  });
  std::thread agentThread([&agentIo] { agentIo.run(); });

  net::IoContext io;
  Client client(io.get_executor());
  // Long enough that the failure is armed well before the retransmission is due.
  auto target = test::targetFor(agent, 1);
  target.timeout = std::chrono::milliseconds(500);
  client.asyncGet(target, Community("public"), {sysDescr}, [](net::ErrorCode ec, const Response&) {
    ADD_FAILURE() << "completed with " << ec.message() << " rather than throwing";
  });

  const auto deadline = std::chrono::steady_clock::now() + longDeadline;
  while (seen.load() == 0 && std::chrono::steady_clock::now() < deadline) {
    io.run_one_for(std::chrono::milliseconds(5));
  }
  ASSERT_EQ(seen.load(), 1) << "the first transmission never arrived";
  EXPECT_EQ(detail::MessageIdView::outstandingIds(client), 1U);

  int thrown = 0;
  {
    const FailingAllocation failing(v2cEncoderReservation);
    try {
      io.run_until(deadline);
    } catch (const std::bad_alloc&) {
      ++thrown;
    }
    EXPECT_TRUE(failing.fired()) << "no allocation of the encoder's size was made";
  }
  net::asio::post(agentIo, [&agent] { agent.close(); });
  agentThread.join();

  EXPECT_EQ(thrown, 1);
  EXPECT_EQ(seen.load(), 1) << "the retransmission went out";
  EXPECT_EQ(detail::MessageIdView::outstandingIds(client), 0U);
}

// The thread an armed ThrowingExecutor throws on, or none. Shared by every copy of one executor.
using ArmedFor = std::atomic<std::thread::id>;

// What ThrowingExecutor throws: scheduling failed, which is all stop() could be told.
struct SchedulingFailed : std::runtime_error {
  SchedulingFailed() : std::runtime_error("scheduling failed") {}
};

// An executor that forwards everything to Inner, and throws from execute() while armed for the
// calling thread. Thread-specific so that nothing the io_context's own thread schedules meanwhile
// -- a timer's completion reaching the strand -- is the call that throws (#66).
template <typename Inner>
class ThrowingExecutor {
 public:
  ThrowingExecutor(Inner inner, std::shared_ptr<ArmedFor> armed) noexcept
      : m_inner(std::move(inner)), m_armed(std::move(armed)) {}

  template <typename F>
  void execute(F&& f) const {
    if (m_armed->load() == std::this_thread::get_id()) throw SchedulingFailed{};
    m_inner.execute(std::forward<F>(f));
  }

  template <typename Property>
  [[nodiscard]] auto query(const Property& p) const
      -> decltype(net::asio::query(std::declval<Inner>(), p)) {
    return net::asio::query(m_inner, p);
  }

  template <typename Property>
  [[nodiscard]] auto require(const Property& p) const
      -> ThrowingExecutor<std::decay_t<decltype(net::asio::require(std::declval<Inner>(), p))>> {
    return {net::asio::require(m_inner, p), m_armed};
  }

  template <typename Property>
  [[nodiscard]] auto prefer(const Property& p) const
      -> ThrowingExecutor<std::decay_t<decltype(net::asio::prefer(std::declval<Inner>(), p))>> {
    return {net::asio::prefer(m_inner, p), m_armed};
  }

  [[nodiscard]] friend bool operator==(const ThrowingExecutor& a,
                                       const ThrowingExecutor& b) noexcept {
    return a.m_inner == b.m_inner && a.m_armed == b.m_armed;
  }

 private:
  template <typename>
  friend class ThrowingExecutor;
  Inner m_inner;
  std::shared_ptr<ArmedFor> m_armed;
};

// What an explicit stop() leaves when scheduling its cleanup throws: the exception reaches the
// caller, and the strand never runs another handler, so nothing the Client owns completes again
// (ADR-0009's amendment has why, #66).
TEST(ClientExceptions, AStopWhoseCleanupCannotBeScheduledThrowsAndNothingCompletesAfter) {
  net::IoContext agentIo;
  std::atomic<int> seen{0};
  ScriptedAgent agent(agentIo, [&seen](const V2cMessage&) -> std::optional<Pdu> {
    ++seen;
    return std::nullopt;
  });
  std::thread agentThread([&agentIo] { agentIo.run(); });

  net::IoContext io;
  const auto armed = std::make_shared<ArmedFor>();
  Client client(net::Executor(ThrowingExecutor(io.get_executor(), armed)));
  auto work = net::asio::make_work_guard(io);
  std::thread ioThread([&io] { io.run(); });

  constexpr auto deadline = std::chrono::milliseconds(250);
  auto target = test::targetFor(agent, 0);
  target.timeout = deadline;
  test::CompletionOracle first(io);
  test::CompletionOracle second(io);
  const auto ignore = [](net::ErrorCode, const Response&) {};
  client.asyncGet(target, Community("public"), {sysDescr}, first.handler(ignore));
  client.asyncGet(target, Community("public"), {sysDescr}, second.handler(ignore));

  const auto giveUp = std::chrono::steady_clock::now() + longDeadline;
  while (seen.load() < 2 && std::chrono::steady_clock::now() < giveUp) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  ASSERT_EQ(seen.load(), 2) << "the two requests never arrived";

  // From this thread, not the io_context's, so the strand is idle and stop() has to schedule.
  armed->store(std::this_thread::get_id());
  EXPECT_THROW(client.stop(), SchedulingFailed);
  armed->store(std::thread::id{});

  test::CompletionOracle later(io);
  client.asyncGet(target, Community("public"), {sysDescr}, later.handler(ignore));
  EXPECT_NO_THROW(client.stop());

  // The io_context still runs handlers; the Client's strand does not.
  std::atomic<bool> onIo{false};
  std::atomic<bool> onStrand{false};
  net::asio::post(io, [&onIo] { onIo = true; });
  net::asio::post(client.getExecutor(), [&onStrand] { onStrand = true; });
  // Well past the Outstanding Requests' deadlines, which is when they would otherwise complete.
  std::this_thread::sleep_for(4 * deadline);
  work.reset();
  io.stop();
  ioThread.join();
  net::asio::post(agentIo, [&agent] { agent.close(); });
  agentThread.join();

  EXPECT_TRUE(onIo.load()) << "the io_context itself stopped running handlers";
  EXPECT_FALSE(onStrand.load()) << "the strand recovered; the Client may be usable after all";
  EXPECT_TRUE(first.invocations().empty()) << "an Outstanding Request completed";
  EXPECT_TRUE(second.invocations().empty()) << "an Outstanding Request completed";
  EXPECT_TRUE(later.invocations().empty()) << "the request after the stop completed";
  EXPECT_EQ(seen.load(), 2) << "the request after the stop was sent";
}

}  // namespace
}  // namespace snmpio
