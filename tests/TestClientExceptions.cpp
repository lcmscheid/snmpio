#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <new>
#include <optional>
#include <thread>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/Usm.hpp>

#include "FailingAllocation.hpp"
#include "ScriptedAgent.hpp"
#include "ScriptedV3Agent.hpp"

// Threat model L7: an exception escaping the Client's own coroutines leaves io_context::run(),
// and never strands an Outstanding Request in silence. Nothing in the Client throws by design, so
// these tests make an allocation fail on purpose (FailingAllocation.hpp).

namespace snmpio {
namespace {

using test::FailingAllocation;
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

// Long enough that a request ended by its deadline rather than by the exception shows up as a
// completion, short enough not to hang the suite if one queues forever.
constexpr auto longDeadline = std::chrono::seconds(5);

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

template <typename Agent>
Target longDeadlineTarget(const Agent& agent) {
  auto t = test::targetFor(agent, 0);
  t.timeout = longDeadline;
  return t;
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

}  // namespace
}  // namespace snmpio
