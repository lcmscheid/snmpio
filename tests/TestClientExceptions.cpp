#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <new>
#include <optional>
#include <thread>

#include <snmpio/Client.hpp>
#include <snmpio/Usm.hpp>

#include "FailingAllocation.hpp"
#include "ScriptedV3Agent.hpp"

// Threat model L7: an exception escaping the Client's own coroutines leaves io_context::run(),
// and never strands an Outstanding Request in silence. Nothing in the Client throws by design, so
// these tests make an allocation fail on purpose (FailingAllocation.hpp).

namespace snmpio {
namespace {

using test::FailingAllocation;
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

Target longDeadlineTarget(const ScriptedV3Agent& agent) {
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

}  // namespace
}  // namespace snmpio
