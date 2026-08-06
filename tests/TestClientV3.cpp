#include <gtest/gtest.h>

#include <optional>
#include <vector>

#include <snmpio/Client.hpp>

#include "ScriptedV3Agent.hpp"

namespace snmpio {
namespace {

using test::ScriptedV3Agent;
using test::targetFor;

const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};
const Oid sysUpTime{1, 3, 6, 1, 2, 1, 1, 3, 0};

Credentials credentials(AuthProtocol protocol = AuthProtocol::Sha256,
                        SecurityLevel level = SecurityLevel::AuthNoPriv) {
  return Credentials{"bert", level, protocol, "maplesyrup"};
}

// The data plane every well-behaved case here uses: echo the requested OIDs back with a value.
Pdu echoAnswer(const Pdu& request) {
  Pdu p;
  p.type = PduType::Response;
  for (const auto& vb : request.varbinds) {
    p.varbinds.push_back(Varbind{vb.name, Octets{std::byte{'o'}, std::byte{'k'}}});
  }
  return p;
}

// Same shape as TestClient.cpp's: one io_context on the test thread, so a hung operation is a hung
// test rather than a flake.
struct Fixture {
  net::IoContext io;
  Client client{io.get_executor()};
  ScriptedV3Agent* agent = nullptr;

  net::ErrorCode ec;
  Response response;
  std::vector<Varbind> collected;
  int completions = 0;
  int expectedCompletions = 1;

  auto requestToken() {
    return [this](net::ErrorCode e, Response r) {
      ec = e;
      response = std::move(r);
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
    if (++completions < expectedCompletions) return;
    client.stop();
    if (agent != nullptr) agent->close();
  }

  void run() {
    io.run();
    EXPECT_EQ(completions, expectedCompletions) << "an operation never completed";
  }
};

TEST(ClientV3, DiscoversTheEngineAndThenAnswers) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  ASSERT_EQ(f.response.varbinds.size(), 1U);
  EXPECT_EQ(f.response.varbinds[0].name, sysDescr);
  // Two discovery exchanges -- the engineID, then the boots/time pair -- and then the request.
  EXPECT_EQ(agent.requestsSeen(), 3);
}

TEST(ClientV3, NoAuthNoPrivNeedsOnlyTheFirstDiscoveryPhase) {
  Fixture f;
  const auto creds = credentials(AuthProtocol::None, SecurityLevel::NoAuthNoPriv);
  ScriptedV3Agent agent(f.io, creds, echoAnswer);
  f.agent = &agent;

  f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(agent.requestsSeen(), 2);
}

TEST(ClientV3, ASecondRequestSendsNoProbe) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  const auto target = targetFor(agent);
  f.client.asyncGet(target, credentials(), {sysDescr}, [&](net::ErrorCode e, const Response&) {
    EXPECT_FALSE(e) << e.message();
    f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
    f.finish();
  });
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  // Three for the first request, one for the second: the Engine and its keys are cached.
  EXPECT_EQ(agent.requestsSeen(), 4);
}

TEST(ClientV3, ConcurrentRequestsShareOneDiscovery) {
  Fixture f;
  constexpr int requests = 5;
  f.expectedCompletions = requests;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  const auto target = targetFor(agent);
  for (int i = 0; i < requests; ++i) {
    f.client.asyncGet(target, credentials(), {sysDescr}, f.requestToken());
  }
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  // Not 5 discoveries: the four that arrived while the first was in flight queued behind it.
  EXPECT_EQ(agent.requestsSeen(), 2 + requests);
}

TEST(ClientV3, WorksUnderEveryAuthProtocol) {
  for (const auto protocol : {AuthProtocol::Md5, AuthProtocol::Sha1, AuthProtocol::Sha224,
                              AuthProtocol::Sha256, AuthProtocol::Sha384, AuthProtocol::Sha512}) {
    Fixture f;
    ScriptedV3Agent agent(f.io, credentials(protocol), echoAnswer);
    f.agent = &agent;

    f.client.asyncGet(targetFor(agent), credentials(protocol), {sysDescr}, f.requestToken());
    f.run();

    EXPECT_FALSE(f.ec) << "protocol " << static_cast<int>(protocol) << ": " << f.ec.message();
    EXPECT_EQ(f.response.varbinds.size(), 1U);
  }
}

// Everything below is the Agent misbehaving, which is the half of this that a correct one never
// reaches (ADR-0006).

TEST(ClientV3, ResynchronisesAfterANotInTimeWindowsReport) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  // The Engine reboots after discovery has already settled, so the pair we cached is stale by the
  // time the real request goes out. The resynchronisation and the retry are both invisible here.
  int authenticatedSeen = 0;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        const auto& usm = req.message.security;
        if (usm.engineId.empty()) {
          return ScriptedV3Agent::report(ScriptedV3Agent::unknownEngineIds,
                                         SecurityLevel::NoAuthNoPriv);
        }
        if (!isAuthenticated(req.message.header.level)) return std::nullopt;

        auto untimely = [](std::int32_t boots, std::int32_t time) {
          auto r =
              ScriptedV3Agent::report(ScriptedV3Agent::notInTimeWindows, SecurityLevel::AuthNoPriv);
          r.boots = boots;
          r.time = time;
          return r;
        };
        switch (++authenticatedSeen) {
          case 1:
            return untimely(3, 1000);  // discovery's second phase, answered honestly
          case 2:
            return untimely(9, 4242);  // and now it has rebooted
          default:
            break;
        }
        EXPECT_EQ(usm.boots, 9) << "the retry did not carry the resynchronised boots";
        EXPECT_GE(usm.time, 4242);

        ScriptedV3Agent::Reply reply;
        reply.level = req.message.header.level;
        reply.boots = 9;
        reply.time = 4242;
        reply.scoped.pdu = echoAnswer(req.message.scoped.pdu);
        return reply;
      });

  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(f.response.varbinds.size(), 1U);
}

TEST(ClientV3, FailsWhenTheEngineNeverAgreesOnTheTimeWindow) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setResponder([](const ScriptedV3Agent::Request& req) {
    if (req.message.security.engineId.empty()) {
      return std::optional(
          ScriptedV3Agent::report(ScriptedV3Agent::unknownEngineIds, SecurityLevel::NoAuthNoPriv));
    }
    return std::optional(
        ScriptedV3Agent::report(ScriptedV3Agent::notInTimeWindows, SecurityLevel::AuthNoPriv));
  });

  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, f.requestToken());
  f.run();

  // Two attempts and no more: an Engine that keeps disagreeing must not be able to loop us.
  EXPECT_EQ(f.ec, make_error_code(Errc::NotInTimeWindow));
}

TEST(ClientV3, SurfacesAnUnknownUserName) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  auto wrongUser = credentials();
  wrongUser.userName = "ernie";
  f.client.asyncGet(targetFor(agent), wrongUser, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::UnknownUserName));
}

TEST(ClientV3, SurfacesAWrongDigestReport) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  auto wrongPassword = credentials();
  wrongPassword.authPassword = "notthepassword";
  f.client.asyncGet(targetFor(agent), wrongPassword, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::AuthFailed));
}

TEST(ClientV3, DropsAResponseWhoseDigestDoesNotVerify) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (req.message.security.engineId.empty()) {
          return ScriptedV3Agent::report(ScriptedV3Agent::unknownEngineIds,
                                         SecurityLevel::NoAuthNoPriv);
        }
        if (!req.authenticated) return std::nullopt;
        ScriptedV3Agent::Reply reply;
        reply.level = req.message.header.level;
        reply.scoped.pdu = echoAnswer(req.message.scoped.pdu);
        // Signed with a key that is not this Agent's. Nobody who can forge a datagram should be
        // able to fail somebody else's request, so this has to be dropped rather than surfaced.
        reply.corruptDigest = true;
        return reply;
      });

  f.client.asyncGet(targetFor(agent, 0), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::Timeout));
}

TEST(ClientV3, DropsAResponseFromOutsideTheTimeWindow) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        const auto& usm = req.message.security;
        if (usm.engineId.empty())
          return ScriptedV3Agent::report(ScriptedV3Agent::unknownEngineIds,
                                         SecurityLevel::NoAuthNoPriv);
        if (!isAuthenticated(req.message.header.level)) return std::nullopt;
        ScriptedV3Agent::Reply reply;
        reply.level = req.message.header.level;
        reply.scoped.pdu = echoAnswer(req.message.scoped.pdu);
        // A replay of a capture taken an hour ago looks exactly like this.
        reply.time = 5000;
        return reply;
      });

  // The sync phase seeds boots/time from the Report, so by the request itself we have a Window.
  f.client.asyncGet(targetFor(agent, 0), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::Timeout));
}

TEST(ClientV3, RediscoversWhenTheEngineIdChanges) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  const auto target = targetFor(agent);
  f.client.asyncGet(target, credentials(), {sysDescr}, [&](net::ErrorCode e, const Response&) {
    EXPECT_FALSE(e) << e.message();
    // The Target was replaced between requests. The Report that says so is unauthenticated by
    // necessity, and re-discovery is what it has to trigger.
    agent.setEngineId({std::byte{0x80}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x88},
                       std::byte{0x09}, std::byte{0x09}});
    f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
    f.finish();
  });
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  ASSERT_EQ(f.response.varbinds.size(), 1U);
  EXPECT_EQ(f.response.varbinds[0].name, sysUpTime);
}

TEST(ClientV3, TimesOutAgainstASilentTarget) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setResponder([](const ScriptedV3Agent::Request&) { return std::nullopt; });

  f.client.asyncGet(targetFor(agent, 0), credentials(), {sysDescr}, f.requestToken());
  f.run();

  // Discovery is the thing that timed out, and it says so as any other exchange would.
  EXPECT_EQ(f.ec, make_error_code(Errc::Timeout));
}

TEST(ClientV3, SurfacesAnAgentErrorStatusInTheAgentCategory) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), [](const Pdu&) {
    Pdu p;
    p.type = PduType::Response;
    p.errorStatus = static_cast<std::int32_t>(ErrorStatus::NoAccess);
    p.errorIndex = 1;
    return p;
  });
  f.agent = &agent;

  f.client.asyncSet(targetFor(agent), credentials(), {Varbind{sysDescr, null}}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, ErrorStatus::NoAccess);
  EXPECT_EQ(f.ec.category(), agentErrorCategory());
  EXPECT_EQ(f.response.errorIndex, 1);
}

TEST(ClientV3, RefusesAuthPrivBeforeItCanProvideIt) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  const auto creds = credentials(AuthProtocol::Sha256, SecurityLevel::AuthPriv);
  f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::UnsupportedSecurityLevel));
  EXPECT_EQ(agent.requestsSeen(), 0) << "a message claiming privacy reached the network";
}

TEST(ClientV3, SurfacesAnUnsupportedSecurityLevelReport) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setResponder([](const ScriptedV3Agent::Request& req) {
    if (req.message.security.engineId.empty()) {
      return std::optional(
          ScriptedV3Agent::report(ScriptedV3Agent::unknownEngineIds, SecurityLevel::NoAuthNoPriv));
    }
    return std::optional(ScriptedV3Agent::report(ScriptedV3Agent::unsupportedSecLevels,
                                                 SecurityLevel::NoAuthNoPriv));
  });

  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::UnsupportedSecurityLevel));
}

// The security property behind accepting unauthenticated Reports at all: one may cost us a round
// trip, and may never write anything into the cache. An Engine claiming a boots/time pair without
// signing for it gets a full re-discovery, not a resynchronisation.
TEST(ClientV3, AnUnauthenticatedReportNeverResynchronisesTheCache) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  int identityPhases = 0;
  bool lied = false;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        const auto& usm = req.message.security;
        if (usm.engineId.empty()) {
          ++identityPhases;
          return ScriptedV3Agent::report(ScriptedV3Agent::unknownEngineIds,
                                         SecurityLevel::NoAuthNoPriv);
        }
        if (!isAuthenticated(req.message.header.level)) return std::nullopt;
        if (usm.boots == 0) {  // discovery's second phase
          auto r =
              ScriptedV3Agent::report(ScriptedV3Agent::notInTimeWindows, SecurityLevel::AuthNoPriv);
          r.boots = 3;
          r.time = 1000;
          return r;
        }
        if (!lied) {
          lied = true;
          // Unsigned, and claiming a pair we would otherwise adopt.
          auto r = ScriptedV3Agent::report(ScriptedV3Agent::notInTimeWindows,
                                           SecurityLevel::NoAuthNoPriv);
          r.boots = 900000;
          r.time = 7;
          return r;
        }
        ScriptedV3Agent::Reply reply;
        reply.level = req.message.header.level;
        reply.scoped.pdu = echoAnswer(req.message.scoped.pdu);
        return reply;
      });

  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  // Two identity phases: the lie was answered by discovering the Engine again from scratch rather
  // than by believing it.
  EXPECT_EQ(identityPhases, 2);
}

// Story 19, and the reason EngineState tracks whether its pair was ever authenticated: a Target
// first met without authentication has an engineID but no trustworthy clock.
TEST(ClientV3, SynchronisesTimeWhenAnUnauthenticatedTargetIsLaterAuthenticated) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  const auto target = targetFor(agent);
  const auto noAuth = credentials(AuthProtocol::None, SecurityLevel::NoAuthNoPriv);
  f.client.asyncGet(target, noAuth, {sysDescr}, [&](net::ErrorCode e, const Response&) {
    EXPECT_FALSE(e) << e.message();
    f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
    f.finish();
  });
  f.run();

  // Had the authenticated request reused the unauthenticated discovery's boots/time, the Agent
  // would have rejected it as untimely and this would be Errc::NotInTimeWindow.
  EXPECT_FALSE(f.ec) << f.ec.message();
}

// ADR-0003: "Engine Discovery is single-flight per Engine and outlives any individual waiter, so
// cancelling a queued request never cancels the discovery others are waiting on."
TEST(ClientV3, CancellingTheRequestThatStartedDiscoveryLeavesTheQueueIntact) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  net::asio::cancellation_signal signal;
  net::ErrorCode firstEc;
  const auto target = targetFor(agent);

  f.client.asyncGet(
      target, credentials(), {sysDescr},
      net::asio::bind_cancellation_slot(signal.slot(), [&](net::ErrorCode e, const Response&) {
        firstEc = e;
        f.finish();
      }));
  f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
  // Both are now queued behind one discovery. Dropping the first must not drop the discovery.
  signal.emit(net::asio::cancellation_type::terminal);

  f.run();

  EXPECT_EQ(firstEc, net::asio::error::operation_aborted);
  EXPECT_FALSE(f.ec) << "the sibling request went down with the one that was cancelled: "
                     << f.ec.message();
  ASSERT_EQ(f.response.varbinds.size(), 1U);
  EXPECT_EQ(f.response.varbinds[0].name, sysUpTime);
}

TEST(ClientV3, StoppingDuringDiscoveryFailsTheQueuedRequests) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setResponder([](const ScriptedV3Agent::Request&) { return std::nullopt; });

  f.client.asyncGet(targetFor(agent, 5), credentials(), {sysDescr}, f.requestToken());
  net::asio::post(f.io, [&] { f.client.stop(); });
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::ClientStopped));
}

TEST(ClientV3Walk, CollectsTheWholeSubtreeAcrossSeveralRounds) {
  Fixture f;
  const Oid base{1, 3, 6, 1, 2, 1, 1};
  std::uint32_t next = 1;
  ScriptedV3Agent agent(f.io, credentials(), [&](const Pdu&) {
    Pdu p;
    p.type = PduType::Response;
    if (next > 3) {
      p.varbinds = {Varbind{Oid{1, 3, 6, 1, 2, 1, 2, 1, 0}, Counter32{7}}};  // out of the Subtree
      return p;
    }
    p.varbinds = {Varbind{Oid{1, 3, 6, 1, 2, 1, 1, next, 0}, Counter32{next}}};
    ++next;
    return p;
  });
  f.agent = &agent;

  f.client.asyncWalkCollect(targetFor(agent), credentials(), base, WalkOptions{1},
                            f.collectToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(f.collected.size(), 3U);
}

}  // namespace
}  // namespace snmpio
