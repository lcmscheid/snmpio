#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/detail/CacheView.hpp>
#include <snmpio/detail/DeriverView.hpp>

#include "CompletionOracle.hpp"
#include "Deadlines.hpp"
#include "FreshProcess.hpp"
#include "MasterKeys.hpp"
#include "RefusedFetches.hpp"
#include "ScriptedV3Agent.hpp"

#include <openssl/rand.h>

namespace snmpio {
namespace {

using test::atOnceLimit;
using test::ScriptedV3Agent;
using test::targetFor;
using test::withMasterKeys;

const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};
const Oid sysUpTime{1, 3, 6, 1, 2, 1, 1, 3, 0};

Credentials credentials(AuthProtocol protocol = AuthProtocol::Sha256,
                        SecurityLevel level = SecurityLevel::AuthNoPriv) {
  return Credentials{"bert", level, protocol, "maplesyrup", PrivProtocol::None, ""};
}

Credentials privCredentials(PrivProtocol priv, AuthProtocol protocol = AuthProtocol::Sha256) {
  return Credentials{"bert", SecurityLevel::AuthPriv, protocol, "maplesyrup", priv, "privatepass"};
}

// The same Credentials for another user the Agent knows, with passwords of its own: whoever a reply
// for someone other than bert is signed by.
Credentials asErnie(Credentials creds) {
  creds.userName = "ernie";
  creds.authPassword = "butterscotch";
  if (creds.privProtocol != PrivProtocol::None) creds.privPassword = "butterscotch-priv";
  return creds;
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

TEST(ClientV3, ASecondRequestSkipsEngineDiscovery) {
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

        const auto untimely = [](std::int32_t boots, std::int32_t time) {
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

// An Agent that answers the request but stamps a boots/time pair of its own into the reply --
// which is what an Engine that restarted between two requests looks like from here, and what the
// Simulator's engineBootsBump and engineTimeOffsetS put on the wire.
ScriptedV3Agent::Responder answersWith(std::int32_t boots, std::int32_t time) {
  return [boots, time](const ScriptedV3Agent::Request& req) {
    ScriptedV3Agent::Reply reply;
    reply.level = req.message.header.level;
    reply.scoped.pdu = echoAnswer(req.message.scoped.pdu);
    reply.boots = boots;
    reply.time = time;
    return std::optional(reply);
  };
}

// One GET settles the cache at the Engine's boots 3, then `changeTheAgent` runs, then two more
// GETs go out one after the other. The Agent change most tests here care about is an Engine whose
// boots counter went backwards -- a factory reset, a replaced line card, firmware that lost
// snmpEngineBoots -- and the cases either side of it.
struct LaterGetResults {
  net::ErrorCode second;
  net::ErrorCode third;
  int requestsAfterTheSecondGet = 0;
};

LaterGetResults afterTheCacheIsSettled(
    const std::function<void(ScriptedV3Agent&)>& changeTheAgent) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  f.expectedCompletions = 3;

  LaterGetResults result;
  const auto target = targetFor(agent);
  f.client.asyncGet(target, credentials(), {sysDescr}, [&](net::ErrorCode first, const Response&) {
    EXPECT_FALSE(first) << "the GET that settles the cache: " << first.message();
    changeTheAgent(agent);
    const int requestsBeforeTheSecondGet = agent.requestsSeen();
    f.client.asyncGet(target, credentials(), {sysDescr},
                      [&, requestsBeforeTheSecondGet](net::ErrorCode ec, const Response&) {
                        result.second = ec;
                        result.requestsAfterTheSecondGet =
                            agent.requestsSeen() - requestsBeforeTheSecondGet;
                        f.client.asyncGet(target, credentials(), {sysUpTime},
                                          [&](net::ErrorCode ec3, const Response&) {
                                            result.third = ec3;
                                            f.finish();
                                          });
                        f.finish();
                      });
    f.finish();
  });
  f.run();
  return result;
}

// What a second GET makes of a reply carrying `boots`/`time`, the first having settled the cache
// on the Agent's own pair. One Client throughout, because the cache is the Client's (ADR-0003).
net::ErrorCode secondGetAnsweredWith(std::int32_t boots, std::int32_t time) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  f.expectedCompletions = 2;

  const auto target = targetFor(agent);
  net::ErrorCode second;
  f.client.asyncGet(target, credentials(), {sysDescr}, [&](net::ErrorCode first, const Response&) {
    EXPECT_FALSE(first) << "the GET that settles the cache: " << first.message();
    agent.setResponder(answersWith(boots, time));
    f.client.asyncGet(target, credentials(), {sysDescr}, [&](net::ErrorCode ec, const Response&) {
      second = ec;
      f.finish();
    });
    f.finish();
  });
  f.run();
  return second;
}

// Criterion: a reply from an Engine that has restarted since we cached it is timely. RFC 3414
// section 3.2 step 7(b) makes only an *older* pair untimely from the non-authoritative side; a
// higher boots count is the Engine saying where it has got to, and it resets the cache rather than
// being dropped.
//
// Requiring the pair to match instead costs a Target that is answering: every reply from a
// restarted Engine is discarded, and the caller is told Timeout until the cache is thrown away.
//
// The reply answers a request sent under the Baseline the cache holds, so ADR-0010's amendment,
// which drops the clock from a reply to a request sent under an earlier one, must not refuse it:
// the next request carries the restarted boots.
TEST(ClientV3, AcceptsAReplyFromAnEngineThatRestartedSinceWeCachedIt) {
  std::vector<std::int32_t> bootsCarried;
  const auto r = afterTheCacheIsSettled([&](ScriptedV3Agent& agent) {
    agent.setResponder([&](const ScriptedV3Agent::Request& req) {
      if (!req.message.security.engineId.empty()) {
        bootsCarried.push_back(req.message.security.boots);
      }
      return answersWith(9, 20)(req);
    });
  });

  EXPECT_FALSE(r.second) << "a restarted Engine's reply was dropped: " << r.second.message();
  EXPECT_FALSE(r.third) << r.third.message();
  EXPECT_EQ(bootsCarried, (std::vector<std::int32_t>{3, 9}))
      << "the restarted boots was not adopted";
}

// The other half of the same rule, and the ordinary one of the two: a clock stepped forward within
// one boot needs nothing more than NTP. Only a time *behind* our projection by more than the
// Window is untimely, so this is a Response to be answered from, not one to drop.
TEST(ClientV3, AcceptsAReplyWhoseClockSteppedForwardWithinOneBoot) {
  const auto ec = secondGetAnsweredWith(3, 4000);
  EXPECT_FALSE(ec) << "a clock step forward was read as untimely: " << ec.message();
}

// And the direction that must stay refused, which is what the rule is for: a pair older than the
// one we hold is a replay, and RFC 3414 section 2.2.3 never lets a cached boots count go down.
// Dropped rather than failed, like every other unusable datagram -- the request stays outstanding
// and retransmits. At the deadline it says why it dropped them rather than Timeout (ADR-0008).
TEST(ClientV3, DropsAReplyClaimingAnOlderBootsCount) {
  const auto ec = secondGetAnsweredWith(2, 1000);
  EXPECT_EQ(ec, make_error_code(Errc::NotInTimeWindow))
      << "a boots regression was accepted: " << ec.message();
}

bool isTimeSyncPhase(const ScriptedV3Agent::Request& req) {
  return !req.message.security.engineId.empty() && req.message.security.boots == 0;
}

// Which of a test's requests this is, told apart by the first name it asks for.
bool asksFor(const ScriptedV3Agent::Request& req, const Oid& name) {
  const auto& varbinds = req.message.scoped.pdu.varbinds;
  return !varbinds.empty() && varbinds.front().name == name;
}

// Criterion: the signed notInTimeWindows Report from an Engine now at a lower boots is the Engine
// telling us its real clock, and the cache is rediscovered from it rather than refusing it forever.
TEST(ClientV3, RediscoversAnEngineWhoseBootsWentBackwards) {
  int timeSyncPhases = 0;
  std::vector<std::int32_t> bootsCarried;
  const auto r = afterTheCacheIsSettled([&](ScriptedV3Agent& agent) {
    agent.setBoots(1);
    agent.setTime(50);
    agent.setResponder([&](const ScriptedV3Agent::Request& req) {
      if (isTimeSyncPhase(req)) ++timeSyncPhases;
      if (!req.message.security.engineId.empty())
        bootsCarried.push_back(req.message.security.boots);
      return agent.behaveLikeACompliantAgent(req);
    });
  });

  EXPECT_FALSE(r.second) << "the lower boots locked the Engine out: " << r.second.message();
  EXPECT_FALSE(r.third) << "the request after the resync failed: " << r.third.message();
  EXPECT_EQ(timeSyncPhases, 1) << "the Engine was not rediscovered exactly once";
  // The stale request, the rediscovery's time-sync phase, its retry at the new boots, and the third
  // GET at the new boots.
  EXPECT_EQ(bootsCarried, (std::vector<std::int32_t>{3, 0, 1, 1}));
}

// The forger's half: an unsigned Report claiming a lower boots buys a round trip and nothing else.
// The cached clock is neither lowered nor forgotten, so every request still carries boots 3, no
// time-sync phase runs, and the request fails with the error the Report named.
TEST(ClientV3, AnUnsignedLowerBootsReportNeverClearsTheCachedClock) {
  int timeSyncPhases = 0;
  std::vector<std::int32_t> bootsCarried;
  const auto r = afterTheCacheIsSettled([&](ScriptedV3Agent& agent) {
    agent.setBoots(1);
    agent.setResponder([&](const ScriptedV3Agent::Request& req) {
      if (isTimeSyncPhase(req)) ++timeSyncPhases;
      auto reply = agent.behaveLikeACompliantAgent(req);
      if (req.message.security.engineId.empty()) return reply;
      bootsCarried.push_back(req.message.security.boots);
      if (reply && reply->scoped.pdu.type == PduType::Report) {
        reply->level = SecurityLevel::NoAuthNoPriv;
      }
      return reply;
    });
  });

  EXPECT_EQ(r.second, make_error_code(Errc::NotInTimeWindow)) << r.second.message();
  EXPECT_EQ(r.third, make_error_code(Errc::NotInTimeWindow)) << r.third.message();
  EXPECT_EQ(timeSyncPhases, 0) << "an unsigned Report made the Client forget the Engine's clock";
  // Each GET is one attempt and one retry, and every one of them still carries the cached boots.
  EXPECT_EQ(bootsCarried, (std::vector<std::int32_t>{3, 3, 3, 3}));
}

// The bound: a request gets at most one forced resync. An Engine whose every Report names a boots
// lower than the request carried -- even after rediscovery handed us its own -- fails that request
// after exactly one rediscovery rather than sending it round again.
TEST(ClientV3, AForcedResyncHappensAtMostOncePerRequest) {
  const auto r = afterTheCacheIsSettled([&](ScriptedV3Agent& agent) {
    agent.setResponder(
        [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
          if (req.message.security.engineId.empty()) return agent.behaveLikeACompliantAgent(req);
          auto report =
              ScriptedV3Agent::report(ScriptedV3Agent::notInTimeWindows, SecurityLevel::AuthNoPriv);
          report.boots = isTimeSyncPhase(req) ? 2 : req.message.security.boots - 1;
          return report;
        });
  });

  EXPECT_EQ(r.second, make_error_code(Errc::NotInTimeWindow)) << r.second.message();
  // The stale request, the identity and time-sync phases of one rediscovery, and one retry.
  EXPECT_EQ(r.requestsAfterTheSecondGet, 4);
}

// #43 and #84. Two Outstanding Requests sent at the cached boots 3, and the Engine resets to boots
// 1 between signing a Response to one and answering the other. The other request's signed
// lower-boots Report forgets the clock, and its retry rediscovers the Engine at boots 1. The signed
// Response is held back and let go at one of the points below. It is authenticated and ahead of
// the boots the rediscovery set, so RFC 3414 section 3.2 step 7(b)(1) reads it as a restart, and it
// still answers its own request. It must neither stand in for the rediscovery's time-sync phase
// (#43) nor move the cache back to the boots the rediscovery abandoned (#84, ADR-0010's amendment).
// Had it done either, the reported request would fail: its retry would go out at boots 3 with no
// forced resync left, or the retry's answer at boots 1 would be dropped as behind the cache. The
// next request would go out at boots 3 and cost a third time-sync phase. A third GET, after both,
// shows which boots the cache holds.
enum class ReleasePoint {
  // Just ahead of the rediscovery's identity phase's answer, while the rediscovery is owed (#43).
  DuringTheRediscovery,
  // Right behind the time-sync phase's answer, before the reported request's retry can go out: the
  // order #84 names, on the wire. On one thread, as here, the Client still encodes the retry
  // before it reads the held Response, so this lands where BeforeTheRetryIsAnswered does. The
  // other order, where the retry would go out at boots 3, is the executor's to choose and no test
  // can schedule it, but the same check covers it: the retry must carry boots 1.
  BeforeTheRetry,
  // Once the retry is on the wire at the rediscovered boots, just ahead of its answer.
  BeforeTheRetryIsAnswered,
  // Once the reported request has completed, so that only the next request can be hurt.
  AfterTheReportedRequestCompletes,
};

struct LateRelease {
  ReleasePoint at;
  const char* name;
};

class ALateSignedResponseAtTheOldBoots : public testing::TestWithParam<LateRelease> {};

TEST_P(ALateSignedResponseAtTheOldBoots, NeitherFailsARequestNorCostsASecondRediscovery) {
  // The Engine's clock as the cache settled it, and as it is after the reset.
  constexpr std::int32_t oldBoots = 3;
  constexpr std::int32_t oldTime = 1000;
  constexpr std::int32_t resetBoots = 1;
  constexpr std::int32_t resetTime = 50;
  const Oid sysContact{1, 3, 6, 1, 2, 1, 1, 4, 0};
  const ReleasePoint at = GetParam().at;

  Fixture f;
  f.expectedCompletions = 3;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  test::CompletionOracle reported(f.io);  // asks for sysDescr, and meets the lower-boots Report
  test::CompletionOracle late(f.io);      // asks for sysUpTime, and its Response is held back
  test::CompletionOracle next(f.io);      // asks for sysContact, once both have completed

  std::optional<ScriptedV3Agent::Request> reportedRequest;
  std::optional<ScriptedV3Agent::Request> lateRequest;
  std::optional<ScriptedV3Agent::Reply> lateResponse;
  bool reset = false;
  bool released = false;
  int timeSyncPhases = 0;
  std::vector<std::int32_t> bootsTheReportedRequestCarried;
  std::vector<std::int32_t> bootsTheNextRequestCarried;

  const auto release = [&] {
    if (!lateResponse) return;
    agent.answerLate(*lateRequest, *std::exchange(lateResponse, std::nullopt));
    released = true;
  };

  agent.setBoots(oldBoots);
  agent.setTime(oldTime);
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (isTimeSyncPhase(req)) ++timeSyncPhases;
        const bool isReported = asksFor(req, sysDescr);
        const bool isLate = asksFor(req, sysUpTime);
        if (isReported) bootsTheReportedRequestCarried.push_back(req.message.security.boots);
        if (asksFor(req, sysContact)) {
          bootsTheNextRequestCarried.push_back(req.message.security.boots);
        }

        if (!reset && (isReported || isLate)) {
          // Hold whichever arrives first, so that both were sent at the old boots before the reset.
          (isReported ? reportedRequest : lateRequest) = req;
          if (!reportedRequest || !lateRequest) return std::nullopt;
          // Signed at the old clock, before the reset, and not yet sent.
          lateResponse = agent.behaveLikeACompliantAgent(*lateRequest);
          lateResponse->boots = oldBoots;
          lateResponse->time = oldTime;
          reset = true;
          agent.setBoots(resetBoots);
          agent.setTime(resetTime);
          agent.answerLate(*reportedRequest, *agent.behaveLikeACompliantAgent(*reportedRequest));
          return std::nullopt;
        }
        if (!reset) return agent.behaveLikeACompliantAgent(req);

        if (at == ReleasePoint::DuringTheRediscovery && req.message.security.engineId.empty()) {
          release();
        }
        // Both datagrams are on the wire before the Client has read either, so the held Response
        // cannot arrive behind the retry.
        if (at == ReleasePoint::BeforeTheRetry && isTimeSyncPhase(req) && lateResponse) {
          agent.answerLate(req, *agent.behaveLikeACompliantAgent(req));
          release();
          return std::nullopt;
        }
        if (at == ReleasePoint::BeforeTheRetryIsAnswered && isReported &&
            req.message.security.boots == resetBoots) {
          release();
        }
        return agent.behaveLikeACompliantAgent(req);
      });

  // No retransmission, and long enough to answer: every datagram here is one the test chose.
  Target target = targetFor(agent);
  target.timeout = std::chrono::seconds(5);
  target.retries = 0;
  int bothDone = 0;
  const auto thenTheNext = [&] {
    f.finish();
    if (++bothDone < 2) return;
    f.client.asyncGet(target, credentials(), {sysContact},
                      next.handler([&f](net::ErrorCode, const Response&) { f.finish(); }));
  };
  f.client.asyncGet(target, credentials(), {sysDescr},
                    reported.handler([&](net::ErrorCode, const Response&) {
                      if (at == ReleasePoint::AfterTheReportedRequestCompletes) release();
                      thenTheNext();
                    }));
  f.client.asyncGet(target, credentials(), {sysUpTime},
                    late.handler([&](net::ErrorCode, const Response&) { thenTheNext(); }));
  f.run();

  ASSERT_TRUE(released) << "the held Response was never let go";
  EXPECT_TRUE(late.completedExactlyOnce({net::ErrorCode{}}));
  EXPECT_TRUE(reported.completedExactlyOnce({net::ErrorCode{}}))
      << "the late Response undid the rediscovery";
  EXPECT_TRUE(next.completedExactlyOnce({net::ErrorCode{}}));
  // The first discovery's, and the rediscovery's. Not a third.
  EXPECT_EQ(timeSyncPhases, 2);
  // The request at the old boots, and its retry at the rediscovered one.
  EXPECT_EQ(bootsTheReportedRequestCarried, (std::vector<std::int32_t>{oldBoots, resetBoots}));
  EXPECT_EQ(bootsTheNextRequestCarried, (std::vector<std::int32_t>{resetBoots}));
}

INSTANTIATE_TEST_SUITE_P(
    ClientV3, ALateSignedResponseAtTheOldBoots,
    testing::Values(LateRelease{ReleasePoint::DuringTheRediscovery, "DuringTheRediscovery"},
                    LateRelease{ReleasePoint::BeforeTheRetry, "BeforeTheRetry"},
                    LateRelease{ReleasePoint::BeforeTheRetryIsAnswered, "BeforeTheRetryIsAnswered"},
                    LateRelease{ReleasePoint::AfterTheReportedRequestCompletes,
                                "AfterTheReportedRequestCompletes"}),
    [](const testing::TestParamInfo<LateRelease>& param) { return std::string(param.param.name); });

// The direction that was always right stays as it was: a signed Report naming a *higher* boots is
// adopted and the request retried, with no rediscovery.
TEST(ClientV3, ASignedHigherBootsReportIsAdoptedWithoutRediscovery) {
  int timeSyncPhases = 0;
  int identityPhases = 0;
  const auto r = afterTheCacheIsSettled([&](ScriptedV3Agent& agent) {
    agent.setBoots(9);
    agent.setResponder([&](const ScriptedV3Agent::Request& req) {
      if (req.message.security.engineId.empty()) ++identityPhases;
      if (isTimeSyncPhase(req)) ++timeSyncPhases;
      return agent.behaveLikeACompliantAgent(req);
    });
  });

  EXPECT_FALSE(r.second) << r.second.message();
  EXPECT_FALSE(r.third) << r.third.message();
  EXPECT_EQ(identityPhases, 0);
  EXPECT_EQ(timeSyncPhases, 0);
  // The stale request and its retry.
  EXPECT_EQ(r.requestsAfterTheSecondGet, 2);
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

// The half of ADR-0008 that must not have moved: recording *why* a datagram was dropped is not the
// same as acting on it. The reply still cannot fail the request early, so every retransmission the
// Target's retries buy still goes out -- one attempt plus one retry, on top of the two discovery
// exchanges.
TEST(ClientV3, KeepsRetransmittingThroughRepliesItDrops) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setResponder([&agent](const ScriptedV3Agent::Request& req) {
    auto reply = agent.behaveLikeACompliantAgent(req);
    if (reply && reply->scoped.pdu.type == PduType::Response) reply->corruptDigest = true;
    return reply;
  });

  f.client.asyncGet(targetFor(agent, 1), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::AuthFailed));
  EXPECT_EQ(agent.requestsSeen(), 4) << "a dropped reply cut the retransmissions short";
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
        if (usm.boots == 0) return agent.behaveLikeACompliantAgent(req);  // the time-sync phase
        ScriptedV3Agent::Reply reply;
        reply.level = req.message.header.level;
        reply.scoped.pdu = echoAnswer(req.message.scoped.pdu);
        // A replay of a capture taken earlier looks exactly like this: the pair discovery seeded
        // from is (3, 1000), and this one is nine hundred seconds behind it -- six times the
        // Window. A time *ahead* of that pair would be an Engine whose clock was stepped, which
        // AcceptsAReplyWhoseClockSteppedForwardWithinOneBoot is about and which is not this.
        reply.time = 100;
        return reply;
      });

  // The sync phase seeds boots/time from the Report, so by the request itself we have a Window.
  f.client.asyncGet(targetFor(agent, 0), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::NotInTimeWindow));
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

TEST(ClientV3, RefusesAnArgumentPastItsCeilingBeforeDiscovering) {
  // The bound is the same at either version, and is checked before the Engine Discovery a first
  // v3 request would otherwise send.
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  f.client.asyncGetBulk(targetFor(agent), credentials(), {sysDescr}, 0, maxRepetitionsCeiling + 1,
                        f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::ArgumentOutOfRange) << f.ec.message();
  EXPECT_EQ(agent.requestsSeen(), 0) << "nothing is sent, Engine Discovery included";
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

TEST(ClientV3, RefusesAuthPrivWithoutAPrivacyProtocol) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  const auto creds = credentials(AuthProtocol::Sha256, SecurityLevel::AuthPriv);
  f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::UnsupportedPrivProtocol));
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

// The same property in the one exchange that does not go through handleReport: discovery's
// time-sync phase. Had the forged pair become the Baseline, every request after it would carry a
// boots count the Engine is nowhere near, and since boots never go backwards, the Engine's signed
// corrections could not repair it.
TEST(ClientV3, AnUnauthenticatedReportNeverSetsTheDiscoveredClock) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  int syncPhases = 0;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        const auto& usm = req.message.security;
        if (!usm.engineId.empty() && usm.boots == 0 && ++syncPhases == 1) {
          // Unsigned, answering the first time-sync phase before the Engine can.
          auto r = ScriptedV3Agent::report(ScriptedV3Agent::notInTimeWindows,
                                           SecurityLevel::NoAuthNoPriv);
          r.boots = 900000;
          r.time = 7;
          return r;
        }
        return agent.behaveLikeACompliantAgent(req);
      });

  const auto target = targetFor(agent);
  f.client.asyncGet(target, credentials(), {sysDescr}, [&](net::ErrorCode e, const Response&) {
    EXPECT_FALSE(e) << e.message();
    f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
    f.finish();
  });
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  // The forgery was dropped and the phase's retransmission got the signed answer.
  EXPECT_EQ(syncPhases, 2);
}

// The other half of the drop above, ADR-0008's: when the signed Report never comes, the phase still
// runs to its deadline -- every retransmission goes out -- and then says why, not just Timeout.
TEST(ClientV3, AnUnsignedNotInTimeWindowsAloneFailsTheTimeSyncAtItsDeadline) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  int syncPhases = 0;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (req.message.security.engineId.empty()) return agent.behaveLikeACompliantAgent(req);
        ++syncPhases;
        return ScriptedV3Agent::report(ScriptedV3Agent::notInTimeWindows,
                                       SecurityLevel::NoAuthNoPriv);
      });

  f.client.asyncGet(targetFor(agent, 1), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::NotInTimeWindow));
  EXPECT_EQ(syncPhases, 2) << "an unsigned Report cut the time-sync phase short";
}

// An unsigned Report in the time-sync phase that names any other counter ends the discovery with
// the error it names, rather than letting the request go on against a clock nobody signed for.
TEST(ClientV3, AnUnauthenticatedReportDuringTimeSyncEndsDiscoveryWithItsError) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (req.message.security.engineId.empty()) return agent.behaveLikeACompliantAgent(req);
        return ScriptedV3Agent::report(ScriptedV3Agent::unknownUserNames,
                                       SecurityLevel::NoAuthNoPriv);
      });

  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::UnknownUserName));
  // Identity, then time sync; the request itself was never sent.
  EXPECT_EQ(agent.requestsSeen(), 2);
}

// Signed is the bar, not which counter the Report names. The Simulator image CI pins as `simulator`
// answers the time-sync phase with a signed unknownEngineIDs Report carrying its real clock --
// non-compliant, since by then it knows the engineID, but signed by the Engine all the same, and
// RFC 3414 section 3.2 step 7(b) learns the pair from any authenticated message. This is that
// Agent's counterpart here (ADR-0006).
TEST(ClientV3, AdoptsTheClockFromASignedReportNamingAnotherCounter) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        const auto& usm = req.message.security;
        if (!usm.engineId.empty() && usm.boots == 0) {
          auto r =
              ScriptedV3Agent::report(ScriptedV3Agent::unknownEngineIds, SecurityLevel::AuthNoPriv);
          r.boots = 3;
          r.time = 1000;
          return r;
        }
        return agent.behaveLikeACompliantAgent(req);
      });

  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  // Identity, time sync, then the request itself -- with no second discovery.
  EXPECT_EQ(agent.requestsSeen(), 3);
}

// The other answer the time-sync phase can get. An Engine that has just booted finds boots 0 and
// time 0 timely and answers with a Response, signed -- a pair as trustworthy as any Report's.
TEST(ClientV3, AdoptsTheClockFromASignedResponseToTheTimeSyncPhase) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setBoots(0);
  agent.setTime(0);

  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(agent.requestsSeen(), 3);
}

// The identity phase is unsigned by design, so the pair it carries is never a Baseline: nothing is
// timely or untimely against it. Had it been, a forged identity reply would get the Engine's own
// signed Response to the time-sync phase dropped as a replay.
TEST(ClientV3, TheIdentityPhasesClockIsNotABaseline) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setBoots(0);
  agent.setTime(0);
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (!req.message.security.engineId.empty()) return agent.behaveLikeACompliantAgent(req);
        auto r =
            ScriptedV3Agent::report(ScriptedV3Agent::unknownEngineIds, SecurityLevel::NoAuthNoPriv);
        r.boots = 900000;
        r.time = 7;
        return r;
      });

  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
}

// Whether a reply was authenticated is a fact about that datagram, not about the exchange. Here a
// request's first answer is signed but dropped for naming an Engine we did not address, and its
// retransmission is answered by an unsigned notInTimeWindows Report claiming a huge boots. Had the
// first datagram's signature carried over, handleReport would have adopted that pair, every later
// request would have carried a boots the Engine is nowhere near, and nothing could repair it.
TEST(ClientV3, ASignedButDroppedReplyDoesNotVouchForTheNextOne) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  int dataRequests = 0;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        const auto& usm = req.message.security;
        if (usm.engineId.empty() || usm.boots == 0) return agent.behaveLikeACompliantAgent(req);
        ++dataRequests;
        if (dataRequests == 1) {
          // Signed with the right key, and dropped for naming an Engine we did not address.
          ScriptedV3Agent::Reply reply;
          reply.scoped.pdu = echoAnswer(req.message.scoped.pdu);
          reply.engineId = Octets{std::byte{0x80}, std::byte{0x00}, std::byte{0x00}};
          return reply;
        }
        if (dataRequests == 2) {
          auto r = ScriptedV3Agent::report(ScriptedV3Agent::notInTimeWindows,
                                           SecurityLevel::NoAuthNoPriv);
          r.boots = 900000;
          r.time = 7;
          return r;
        }
        return agent.behaveLikeACompliantAgent(req);
      });

  const auto target = targetFor(agent);
  f.client.asyncGet(target, credentials(), {sysDescr}, [&](net::ErrorCode e, const Response&) {
    EXPECT_FALSE(e) << e.message();
    f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
    f.finish();
  });
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
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

// Issues the unauthenticated Get the next two tests queue an authenticated one behind, and
// records how it went in `ec`.
void getWithoutAuthentication(Fixture& f, const Target& target, net::ErrorCode& ec) {
  f.client.asyncGet(target, credentials(AuthProtocol::None, SecurityLevel::NoAuthNoPriv),
                    {sysDescr}, [&f, &ec](net::ErrorCode e, const Response&) {
                      ec = e;
                      f.finish();
                    });
}

// The same, with both requests issued at once: the authenticated one queues behind the discovery
// the unauthenticated one started, which on its own would stop after its identity phase. The pair
// that phase recorded is unsigned, so the discovery has to go on to a time-sync phase -- carrying
// that pair instead would leave the Engine unsynced, and every later reply unchecked against the
// Time Window.
TEST(ClientV3, AnAuthenticatedRequestQueuedBehindAnUnauthenticatedDiscoveryStillSynchronises) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  int timeSyncPhases = 0;
  int authenticatedAttempts = 0;
  agent.setResponder([&](const ScriptedV3Agent::Request& req) {
    if (isTimeSyncPhase(req)) ++timeSyncPhases;
    if (asksFor(req, sysUpTime)) ++authenticatedAttempts;
    return agent.behaveLikeACompliantAgent(req);
  });

  const auto target = targetFor(agent);
  net::ErrorCode noAuthEc;
  getWithoutAuthentication(f, target, noAuthEc);
  f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
  f.run();

  EXPECT_FALSE(noAuthEc) << noAuthEc.message();
  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(timeSyncPhases, 1) << "the authenticated request went out on an unsigned pair";
  EXPECT_EQ(authenticatedAttempts, 1);
}

// The time-sync phase that the queued request asked for is that request's business. An Engine that
// never answers it fails the authenticated request with the Timeout, before its Get ever goes out.
// The unauthenticated request the discovery was started for already has the engineID it needed,
// and succeeds.
TEST(ClientV3, AnUnansweredTimeSyncPhaseFailsOnlyTheAuthenticatedRequestQueuedForIt) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  int authenticatedAttempts = 0;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (isTimeSyncPhase(req)) return std::nullopt;
        if (asksFor(req, sysUpTime)) ++authenticatedAttempts;
        return agent.behaveLikeACompliantAgent(req);
      });

  // Short and without retries: the silence is the point, and waiting it out is all this test does.
  Target target = targetFor(agent);
  target.timeout = std::chrono::milliseconds(100);
  target.retries = 0;
  net::ErrorCode noAuthEc;
  getWithoutAuthentication(f, target, noAuthEc);
  f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
  f.run();

  EXPECT_FALSE(noAuthEc) << "the queued request's failure failed the request it queued behind: "
                         << noAuthEc.message();
  EXPECT_EQ(f.ec, make_error_code(Errc::Timeout)) << f.ec.message();
  EXPECT_EQ(authenticatedAttempts, 0) << "the Get went out on the identity phase's unsigned pair";
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

// TestDisruptionMatrix.cpp's QueuedBehindDiscovery_* cells, with a sibling waiter: a request parked
// on an Engine Discovery. The signal is emitted from the Agent, as the discovery request reaches
// it, which is the one moment both requests are suspended on the discovery rather than on a reply
// of their own. That it is answered there and not later is countable: a request ended in the
// discovery wait never sends a datagram of its own.
class QueuedBehindDiscovery : public testing::TestWithParam<net::asio::cancellation_type> {};

TEST_P(QueuedBehindDiscovery, IsAbortedAndLeavesTheDiscoveryRunning) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  net::asio::cancellation_signal signal;
  net::ErrorCode queuedEc;
  const auto target = targetFor(agent);

  agent.setOnDatagram([&signal, seen = 0](std::span<const std::byte>) mutable {
    if (seen++ == 0) signal.emit(GetParam());
  });

  f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
  f.client.asyncGet(
      target, credentials(), {sysDescr},
      net::asio::bind_cancellation_slot(signal.slot(), [&](net::ErrorCode e, const Response&) {
        queuedEc = e;
        f.finish();
      }));

  f.run();

  EXPECT_EQ(queuedEc, net::asio::error::operation_aborted);
  EXPECT_FALSE(f.ec) << "cancelling one waiter took the discovery down with it: " << f.ec.message();
  ASSERT_EQ(f.response.varbinds.size(), 1U);
  EXPECT_EQ(f.response.varbinds[0].name, sysUpTime);
  // The discovery's two datagrams and the surviving request's one. A fourth would mean the
  // cancelled request was let through to send an exchange it had already been told to abandon.
  EXPECT_EQ(agent.requestsSeen(), 3);
}

INSTANTIATE_TEST_SUITE_P(ClientV3, QueuedBehindDiscovery,
                         testing::Values(net::asio::cancellation_type::terminal,
                                         net::asio::cancellation_type::total));

// A total signal lets the reply already on its way count, and here that reply is a Report asking
// for a second attempt. A retryable Report is not an answer to the request, only a call for another
// exchange, which total forbids: the request ends with operation_aborted and makes no second
// attempt (#73). Depending on the Report, that attempt would be a fresh exchange or the first
// datagram of a rediscovery. The Agent goes silent after the Report until the request ends, so
// either would sit out a whole deadline.
struct RetryableReport {
  std::uint32_t counter;
  SecurityLevel level;  // signed, so the Client acts on its clock; or not, so it forgets the Engine
  std::int32_t bootsInTheReport;  // the Agent's default is 3, the boots discovery cached
  int nextRequestDatagrams;       // what the request after the cancelled one costs; see the table
  const char* name;
};

class TotalCancelThenRetryableReport : public testing::TestWithParam<RetryableReport> {
 protected:
  static constexpr auto deadline = std::chrono::seconds(4);

  TotalCancelThenRetryableReport() {
    m_f.agent = &m_agent;
    m_target.timeout = deadline;
  }

  // Sends the request that a total signal cancels as the Agent answers it with this row's Report.
  // The Agent's clock moves to the Report's boots as it does. The Agent is silent from then until
  // the request ends, and compliant after. `then` runs as the request ends.
  void sendTheCancelledRequest(std::function<void()> then) {
    m_agent.setResponder(
        [this](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
          if (m_cancelled.ended) return m_agent.behaveLikeACompliantAgent(req);
          if (m_cancelled.reported) return std::nullopt;
          if (req.message.scoped.pdu.varbinds.empty())
            return m_agent.behaveLikeACompliantAgent(req);
          m_cancelled.reported = true;
          m_emittedAt = std::chrono::steady_clock::now();
          m_signal.emit(net::asio::cancellation_type::total);
          m_agent.setBoots(GetParam().bootsInTheReport);
          return ScriptedV3Agent::report(GetParam().counter, GetParam().level);
        });

    m_f.client.asyncGet(
        m_target, credentials(), {sysDescr},
        net::asio::bind_cancellation_slot(
            m_signal.slot(), [this, then = std::move(then)](net::ErrorCode ec, const Response&) {
              m_cancelled.took = std::chrono::steady_clock::now() - m_emittedAt;
              m_cancelled.ec = ec;
              m_cancelled.datagrams = m_agent.requestsSeen();
              m_cancelled.ended = true;
              then();
            }));
  }

  Fixture m_f;
  ScriptedV3Agent m_agent{m_f.io, credentials(), echoAnswer};
  Target m_target = targetFor(m_agent, 0);

  // What the cancelled request did, as it ended.
  struct {
    bool reported = false;
    bool ended = false;
    net::ErrorCode ec;
    int datagrams = 0;                           // the Agent had seen, discovery's included
    std::chrono::steady_clock::duration took{};  // from the signal to the end
  } m_cancelled;

 private:
  net::asio::cancellation_signal m_signal;
  std::chrono::steady_clock::time_point m_emittedAt;
};

TEST_P(TotalCancelThenRetryableReport, EndsWithoutASecondAttempt) {
  sendTheCancelledRequest([this] { m_f.finish(); });
  m_f.run();

  ASSERT_TRUE(m_cancelled.reported) << "the Agent never sent the Report";
  EXPECT_EQ(m_cancelled.ec, net::asio::error::operation_aborted) << m_cancelled.ec.message();
  // The discovery's two datagrams and the request's one. A fourth is the second attempt.
  EXPECT_EQ(m_cancelled.datagrams, 3);
  EXPECT_LT(m_cancelled.took, atOnceLimit(deadline)) << "waited out the second attempt";
}

// What the Report said about the Engine still reaches the cache: it is as true for the next request
// as it would have been for the retry, and must not hinge on whether the request that heard it is
// still wanted. The next request's datagram count shows what the Client made of it; each row's
// count differs from the one a cache left as it was would cost.
TEST_P(TotalCancelThenRetryableReport, StillActsOnTheReportForTheNextRequest) {
  m_f.expectedCompletions = 2;
  sendTheCancelledRequest([this] {
    m_f.client.asyncGet(m_target, credentials(), {sysUpTime}, m_f.requestToken());
    m_f.finish();
  });
  m_f.run();

  ASSERT_EQ(m_cancelled.ec, net::asio::error::operation_aborted) << m_cancelled.ec.message();
  EXPECT_FALSE(m_f.ec) << "the next request failed: " << m_f.ec.message();
  EXPECT_EQ(m_agent.requestsSeen() - m_cancelled.datagrams, GetParam().nextRequestDatagrams)
      << "the cancelled request's Report never reached the Engine cache";
}

INSTANTIATE_TEST_SUITE_P(
    ClientV3, TotalCancelThenRetryableReport,
    testing::Values(
        // A signed later boots is adopted, so the next request is timely at once: one datagram.
        // Unadopted, it would draw a notInTimeWindows of its own and retry: two.
        RetryableReport{ScriptedV3Agent::notInTimeWindows, SecurityLevel::AuthNoPriv, 4, 1,
                        "NotInTimeWindows"},
        // A signed lower boots forgets the Engine's clock (ADR-0010), so the next request
        // rediscovers the Engine, both phases, before it goes out: three. Remembered, it would be
        // untimely, forget the clock at its own Report and rediscover before retrying: four.
        RetryableReport{ScriptedV3Agent::notInTimeWindows, SecurityLevel::AuthNoPriv, 2, 3,
                        "BootsRegression"},
        // An unknownEngineIds forgets which Engine the Target reaches, so the next request
        // re-runs the identity phase first: two. The Engine keeps its synced clock, so there is
        // no time-sync phase. Remembered, the request would go straight out: one.
        RetryableReport{ScriptedV3Agent::unknownEngineIds, SecurityLevel::NoAuthNoPriv, 3, 2,
                        "UnknownEngineIds"}),
    [](const testing::TestParamInfo<RetryableReport>& param) {
      return std::string(param.param.name);
    });

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

// Over v3 a request does work of its own before it sends -- Engine Discovery, key localisation --
// so a Client stopped between a Walk's requests must refuse the next one before any of it.
TEST(ClientV3Walk, AWalkStoppedBetweenItsRequestsSendsNothingMore) {
  Fixture f;
  std::uint32_t next = 1;
  ScriptedV3Agent agent(f.io, credentials(), [&](const Pdu&) {
    Pdu p;
    p.type = PduType::Response;
    p.varbinds = {Varbind{Oid{1, 3, 6, 1, 2, 1, 1, next, 0}, Counter32{next}}};
    ++next;
    return p;
  });
  f.agent = &agent;

  int batches = 0;
  f.client.asyncWalk(
      targetFor(agent), credentials(), Oid{1, 3, 6, 1, 2, 1, 1}, WalkOptions{1},
      [&](std::span<const Varbind>) {
        ++batches;
        f.client.stop();
        return true;
      },
      [&](net::ErrorCode e) {
        f.ec = e;
        f.finish();
      });
  f.run();

  EXPECT_EQ(f.ec, Errc::ClientStopped) << f.ec.message();
  EXPECT_EQ(batches, 1);
  EXPECT_EQ(agent.requestsSeen(), 3) << "two for Engine Discovery, one for the first Batch";
}

// A Walk's time limit is a cancellation the caller asked for in advance, so ADR-0008's rule for
// cancellations holds: the Walk says it was cut short, not why the replies it never got to use were
// refused. Discovery succeeds; every Response after it carries a bad digest and is dropped.
TEST(ClientV3Walk, ATimeLimitEndsAWalkWhoseRepliesAreAllRefusedIncomplete) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  agent.setResponder([&agent](const ScriptedV3Agent::Request& req) {
    auto reply = agent.behaveLikeACompliantAgent(req);
    if (reply && reply->scoped.pdu.type == PduType::Response) reply->corruptDigest = true;
    return reply;
  });

  constexpr auto limit = std::chrono::milliseconds(200);
  WalkOptions options{2};
  options.timeLimit = limit;
  const auto start = std::chrono::steady_clock::now();
  f.client.asyncWalkCollect(test::longDeadlineTarget(agent), credentials(),
                            Oid{1, 3, 6, 1, 2, 1, 1}, options, f.collectToken());
  f.run();
  const auto took = std::chrono::steady_clock::now() - start;

  EXPECT_EQ(f.ec, Errc::WalkIncomplete) << f.ec.message();
  EXPECT_TRUE(f.collected.empty());
  EXPECT_GE(took, limit);
  EXPECT_LT(took, test::atOnceLimit(test::longDeadline)) << "the exchange's deadline ended it";
  EXPECT_EQ(agent.requestsSeen(), 3) << "two discovery exchanges, then the one refused attempt";
}

// ---------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------

// Every privacy protocol against a compliant Agent, discovery included. The Blumenthal and Reeder
// pairs are here together because the two extensions are mutually incompatible (ADR-0005): a
// Command Generator that derived one where the Agent derived the other would fail exactly here.
TEST(ClientV3, AuthPrivRoundTripsUnderEveryPrivacyProtocol) {
  for (const auto priv : {PrivProtocol::Des, PrivProtocol::Aes128, PrivProtocol::Aes192,
                          PrivProtocol::Aes256, PrivProtocol::Aes192C, PrivProtocol::Aes256C}) {
    Fixture f;
    ScriptedV3Agent agent(f.io, privCredentials(priv), echoAnswer);
    f.agent = &agent;

    f.client.asyncGet(targetFor(agent), privCredentials(priv), {sysDescr}, f.requestToken());
    f.run();

    EXPECT_FALSE(f.ec) << "privacy protocol " << static_cast<int>(priv) << ": " << f.ec.message();
    ASSERT_EQ(f.response.varbinds.size(), 1U);
    EXPECT_EQ(f.response.varbinds[0].name, sysDescr);
  }
}

// A request fetches the OpenSSL algorithms its Credentials need, and loads the legacy provider for
// DES, as it is initiated on the caller's thread, so neither happens on the strand mid-request
// (#47). With fetching refused from just after initiation, every privacy protocol still
// round-trips. Each runs in a process of its own (gtest_discover_tests), so nothing earlier fetched
// for it; the Agent derives its keys when it is constructed, which fetches the digest but neither
// the cipher, the HMAC, nor the legacy provider. OpenSSL's CSPRNG is drawn from first, outside the
// refusal: it fetches its generator on a thread's first draw, which is OpenSSL's per-thread state
// and no algorithm the Client could hold (threat model B7).
TEST(ClientV3, ARequestFetchesItsAlgorithmsAsItIsInitiated) {
  std::array<unsigned char, 16> firstDraw{};
  ASSERT_EQ(RAND_bytes(firstDraw.data(), static_cast<int>(firstDraw.size())), 1);
  for (const auto priv : {PrivProtocol::Des, PrivProtocol::Aes128, PrivProtocol::Aes192,
                          PrivProtocol::Aes256, PrivProtocol::Aes192C, PrivProtocol::Aes256C}) {
    Fixture f;
    ScriptedV3Agent agent(f.io, privCredentials(priv, AuthProtocol::Sha1), echoAnswer);
    f.agent = &agent;

    f.client.asyncGet(targetFor(agent), privCredentials(priv, AuthProtocol::Sha1), {sysDescr},
                      f.requestToken());
    const test::RefusedFetches refused;
    ASSERT_TRUE(refused.refusing());
    f.run();

    EXPECT_FALSE(f.ec) << "privacy protocol " << static_cast<int>(priv) << ": " << f.ec.message();
  }
}

// The same for both Walks, whose later requests all run on the strand: with fetching refused from
// just after initiation, a Walk of several Batches completes under DES and under AES.
TEST(ClientV3, AWalkFetchesItsAlgorithmsAsItIsInitiated) {
  std::array<unsigned char, 16> firstDraw{};
  ASSERT_EQ(RAND_bytes(firstDraw.data(), static_cast<int>(firstDraw.size())), 1);
  for (const auto priv : {PrivProtocol::Des, PrivProtocol::Aes128}) {
    for (const bool collect : {false, true}) {
      const auto creds = privCredentials(priv, AuthProtocol::Sha1);
      Fixture f;
      std::uint32_t next = 1;
      ScriptedV3Agent agent(f.io, creds, [&](const Pdu&) {
        Pdu p;
        p.type = PduType::Response;
        p.varbinds = {next > 3 ? Varbind{Oid{1, 3, 6, 1, 2, 1, 2, 1, 0}, Counter32{7}}  // past it
                               : Varbind{Oid{1, 3, 6, 1, 2, 1, 1, next, 0}, Counter32{next}}};
        ++next;
        return p;
      });
      f.agent = &agent;

      std::size_t walked = 0;
      if (collect) {
        f.client.asyncWalkCollect(targetFor(agent), creds, Oid{1, 3, 6, 1, 2, 1, 1}, WalkOptions{1},
                                  f.collectToken());
      } else {
        f.client.asyncWalk(
            targetFor(agent), creds, Oid{1, 3, 6, 1, 2, 1, 1}, WalkOptions{1},
            [&](std::span<const Varbind> batch) {
              walked += batch.size();
              return true;
            },
            [&](net::ErrorCode e) {
              f.ec = e;
              f.finish();
            });
      }
      const test::RefusedFetches refused;
      ASSERT_TRUE(refused.refusing());
      f.run();

      const auto* how = collect ? "asyncWalkCollect" : "asyncWalk";
      EXPECT_FALSE(f.ec) << how << ", privacy protocol " << static_cast<int>(priv) << ": "
                         << f.ec.message();
      EXPECT_EQ(collect ? f.collected.size() : walked, 3U) << how;
    }
  }
}

// An algorithm that will not fetch as a request is initiated refuses the request there, before
// anything is sent, Engine Discovery included: DES naming the legacy provider (ADR-0005), a hash
// UnsupportedAuthProtocol (Error.hpp), AES CryptoFailure. The refusal is not held -- the same
// request, once the algorithm fetches, goes through in the same process. Runs where nothing has
// been fetched (expectInFreshProcess), with what the Client needs besides drawn first: the CSPRNG,
// and the passwordDigest's SHA-256. An Agent derives its keys as it is constructed, which fetches
// its hash but no cipher, so while the request is refused the Agent for the SHA-512 case speaks
// SHA-1, leaving SHA-512 unfetched.
TEST(ClientV3, ARequestWhoseAlgorithmsWillNotFetchIsRefusedAsItIsInitiated) {
  test::expectInFreshProcess([]() -> std::string {
    std::array<unsigned char, 16> firstDraw{};
    if (RAND_bytes(firstDraw.data(), static_cast<int>(firstDraw.size())) != 1) return "RAND_bytes";
    net::ErrorCode ec;
    std::ignore = passwordToKey(AuthProtocol::Sha256, "maplesyrup", ec);
    if (ec) return "passwordToKey: " + ec.message();

    struct Case {
      const char* what = nullptr;
      Credentials creds;
      Errc refusedWith = Errc::CryptoFailure;
      Credentials agentWhileRefused;
    };
    const auto des = privCredentials(PrivProtocol::Des, AuthProtocol::Sha1);
    const auto aes = privCredentials(PrivProtocol::Aes128, AuthProtocol::Sha1);
    const std::array cases = {
        Case{"DES", des, Errc::LegacyProviderUnavailable, des},
        Case{"AES-128", aes, Errc::CryptoFailure, aes},
        Case{"SHA-512", credentials(AuthProtocol::Sha512), Errc::UnsupportedAuthProtocol,
             credentials(AuthProtocol::Sha1)},
    };
    std::string wrong;
    for (const auto& c : cases) {
      for (const bool refusing : {true, false}) {
        Fixture f;
        ScriptedV3Agent agent(f.io, refusing ? c.agentWhileRefused : c.creds, echoAnswer);
        f.agent = &agent;
        std::optional<test::RefusedFetches> refused;
        if (refusing) refused.emplace();
        f.client.asyncGet(targetFor(agent), c.creds, {sysDescr}, f.requestToken());
        refused.reset();
        f.io.run();

        const auto want = refusing ? make_error_code(c.refusedWith) : net::ErrorCode{};
        if (f.completions != 1 || f.ec != want) {
          wrong += std::string(c.what) + (refusing ? ", refused: " : ", fetching: ") +
                   f.ec.message() + "\n";
        }
        if (refusing && agent.requestsSeen() != 0) {
          wrong += std::string(c.what) + ": something was sent\n";
        }
      }
    }
    return wrong;
  });
}

// The ScopedPDU is what privacy hides, so nothing above the wire may recognise the OID that went
// out. Read off the datagram rather than inferred from the flags.
TEST(ClientV3, AuthPrivPutsNothingReadableOnTheWire) {
  Fixture f;
  ScriptedV3Agent agent(f.io, privCredentials(PrivProtocol::Aes128), echoAnswer);
  f.agent = &agent;
  std::vector<Octets> seen;
  agent.setOnDatagram(
      [&seen](std::span<const std::byte> d) { seen.emplace_back(d.begin(), d.end()); });

  f.client.asyncGet(targetFor(agent), privCredentials(PrivProtocol::Aes128), {sysDescr},
                    f.requestToken());
  f.run();

  ASSERT_FALSE(f.ec) << f.ec.message();
  // 1.3.6.1.2.1.1.1.0 encoded: the request's own OID, which must appear in no datagram.
  const Octets encodedOid{std::byte{0x2b}, std::byte{0x06}, std::byte{0x01}, std::byte{0x02},
                          std::byte{0x01}, std::byte{0x01}, std::byte{0x01}, std::byte{0x00}};
  for (const auto& datagram : seen) {
    EXPECT_EQ(std::ranges::search(datagram, encodedOid).begin(), datagram.end())
        << "a ScopedPDU went out in the clear";
  }
}

// An authPriv exchange still discovers first, and the second phase is encrypted like everything
// else: an Engine that enforces a minimum Security Level per user would refuse it otherwise.
TEST(ClientV3, AuthPrivDiscoversBeforeItAsks) {
  Fixture f;
  ScriptedV3Agent agent(f.io, privCredentials(PrivProtocol::Aes256), echoAnswer);
  f.agent = &agent;

  f.client.asyncGet(targetFor(agent), privCredentials(PrivProtocol::Aes256), {sysDescr},
                    f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(agent.requestsSeen(), 3);
}

// A reply we cannot open is dropped, not failed -- the same rule as a reply whose digest is wrong
// (ADR-0006). The request stays outstanding, retransmits, and at the deadline reports why the
// replies were unusable rather than Timeout (ADR-0008).
TEST(ClientV3, DropsAReplyEncryptedWithAnotherKey) {
  Fixture f;
  ScriptedV3Agent agent(f.io, privCredentials(PrivProtocol::Aes128), echoAnswer);
  f.agent = &agent;
  agent.setResponder([&agent](const ScriptedV3Agent::Request& req) {
    auto reply = agent.behaveLikeACompliantAgent(req);
    if (reply && reply->scoped.pdu.type == PduType::Response) reply->corruptPrivKey = true;
    return reply;
  });

  f.client.asyncGet(targetFor(agent), privCredentials(PrivProtocol::Aes128), {sysDescr},
                    f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::DecryptionFailed));
}

// usmStatsDecryptionErrors: the Agent could not open what we sent. Nothing about that is worth
// retrying, so it fails the request rather than costing a second round trip.
TEST(ClientV3, SurfacesADecryptionErrorReport) {
  Fixture f;
  ScriptedV3Agent agent(f.io, privCredentials(PrivProtocol::Aes128), echoAnswer);
  f.agent = &agent;
  agent.setResponder(
      [&agent](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (req.message.scoped.pdu.type == PduType::Get && !req.message.security.engineId.empty() &&
            req.message.scoped.pdu.varbinds.size() == 1) {
          return ScriptedV3Agent::report(ScriptedV3Agent::decryptionErrors,
                                         SecurityLevel::AuthNoPriv);
        }
        return agent.behaveLikeACompliantAgent(req);
      });

  f.client.asyncGet(targetFor(agent), privCredentials(PrivProtocol::Aes128), {sysDescr},
                    f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, make_error_code(Errc::DecryptionError));
}

// ---------------------------------------------------------------------------
// Reply matching
// ---------------------------------------------------------------------------

// RFC 3412 section 7.2 step 12: a Response counts only if its Security Level, user name,
// contextEngineID and contextName are the request's. Each row spoils one of them on an otherwise
// genuine Response, signed with the right key wherever its level is signed: what is refused is the
// mismatch, not the digest. A mismatch says nothing about the Target, so it is a silent drop and
// the request reports Timeout (ADR-0008).
struct MismatchedReply {
  Credentials agent;   // what the Agent holds, and so what it can sign and encrypt with
  Credentials client;  // what the request goes out under
  std::function<void(ScriptedV3Agent::Reply&)> spoil;
  const char* name;
};

class AMismatchedResponse : public testing::TestWithParam<MismatchedReply> {
 protected:
  AMismatchedResponse() { m_f.agent = &m_agent; }

  // Every data-plane Response spoiled; with `thenTheGenuineOne`, each is followed by the genuine
  // reply, so the request can only succeed if the spoiled one was refused.
  void answerSpoiled(bool thenTheGenuineOne) {
    m_agent.setResponder([this, thenTheGenuineOne](const ScriptedV3Agent::Request& req) {
      auto reply = m_agent.behaveLikeACompliantAgent(req);
      if (!reply || reply->scoped.pdu.type != PduType::Response) return reply;
      auto spoiled = *reply;
      GetParam().spoil(spoiled);
      for (auto& vb : spoiled.scoped.pdu.varbinds) vb.val = std::int32_t{666};
      if (!thenTheGenuineOne) return std::optional(spoiled);
      m_agent.answerLate(req, std::move(spoiled));
      return reply;
    });
  }

  Fixture m_f;
  ScriptedV3Agent m_agent{m_f.io, GetParam().agent, echoAnswer};
};

TEST_P(AMismatchedResponse, IsDroppedAndTheRequestTimesOut) {
  answerSpoiled(false);

  m_f.client.asyncGet(targetFor(m_agent, 1), GetParam().client, {sysDescr}, m_f.requestToken());
  m_f.run();

  EXPECT_EQ(m_f.ec, make_error_code(Errc::Timeout));
}

TEST_P(AMismatchedResponse, LeavesTheGenuineReplyToComplete) {
  answerSpoiled(true);

  m_f.client.asyncGet(targetFor(m_agent, 0), GetParam().client, {sysDescr}, m_f.requestToken());
  m_f.run();

  ASSERT_FALSE(m_f.ec) << m_f.ec.message();
  ASSERT_EQ(m_f.response.varbinds.size(), 1U);
  EXPECT_EQ(m_f.response.varbinds[0].val, Value(Octets{std::byte{'o'}, std::byte{'k'}}))
      << "the spoiled reply was the one accepted";
}

INSTANTIATE_TEST_SUITE_P(
    ClientV3, AMismatchedResponse,
    testing::Values(
        // The bug this suite was written for: the data crossed the wire in the clear, and the
        // caller was never told.
        MismatchedReply{
            privCredentials(PrivProtocol::Aes128), privCredentials(PrivProtocol::Aes128),
            [](auto& r) { r.level = SecurityLevel::AuthNoPriv; }, "AuthNoPrivAnsweringAuthPriv"},
        MismatchedReply{credentials(), credentials(),
                        [](auto& r) { r.level = SecurityLevel::NoAuthNoPriv; },
                        "NoAuthNoPrivAnsweringAuthNoPriv"},
        // Higher is no better: nothing answers above the level it was asked at.
        MismatchedReply{credentials(), credentials(AuthProtocol::None, SecurityLevel::NoAuthNoPriv),
                        [](auto& r) { r.level = SecurityLevel::AuthNoPriv; },
                        "AuthNoPrivAnsweringNoAuthNoPriv"},
        MismatchedReply{credentials(), credentials(), [](auto& r) { r.userName = "ernie"; },
                        "AnotherUserName"},
        // Signed with that user's own key, so under ours its digest is wrong. It is still a reply
        // for someone else, and says nothing about our Credentials: silence, not AuthFailed. At
        // authPriv it is encrypted with that user's privacy key as well.
        MismatchedReply{credentials(), credentials(),
                        [](auto& r) { r.signer = asErnie(credentials()); },
                        "AnotherUserNameUnderItsOwnKey"},
        MismatchedReply{privCredentials(PrivProtocol::Aes128),
                        privCredentials(PrivProtocol::Aes128),
                        [](auto& r) { r.signer = asErnie(privCredentials(PrivProtocol::Aes128)); },
                        "AnotherUserNameUnderItsOwnKeys"},
        MismatchedReply{credentials(), credentials(),
                        [](auto& r) {
                          r.scoped.contextEngineId = {std::byte{0x80}, std::byte{0x00},
                                                      std::byte{0x1f}, std::byte{0x88},
                                                      std::byte{0x09}};
                        },
                        "AnotherContextEngineId"},
        MismatchedReply{credentials(), credentials(),
                        [](auto& r) { r.scoped.contextName = "elsewhere"; }, "AnotherContextName"},
        // At authPriv the context is inside the ciphertext, so it is compared only once the reply
        // has verified and opened. Encrypted with the right key, it gets that far and is silent.
        MismatchedReply{
            privCredentials(PrivProtocol::Aes128), privCredentials(PrivProtocol::Aes128),
            [](auto& r) {
              r.scoped.contextEngineId = {std::byte{0x80}, std::byte{0x00}, std::byte{0x1f},
                                          std::byte{0x88}, std::byte{0x09}};
            },
            "AnotherContextEngineIdUnderEncryption"},
        MismatchedReply{privCredentials(PrivProtocol::Aes128),
                        privCredentials(PrivProtocol::Aes128),
                        [](auto& r) { r.scoped.contextName = "elsewhere"; },
                        "AnotherContextNameUnderEncryption"}),
    [](const testing::TestParamInfo<MismatchedReply>& row) { return std::string(row.param.name); });

// The one Response matched on its level alone. Engine Discovery's identity phase names no user and
// no context, and an Agent that answers it with a Response rather than a Report quotes its own
// back: the user it knows and its own engineID as the contextEngineID. Its answer is read for the
// engineID and trusted with nothing (RFC 3414 section 4), so neither is a mismatch there.
TEST(ClientV3, AnIdentityPhaseAnsweredWithAResponseStillDiscovers) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  int identityResponses = 0;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (!req.message.security.engineId.empty()) return agent.behaveLikeACompliantAgent(req);
        ++identityResponses;
        ScriptedV3Agent::Reply reply;
        reply.level = SecurityLevel::NoAuthNoPriv;
        reply.scoped.pdu = echoAnswer(req.message.scoped.pdu);
        return reply;
      });

  f.client.asyncGet(targetFor(agent, 0), credentials(), {sysDescr}, f.requestToken());
  f.run();

  ASSERT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(identityResponses, 1);
  ASSERT_EQ(f.response.varbinds.size(), 1U);
  EXPECT_EQ(f.response.varbinds[0].name, sysDescr);
}

// CVE-2008-0960: a verifier that trusted the digest's width as sent compared only that many
// octets, so a 1-octet digest was a 1-in-256 guess and an empty one no guess at all. These carry
// the true digest's leading octets, which such a verifier accepts outright. The width must be the
// protocol's exactly, and a digest that is not is a digest that does not verify (ADR-0008).
TEST(ClientV3, RejectsADigestNarrowerThanTheProtocols) {
  for (const std::size_t width : {std::size_t{1}, std::size_t{0}}) {
    Fixture f;
    ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
    f.agent = &agent;
    agent.setResponder([&agent, width](const ScriptedV3Agent::Request& req) {
      auto reply = agent.behaveLikeACompliantAgent(req);
      if (reply && reply->scoped.pdu.type == PduType::Response) reply->digestWidth = width;
      return reply;
    });

    f.client.asyncGet(targetFor(agent, 0), credentials(), {sysDescr}, f.requestToken());
    f.run();

    EXPECT_EQ(f.ec, make_error_code(Errc::AuthFailed)) << width << "-octet digest";
  }
}

// ---------------------------------------------------------------------------
// Master Keys
// ---------------------------------------------------------------------------

Octets engineIdNumbered(std::uint8_t n) {
  return {std::byte{0x80}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x88},
          std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{n}};
}

TEST(ClientV3MasterKey, AuthNoPrivSucceedsAndDerivesNothing) {
  for (const auto protocol :
       {AuthProtocol::Md5, AuthProtocol::Sha1, AuthProtocol::Sha256, AuthProtocol::Sha512}) {
    Fixture f;
    ScriptedV3Agent agent(f.io, credentials(protocol), echoAnswer);
    f.agent = &agent;

    f.client.asyncGet(targetFor(agent), withMasterKeys(credentials(protocol)), {sysDescr},
                      f.requestToken());
    f.run();

    EXPECT_FALSE(f.ec) << "protocol " << static_cast<int>(protocol) << ": " << f.ec.message();
    ASSERT_EQ(f.response.varbinds.size(), 1U);
    EXPECT_EQ(f.response.varbinds[0].name, sysDescr);
    const auto counts = detail::CacheView::counts(f.client);
    EXPECT_EQ(counts.masterKeyDerivations, 0U)
        << "a Master Key the caller supplied is never derived";
    EXPECT_EQ(counts.masterKeys, 0U) << "nor cached";
  }
}

// SHA-1 and MD5 keys are shorter than AES-192's and AES-256's, so these pairs are the ones where
// the Key Extension runs, and where Blumenthal and Reeder disagree (ADR-0005).
TEST(ClientV3MasterKey, AuthPrivSucceedsUnderBothKeyExtensions) {
  for (const auto auth : {AuthProtocol::Md5, AuthProtocol::Sha1}) {
    for (const auto priv : {PrivProtocol::Des, PrivProtocol::Aes128, PrivProtocol::Aes192,
                            PrivProtocol::Aes256, PrivProtocol::Aes192C, PrivProtocol::Aes256C}) {
      Fixture f;
      ScriptedV3Agent agent(f.io, privCredentials(priv, auth), echoAnswer);
      f.agent = &agent;

      f.client.asyncGet(targetFor(agent), withMasterKeys(privCredentials(priv, auth)), {sysDescr},
                        f.requestToken());
      f.run();

      EXPECT_FALSE(f.ec) << "auth " << static_cast<int>(auth) << " priv " << static_cast<int>(priv)
                         << ": " << f.ec.message();
      ASSERT_EQ(f.response.varbinds.size(), 1U);
      EXPECT_EQ(f.response.varbinds[0].name, sysDescr);
      EXPECT_EQ(detail::CacheView::counts(f.client).masterKeyDerivations, 0U);
    }
  }
}

// A key one Octet short, one Octet long, empty, or derived under a hash of another width: each
// would sign or encrypt with something the Agent can never match, so each is refused before
// anything is sent, Engine Discovery included.
TEST(ClientV3MasterKey, AWrongLengthMasterKeyIsRefused) {
  net::ErrorCode ec;
  const auto sha1Key = passwordToKey(AuthProtocol::Sha1, "maplesyrup", ec);
  ASSERT_FALSE(ec) << ec.message();
  const auto good = withMasterKeys(privCredentials(PrivProtocol::Aes128));
  const auto shortened = [](SecretOctets key) {
    key.pop_back();
    return key;
  };
  const auto lengthened = [](SecretOctets key) {
    key.push_back(std::byte{0});
    return key;
  };

  std::vector<Credentials> cases;
  for (const auto& key :
       {shortened(*good.authMasterKey), lengthened(*good.authMasterKey), SecretOctets{}, sha1Key}) {
    auto authWrong = good;
    authWrong.authMasterKey = key;
    cases.push_back(authWrong);
    auto privWrong = good;
    privWrong.privMasterKey = key;
    cases.push_back(privWrong);
  }

  for (std::size_t i = 0; i < cases.size(); ++i) {
    Fixture f;
    ScriptedV3Agent agent(f.io, privCredentials(PrivProtocol::Aes128), echoAnswer);
    f.agent = &agent;

    f.client.asyncGet(targetFor(agent), cases[i], {sysDescr}, f.requestToken());
    f.run();

    EXPECT_EQ(f.ec, Errc::ArgumentOutOfRange) << "case " << i << ": " << f.ec.message();
    EXPECT_EQ(agent.requestsSeen(), 0) << "case " << i << ": nothing is sent";
  }
}

// A Walk takes its Credentials through the same check, before its first request.
TEST(ClientV3MasterKey, AWalkWithAWrongLengthMasterKeyIsRefused) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  auto creds = withMasterKeys(credentials());
  creds.authMasterKey->pop_back();
  f.client.asyncWalkCollect(targetFor(agent), creds, Oid{1, 3, 6, 1, 2, 1, 1}, WalkOptions{},
                            f.collectToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::ArgumentOutOfRange) << f.ec.message();
  EXPECT_EQ(agent.requestsSeen(), 0);
}

// "In place of" the password, not beside it: with both, which one the Agent holds cannot be told
// from here without deriving the very key the caller supplied to avoid deriving. Refused rather
// than resolved by a rule the caller has to know.
TEST(ClientV3MasterKey, AMasterKeyBesideItsPasswordIsRefused) {
  for (const bool privacy : {false, true}) {
    Fixture f;
    ScriptedV3Agent agent(f.io, privCredentials(PrivProtocol::Aes128), echoAnswer);
    f.agent = &agent;

    auto creds = withMasterKeys(privCredentials(PrivProtocol::Aes128));
    if (privacy) {
      creds.privPassword = "privatepass";
    } else {
      creds.authPassword = "maplesyrup";
    }
    f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
    f.run();

    EXPECT_EQ(f.ec, Errc::ArgumentOutOfRange) << (privacy ? "privacy" : "authentication");
    EXPECT_EQ(agent.requestsSeen(), 0);
  }
}

// A privacy Master Key at authNoPriv is never used, but one that could never be right is still a
// mistake in the Credentials, and is refused rather than waiting for the level to be raised.
TEST(ClientV3MasterKey, AnUnusedPrivacyMasterKeyIsStillChecked) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(AuthProtocol::Sha256), echoAnswer);
  f.agent = &agent;

  auto creds = withMasterKeys(credentials(AuthProtocol::Sha256));
  ASSERT_EQ(creds.level, SecurityLevel::AuthNoPriv);
  creds.privMasterKey = SecretOctets(3, std::byte{0});
  f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::ArgumentOutOfRange);
  EXPECT_EQ(agent.requestsSeen(), 0);
}

// One Client polling several Engines with one user: the password costs one Master Key per secret,
// not one per Engine, and each Engine one Localized Key per secret -- a short hash.
TEST(ClientV3MasterKey, OnePasswordDerivesItsMasterKeyOncePerClient) {
  net::IoContext io;
  Client client{io.get_executor()};
  constexpr int engines = 3;
  const auto creds = privCredentials(PrivProtocol::Aes128);

  std::vector<std::unique_ptr<ScriptedV3Agent>> agents;
  for (int i = 0; i < engines; ++i) {
    agents.push_back(std::make_unique<ScriptedV3Agent>(io, creds, echoAnswer));
    agents.back()->setEngineId(engineIdNumbered(static_cast<std::uint8_t>(i + 1)));
  }

  int completions = 0;
  for (const auto& agent : agents) {
    client.asyncGet(targetFor(*agent), creds, {sysDescr}, [&](net::ErrorCode e, const Response&) {
      EXPECT_FALSE(e) << e.message();
      if (++completions < engines) return;
      client.stop();
      for (const auto& a : agents) a->close();
    });
  }
  io.run();
  ASSERT_EQ(completions, engines);

  const auto counts = detail::CacheView::counts(client);
  EXPECT_EQ(counts.masterKeyDerivations, 2U)
      << "one for the authentication password, one for privacy, whatever the number of Engines";
  EXPECT_EQ(counts.masterKeys, 2U);
  EXPECT_EQ(counts.localizedKeys, 2U * engines) << "two per Engine";
}

// The same password under two hashes is two Master Keys: what the cache is keyed on is what the
// derivation consumes.
TEST(ClientV3MasterKey, OnePasswordUnderTwoHashesIsTwoMasterKeys) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(AuthProtocol::Sha1), echoAnswer);
  f.agent = &agent;

  const auto target = targetFor(agent);
  f.client.asyncGet(
      target, credentials(AuthProtocol::Sha1), {sysDescr}, [&](net::ErrorCode e, const Response&) {
        EXPECT_FALSE(e) << e.message();
        f.client.asyncGet(target, credentials(AuthProtocol::Sha256), {sysDescr}, f.requestToken());
        f.finish();
      });
  f.run();

  // The second fails at the Agent, which holds the SHA-1 user; the derivation happened regardless.
  EXPECT_EQ(detail::CacheView::counts(f.client).masterKeyDerivations, 2U);
  EXPECT_EQ(detail::CacheView::counts(f.client).masterKeys, 2U);
}

// What holds a Client's deriver busy (detail::DeriverView), and lets it go: on release(), or when
// it goes out of scope, so that a test failing early does not leave the deriver's join waiting on
// it. Declared after the Fixture it occupies, so that it goes first.
class DeriverHold {
 public:
  explicit DeriverHold(Client& client) {
    detail::DeriverView::occupy(client, [released = m_released] { released->wait(false); });
  }
  DeriverHold(const DeriverHold&) = delete;
  DeriverHold& operator=(const DeriverHold&) = delete;
  DeriverHold(DeriverHold&&) = delete;
  DeriverHold& operator=(DeriverHold&&) = delete;
  ~DeriverHold() { release(); }

  void release() {
    m_released->store(true);
    m_released->notify_all();
  }
  [[nodiscard]] bool released() const { return m_released->load(); }

  // Releases the deriver once `after` has passed on `io`: long enough for every request the test
  // has made to reach the derivation it queues behind, over loopback.
  void releaseAfter(net::IoContext& io, std::chrono::milliseconds after) {
    m_timer.emplace(io, after);
    m_timer->async_wait([this](net::ErrorCode) { release(); });
  }

 private:
  std::shared_ptr<std::atomic<bool>> m_released = std::make_shared<std::atomic<bool>>(false);
  std::optional<net::SteadyTimer> m_timer;
};

constexpr std::chrono::milliseconds derivationHeld{200};

// #80: a password's Master Key is derived on the Client's deriver, never on its strand. With the
// deriver held, the request can get no further than the identity phase, which needs no key; derived
// on the strand, it would not need the deriver at all, and would be answered before the release.
TEST(ClientV3Derivation, APasswordsMasterKeyIsDerivedOffTheStrand) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  DeriverHold hold(f.client);
  hold.releaseAfter(f.io, derivationHeld);

  int seenBeforeRelease = -1;
  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr},
                    [&](net::ErrorCode e, const Response& r) {
                      EXPECT_TRUE(hold.released()) << "derived without the deriver";
                      f.requestToken()(e, r);
                    });
  net::SteadyTimer check(f.io, derivationHeld / 2);
  check.async_wait([&](net::ErrorCode) { seenBeforeRelease = agent.requestsSeen(); });
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(seenBeforeRelease, 1) << "only the identity phase goes out before the keys are derived";
  EXPECT_EQ(detail::CacheView::counts(f.client).masterKeyDerivations, 1U);
}

// #80: Reeder's Key Extension reruns password-to-key, so it too runs on the deriver, even from a
// Master Key the caller supplied. SHA-1's 20 Octets are short of AES-256's 32, so it does run.
TEST(ClientV3Derivation, AReederExtensionIsDerivedOffTheStrand) {
  Fixture f;
  const auto creds = privCredentials(PrivProtocol::Aes256C, AuthProtocol::Sha1);
  ScriptedV3Agent agent(f.io, creds, echoAnswer);
  f.agent = &agent;
  DeriverHold hold(f.client);
  hold.releaseAfter(f.io, derivationHeld);

  int seenBeforeRelease = -1;
  f.client.asyncGet(targetFor(agent), withMasterKeys(creds), {sysDescr},
                    [&](net::ErrorCode e, const Response& r) {
                      EXPECT_TRUE(hold.released()) << "extended without the deriver";
                      f.requestToken()(e, r);
                    });
  net::SteadyTimer check(f.io, derivationHeld / 2);
  check.async_wait([&](net::ErrorCode) { seenBeforeRelease = agent.requestsSeen(); });
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_EQ(seenBeforeRelease, 1);
  const auto counts = detail::CacheView::counts(f.client);
  EXPECT_EQ(counts.masterKeyDerivations, 0U);
  EXPECT_EQ(counts.reederExtensions, 1U);
}

// The strand is free while the deriver works: a request needing no derivation is answered whole
// while another, to another Target, waits on its Master Key.
TEST(ClientV3Derivation, TheStrandServesOtherRequestsMeanwhile) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent waiting(f.io, credentials(), echoAnswer);
  ScriptedV3Agent served(f.io, credentials(), echoAnswer);
  served.setEngineId(engineIdNumbered(7));
  DeriverHold hold(f.client);

  f.client.asyncGet(targetFor(waiting), credentials(), {sysDescr},
                    [&](net::ErrorCode e, const Response&) {
                      EXPECT_FALSE(e) << e.message();
                      EXPECT_TRUE(hold.released());
                      waiting.close();
                      f.finish();
                    });
  f.client.asyncGet(targetFor(served), withMasterKeys(credentials()), {sysUpTime},
                    [&](net::ErrorCode e, const Response&) {
                      EXPECT_FALSE(e) << e.message();
                      EXPECT_FALSE(hold.released()) << "waited for the other's derivation";
                      served.close();
                      hold.release();
                      f.finish();
                    });
  f.run();
}

// Single-flight: three Engines met at once with one password wait on one derivation, where each
// would otherwise start its own.
TEST(ClientV3Derivation, ConcurrentRequestsShareOneMasterKeyDerivation) {
  net::IoContext io;
  Client client{io.get_executor()};
  constexpr int engines = 3;
  const auto creds = credentials();
  std::vector<std::unique_ptr<ScriptedV3Agent>> agents;
  for (int i = 0; i < engines; ++i) {
    agents.push_back(std::make_unique<ScriptedV3Agent>(io, creds, echoAnswer));
    agents.back()->setEngineId(engineIdNumbered(static_cast<std::uint8_t>(i + 1)));
  }
  DeriverHold hold(client);
  hold.releaseAfter(io, derivationHeld);

  int completions = 0;
  for (const auto& agent : agents) {
    client.asyncGet(targetFor(*agent), creds, {sysDescr}, [&](net::ErrorCode e, const Response&) {
      EXPECT_FALSE(e) << e.message();
      if (++completions < engines) return;
      client.stop();
      for (const auto& a : agents) a->close();
    });
  }
  io.run();
  ASSERT_EQ(completions, engines);

  const auto counts = detail::CacheView::counts(client);
  EXPECT_EQ(counts.masterKeyDerivations, 1U) << "one derivation, three waiters";
  EXPECT_EQ(counts.masterKeys, 1U);
}

// The same for a Reeder extension: one Engine behind two Targets (ADR-0003), discovered at both at
// once, needs one privacy key, extended once.
TEST(ClientV3Derivation, ConcurrentRequestsShareOneReederExtension) {
  net::IoContext io;
  Client client{io.get_executor()};
  const auto creds = privCredentials(PrivProtocol::Aes256C, AuthProtocol::Sha1);
  ScriptedV3Agent first(io, creds, echoAnswer);
  ScriptedV3Agent second(io, creds, echoAnswer);
  ASSERT_EQ(first.engineId(), second.engineId());
  DeriverHold hold(client);
  hold.releaseAfter(io, derivationHeld);

  int completions = 0;
  for (const auto* agent : {&first, &second}) {
    client.asyncGet(targetFor(*agent), withMasterKeys(creds), {sysDescr},
                    [&](net::ErrorCode e, const Response&) {
                      EXPECT_FALSE(e) << e.message();
                      if (++completions < 2) return;
                      client.stop();
                      first.close();
                      second.close();
                    });
  }
  io.run();
  ASSERT_EQ(completions, 2);
  EXPECT_EQ(detail::CacheView::counts(client).reederExtensions, 1U);
}

// A request waiting on a derivation keeps the rule it keeps queued behind Engine Discovery: either
// cancellation type ends it at once, with operation_aborted, and the derivation carries on for
// the request waiting with it. The Engine is discovered first with Master Keys, so that both
// requests wait on the derivation themselves rather than on a discovery.
class WaitingOnADerivation : public testing::TestWithParam<net::asio::cancellation_type> {};

TEST_P(WaitingOnADerivation, IsAbortedAndLeavesTheDerivationRunning) {
  Fixture f;
  f.expectedCompletions = 3;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  const auto target = targetFor(agent);
  std::optional<DeriverHold> hold;

  net::asio::cancellation_signal signal;
  net::ErrorCode cancelledEc;
  bool cancelledBeforeRelease = false;
  std::optional<net::SteadyTimer> cancelAt;
  f.client.asyncGet(target, withMasterKeys(credentials()), {sysDescr},
                    [&](net::ErrorCode e, const Response&) {
                      EXPECT_FALSE(e) << e.message();
                      hold.emplace(f.client);
                      hold->releaseAfter(f.io, derivationHeld);
                      f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
                      f.client.asyncGet(target, credentials(), {sysDescr},
                                        net::asio::bind_cancellation_slot(
                                            signal.slot(), [&](net::ErrorCode c, const Response&) {
                                              cancelledEc = c;
                                              cancelledBeforeRelease = !hold->released();
                                              f.finish();
                                            }));
                      cancelAt.emplace(f.io, derivationHeld / 2);
                      cancelAt->async_wait([&](net::ErrorCode) { signal.emit(GetParam()); });
                      f.finish();
                    });
  f.run();

  EXPECT_EQ(cancelledEc, net::asio::error::operation_aborted);
  EXPECT_TRUE(cancelledBeforeRelease) << "waited out the derivation before completing";
  EXPECT_FALSE(f.ec) << "cancelling one waiter took the derivation down with it: "
                     << f.ec.message();
  ASSERT_EQ(f.response.varbinds.size(), 1U);
  EXPECT_EQ(f.response.varbinds[0].name, sysUpTime);
  EXPECT_EQ(detail::CacheView::counts(f.client).masterKeyDerivations, 1U);
  // The discovery's two, the first request's, and the survivor's. The cancelled one sent nothing.
  EXPECT_EQ(agent.requestsSeen(), 4);
}

INSTANTIATE_TEST_SUITE_P(ClientV3Derivation, WaitingOnADerivation,
                         testing::Values(net::asio::cancellation_type::terminal,
                                         net::asio::cancellation_type::total));

// ADR-0009: Stopping waits for nothing that has not already started, and a derivation in progress
// is not something it waits for. A request waiting on one completes with ClientStopped at once,
// with the deriver still held; were stop() to wait for the derivation, it would never return.
TEST(ClientV3Derivation, StoppingDoesNotWaitForADerivation) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;
  DeriverHold hold(f.client);

  bool stoppedBeforeRelease = false;
  f.client.asyncGet(targetFor(agent), credentials(), {sysDescr},
                    [&](net::ErrorCode e, const Response& r) {
                      stoppedBeforeRelease = !hold.released();
                      hold.release();
                      f.requestToken()(e, r);
                    });
  net::SteadyTimer stopAt(f.io, derivationHeld / 2);
  stopAt.async_wait([&](net::ErrorCode) { f.client.stop(); });
  f.run();

  EXPECT_EQ(f.ec, Errc::ClientStopped) << f.ec.message();
  EXPECT_TRUE(stoppedBeforeRelease);
}

// The same, destroying the Client: its state lives on until the derivation it is waiting on has
// finished, and the io_context drains.
TEST(ClientV3Derivation, DestroyingTheClientDoesNotWaitForADerivation) {
  net::IoContext io;
  auto client = std::make_unique<Client>(io.get_executor());
  ScriptedV3Agent agent(io, credentials(), echoAnswer);
  auto hold = std::make_unique<DeriverHold>(*client);

  net::ErrorCode ec;
  bool completed = false;
  client->asyncGet(targetFor(agent), credentials(), {sysDescr},
                   net::asio::bind_executor(io, [&](net::ErrorCode e, const Response&) {
                     ec = e;
                     completed = true;
                   }));
  net::SteadyTimer destroyAt(io, derivationHeld / 2);
  destroyAt.async_wait([&](net::ErrorCode) {
    client.reset();
    hold->release();
    agent.close();
  });
  io.run();

  EXPECT_TRUE(completed);
  EXPECT_EQ(ec, Errc::ClientStopped) << ec.message();
}

// RFC 3414 section 11.2: a password is at least 8 characters. Refused before anything is sent,
// Engine Discovery included, as an argument out of range is -- for either secret.
TEST(ClientV3Password, ASevenCharacterPasswordIsRefused) {
  for (const bool privacy : {false, true}) {
    Fixture f;
    ScriptedV3Agent agent(f.io, privCredentials(PrivProtocol::Aes128), echoAnswer);
    f.agent = &agent;

    auto creds = privCredentials(PrivProtocol::Aes128);
    (privacy ? creds.privPassword : creds.authPassword) = "seven77";
    f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
    f.run();

    EXPECT_EQ(f.ec, Errc::PasswordTooShort)
        << (privacy ? "privacy" : "authentication") << ": " << f.ec.message();
    EXPECT_EQ(agent.requestsSeen(), 0) << "nothing is sent";
  }
}

TEST(ClientV3Password, AnEightCharacterPasswordIsAccepted) {
  const Credentials creds{"bert",     SecurityLevel::AuthPriv, AuthProtocol::Sha256,
                          "authpass", PrivProtocol::Aes128,    "privpass"};
  ASSERT_EQ(creds.authPassword.size(), 8U);
  ASSERT_EQ(creds.privPassword.size(), 8U);
  Fixture f;
  ScriptedV3Agent agent(f.io, creds, echoAnswer);
  f.agent = &agent;

  f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  ASSERT_EQ(f.response.varbinds.size(), 1U);
  EXPECT_EQ(f.response.varbinds[0].name, sysDescr);
}

// Empty is shorter than 8 too, where the Security Level needs the password; where it does not, an
// empty password is no password, and the usual way to leave the privacy secret unset.
TEST(ClientV3Password, AnEmptyPasswordIsRefusedOnlyWhereTheLevelNeedsIt) {
  {
    Fixture f;
    ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
    f.agent = &agent;
    auto creds = credentials();
    creds.authPassword.clear();
    f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
    f.run();
    EXPECT_EQ(f.ec, Errc::PasswordTooShort) << f.ec.message();
    EXPECT_EQ(agent.requestsSeen(), 0);
  }
  {
    Fixture f;
    ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
    f.agent = &agent;
    ASSERT_TRUE(credentials().privPassword.empty());
    f.client.asyncGet(targetFor(agent), credentials(), {sysDescr}, f.requestToken());
    f.run();
    EXPECT_FALSE(f.ec) << f.ec.message();
  }
}

// A short password the level does not use is still a mistake in the Credentials, as an unused
// Master Key of the wrong width is (AnUnusedPrivacyMasterKeyIsStillChecked).
TEST(ClientV3Password, AnUnusedShortPrivacyPasswordIsStillChecked) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  auto creds = credentials();
  ASSERT_EQ(creds.level, SecurityLevel::AuthNoPriv);
  creds.privPassword = "short";
  f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::PasswordTooShort) << f.ec.message();
  EXPECT_EQ(agent.requestsSeen(), 0);
}

// Both Walk styles check the Credentials as a request does, before any Batch is asked for: the
// streaming one and the collecting one, for either secret.
TEST(ClientV3Password, AWalkWithASevenCharacterPasswordIsRefused) {
  for (const bool collect : {false, true}) {
    for (const bool privacy : {false, true}) {
      Fixture f;
      ScriptedV3Agent agent(f.io, privCredentials(PrivProtocol::Aes128), echoAnswer);
      f.agent = &agent;

      auto creds = privCredentials(PrivProtocol::Aes128);
      (privacy ? creds.privPassword : creds.authPassword) = "seven77";
      int batches = 0;
      if (collect) {
        f.client.asyncWalkCollect(targetFor(agent), creds, Oid{1, 3, 6, 1, 2, 1, 1}, WalkOptions{},
                                  f.collectToken());
      } else {
        f.client.asyncWalk(
            targetFor(agent), creds, Oid{1, 3, 6, 1, 2, 1, 1}, WalkOptions{},
            [&](std::span<const Varbind>) {
              ++batches;
              return true;
            },
            [&](net::ErrorCode e) {
              f.ec = e;
              f.finish();
            });
      }
      f.run();

      const auto* what = privacy ? "privacy" : "authentication";
      const auto* how = collect ? "asyncWalkCollect" : "asyncWalk";
      EXPECT_EQ(f.ec, Errc::PasswordTooShort) << how << ", " << what << ": " << f.ec.message();
      EXPECT_EQ(batches, 0) << how << ", " << what;
      EXPECT_EQ(agent.requestsSeen(), 0) << how << ", " << what << ": nothing is sent";
    }
  }
}

TEST(ClientV3Password, AWalkWithEightCharacterPasswordsIsAccepted) {
  const Credentials creds{"bert",     SecurityLevel::AuthPriv, AuthProtocol::Sha256,
                          "authpass", PrivProtocol::Aes128,    "privpass"};
  for (const bool collect : {false, true}) {
    Fixture f;
    std::uint32_t next = 1;
    ScriptedV3Agent agent(f.io, creds, [&](const Pdu&) {
      Pdu p;
      p.type = PduType::Response;
      p.varbinds = {next > 3 ? Varbind{Oid{1, 3, 6, 1, 2, 1, 2, 1, 0}, Counter32{7}}  // past it
                             : Varbind{Oid{1, 3, 6, 1, 2, 1, 1, next, 0}, Counter32{next}}};
      ++next;
      return p;
    });
    f.agent = &agent;

    std::size_t walked = 0;
    if (collect) {
      f.client.asyncWalkCollect(targetFor(agent), creds, Oid{1, 3, 6, 1, 2, 1, 1}, WalkOptions{1},
                                f.collectToken());
    } else {
      f.client.asyncWalk(
          targetFor(agent), creds, Oid{1, 3, 6, 1, 2, 1, 1}, WalkOptions{1},
          [&](std::span<const Varbind> batch) {
            walked += batch.size();
            return true;
          },
          [&](net::ErrorCode e) {
            f.ec = e;
            f.finish();
          });
    }
    f.run();

    const auto* how = collect ? "asyncWalkCollect" : "asyncWalk";
    EXPECT_FALSE(f.ec) << how << ": " << f.ec.message();
    EXPECT_EQ(collect ? f.collected.size() : walked, 3U) << how;
  }
}

// A level that names no protocol for a secret is refused for the missing protocol, which is the
// mistake, not for the password nothing would have used.
TEST(ClientV3Password, AMissingProtocolIsReportedAheadOfItsMissingPassword) {
  struct Case {
    Credentials creds;
    Errc expected = Errc::Ok;
  };
  const std::array<Case, 2> cases = {{
      {Credentials{"bert", SecurityLevel::AuthNoPriv, AuthProtocol::None, "", PrivProtocol::None,
                   ""},
       Errc::UnsupportedAuthProtocol},
      {credentials(AuthProtocol::Sha256, SecurityLevel::AuthPriv), Errc::UnsupportedPrivProtocol},
  }};
  for (const auto& c : cases) {
    Fixture f;
    ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
    f.agent = &agent;
    f.client.asyncGet(targetFor(agent), c.creds, {sysDescr}, f.requestToken());
    f.run();
    EXPECT_EQ(f.ec, c.expected) << f.ec.message();
    EXPECT_EQ(agent.requestsSeen(), 0);
  }
}

// Only an empty password defers to the missing protocol. A short one is a password given, and
// refused as one, whatever protocol it was given for.
TEST(ClientV3Password, AShortPasswordForAMissingProtocolIsStillTooShort) {
  const std::array<Credentials, 2> cases = {{
      Credentials{"bert", SecurityLevel::AuthNoPriv, AuthProtocol::None, "short",
                  PrivProtocol::None, ""},
      Credentials{"bert", SecurityLevel::AuthPriv, AuthProtocol::Sha256, "maplesyrup",
                  PrivProtocol::None, "short"},
  }};
  for (const auto& creds : cases) {
    Fixture f;
    ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
    f.agent = &agent;
    f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
    f.run();
    EXPECT_EQ(f.ec, Errc::PasswordTooShort) << f.ec.message();
    EXPECT_EQ(agent.requestsSeen(), 0);
  }
}

// A stopped Client says so ahead of anything wrong with the Credentials, as it does ahead of an
// argument out of range.
TEST(ClientV3Password, AStoppedClientSaysSoAheadOfAShortPassword) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  auto creds = credentials();
  creds.authPassword = "seven77";
  f.client.stop();
  f.client.asyncGet(targetFor(agent), creds, {sysDescr}, f.requestToken());
  f.run();

  EXPECT_EQ(f.ec, Errc::ClientStopped) << f.ec.message();
}

// ---------------------------------------------------------------------------
// Bounded caches (threat model B2)
// ---------------------------------------------------------------------------

// RFC 3411's SnmpEngineID is SIZE(5..32), and RFC 3414 section 3.2 step 3 treats any other size as
// unknown. The codec still decodes one (CLAUDE.md's codec posture); the Client refuses to cache it.
struct EngineIdLength {
  std::size_t octets;
  SecurityLevel level;
  bool accepted;
};

class AnEngineIdOfLength : public testing::TestWithParam<EngineIdLength> {};

TEST_P(AnEngineIdOfLength, IsCachedOnlyWithinFiveToThirtyTwoOctets) {
  const auto [octets, level, accepted] = GetParam();
  Fixture f;
  const auto creds = credentials(AuthProtocol::Sha256, level);
  ScriptedV3Agent agent(f.io, creds, echoAnswer);
  f.agent = &agent;
  agent.setEngineId(Octets(octets, std::byte{0x2a}));

  f.client.asyncGet(targetFor(agent, 0), creds, {sysDescr}, f.requestToken());
  f.run();

  const auto counts = detail::CacheView::counts(f.client);
  if (accepted) {
    EXPECT_FALSE(f.ec) << f.ec.message();
    EXPECT_EQ(counts.engines, 1U);
    return;
  }
  EXPECT_EQ(f.ec, make_error_code(Errc::UnknownEngineId)) << f.ec.message();
  EXPECT_EQ(counts.engines, 0U);
  EXPECT_EQ(counts.localizedKeys, 0U);
  EXPECT_EQ(counts.masterKeys, 0U);
  EXPECT_EQ(agent.requestsSeen(), 1) << "nothing goes out under an engineID refused";
}

INSTANTIATE_TEST_SUITE_P(ClientV3Cache, AnEngineIdOfLength,
                         testing::Values(EngineIdLength{4, SecurityLevel::AuthNoPriv, false},
                                         EngineIdLength{33, SecurityLevel::AuthNoPriv, false},
                                         EngineIdLength{4, SecurityLevel::NoAuthNoPriv, false},
                                         EngineIdLength{33, SecurityLevel::NoAuthNoPriv, false},
                                         EngineIdLength{5, SecurityLevel::AuthNoPriv, true},
                                         EngineIdLength{32, SecurityLevel::AuthNoPriv, true}),
                         [](const testing::TestParamInfo<EngineIdLength>& param) {
                           return std::to_string(param.param.octets) + "Octets" +
                                  (param.param.level == SecurityLevel::NoAuthNoPriv ? "NoAuthNoPriv"
                                                                                    : "AuthNoPriv");
                         });

// research section 1.4.1: an Agent that answers every Engine Discovery with a fresh engineID. Each
// change reaches the Client as an unknownEngineIDs Report, which forgets the Engine at the Target,
// and the rediscovery after it maps the Target to the new one. The old one goes, keys and all.
TEST(ClientV3Cache, AFreshEngineIdOnEveryRediscoveryLeavesTheCachesBounded) {
  Fixture f;
  constexpr int rediscoveries = 16;
  f.expectedCompletions = rediscoveries + 1;
  const auto creds = privCredentials(PrivProtocol::Aes128);
  ScriptedV3Agent agent(f.io, creds, echoAnswer);
  f.agent = &agent;

  const auto target = targetFor(agent);
  std::vector<detail::CacheCounts> seen;
  std::function<void()> ask = [&] {
    f.client.asyncGet(target, creds, {sysDescr}, [&](net::ErrorCode e, const Response&) {
      EXPECT_FALSE(e) << "request " << seen.size() << ": " << e.message();
      seen.push_back(detail::CacheView::counts(f.client));
      agent.setEngineId(engineIdNumbered(static_cast<std::uint8_t>(seen.size())));
      if (f.completions + 1 < f.expectedCompletions) ask();
      f.finish();
    });
  };
  ask();
  f.run();

  ASSERT_EQ(seen.size(), static_cast<std::size_t>(rediscoveries + 1));
  for (std::size_t i = 0; i < seen.size(); ++i) {
    EXPECT_EQ(seen[i].engines, 1U) << "after request " << i;
    EXPECT_EQ(seen[i].localizedKeys, 2U) << "after request " << i << ": one per secret";
  }
  EXPECT_EQ(seen.back().masterKeys, 2U) << "Master Keys are per password, not per Engine";
}

// The same Agent seen from inside one Engine Discovery: its identity phase names a fresh engineID
// every time, and its time-sync phase, sent under that engineID, is refused with an unsigned
// unknownEngineIDs Report, which ends that discovery (R6). The identity phase has already mapped
// the Target, and localised its keys, by then, so each discovery replaces the last one's Engine.
TEST(ClientV3Cache, AnIdentityPhaseNamingAFreshEngineIdEachTimeLeavesTheCachesBounded) {
  Fixture f;
  constexpr int discoveries = 16;
  f.expectedCompletions = discoveries;
  const auto creds = privCredentials(PrivProtocol::Aes128);
  ScriptedV3Agent agent(f.io, creds, echoAnswer);
  f.agent = &agent;

  std::uint8_t named = 0;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        auto reply = agent.behaveLikeACompliantAgent(req);
        if (reply && req.message.security.engineId.empty())
          reply->engineId = engineIdNumbered(++named);
        return reply;
      });

  const auto target = targetFor(agent);
  std::vector<detail::CacheCounts> seen;
  std::function<void()> ask = [&] {
    f.client.asyncGet(target, creds, {sysDescr}, [&](net::ErrorCode e, const Response&) {
      EXPECT_EQ(e, make_error_code(Errc::UnknownEngineId)) << "request " << seen.size();
      seen.push_back(detail::CacheView::counts(f.client));
      if (f.completions + 1 < f.expectedCompletions) ask();
      f.finish();
    });
  };
  ask();
  f.run();

  ASSERT_EQ(seen.size(), static_cast<std::size_t>(discoveries));
  EXPECT_EQ(named, discoveries) << "one identity phase per request";
  for (std::size_t i = 0; i < seen.size(); ++i) {
    EXPECT_EQ(seen[i].engines, 1U) << "after request " << i;
    EXPECT_EQ(seen[i].localizedKeys, 2U) << "after request " << i << ": one per secret";
  }
}

// The other way a Target's Engine is replaced: still mapped, not forgotten, when a request that
// authenticates finds the Engine a noAuthNoPriv discovery left unsynchronised and discovers again.
TEST(ClientV3Cache, AnEngineReplacedAtItsOnlyTargetIsEvicted) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  const auto target = targetFor(agent);
  const auto plain = credentials(AuthProtocol::Sha256, SecurityLevel::NoAuthNoPriv);
  f.client.asyncGet(target, plain, {sysDescr}, [&](net::ErrorCode e, const Response&) {
    EXPECT_FALSE(e) << e.message();
    agent.setEngineId(engineIdNumbered(9));
    f.client.asyncGet(target, credentials(), {sysDescr}, f.requestToken());
    f.finish();
  });
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  const auto counts = detail::CacheView::counts(f.client);
  EXPECT_EQ(counts.engines, 1U);
  EXPECT_EQ(counts.localizedKeys, 1U);
}

// The other side of forgetting: an unsigned unknownEngineIDs Report about an Engine that has not
// changed. The rediscovery finds the one that was kept, synchronised clock and keys, so it costs
// the identity phase and nothing more (E1).
TEST(ClientV3Cache, AForgottenEngineThatComesBackUnchangedIsKept) {
  Fixture f;
  f.expectedCompletions = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.agent = &agent;

  bool settled = false;
  bool reported = false;
  int timeSyncPhases = 0;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (isTimeSyncPhase(req)) ++timeSyncPhases;
        if (settled && !reported && !req.message.security.engineId.empty()) {
          reported = true;
          return ScriptedV3Agent::report(ScriptedV3Agent::unknownEngineIds,
                                         SecurityLevel::NoAuthNoPriv);
        }
        return agent.behaveLikeACompliantAgent(req);
      });

  const auto target = targetFor(agent);
  f.client.asyncGet(target, credentials(), {sysDescr}, [&](net::ErrorCode e, const Response&) {
    EXPECT_FALSE(e) << e.message();
    settled = true;
    f.client.asyncGet(target, credentials(), {sysUpTime}, f.requestToken());
    f.finish();
  });
  f.run();

  EXPECT_FALSE(f.ec) << f.ec.message();
  EXPECT_TRUE(reported);
  EXPECT_EQ(timeSyncPhases, 1) << "the forgotten Engine was evicted, clock and all";
  const auto counts = detail::CacheView::counts(f.client);
  EXPECT_EQ(counts.engines, 1U);
  EXPECT_EQ(counts.localizedKeys, 1U);
}

// ADR-0003: one Engine behind two Targets is one entry. When one Target's Engine changes, the
// shared one stays for the other -- which then needs no rediscovery -- and goes only once neither
// maps to it.
TEST(ClientV3Cache, OneEngineAtTwoTargetsIsOneEntryUntilNeitherMapsToIt) {
  net::IoContext io;
  Client client{io.get_executor()};
  const auto creds = credentials();
  ScriptedV3Agent first(io, creds, echoAnswer);
  ScriptedV3Agent second(io, creds, echoAnswer);  // the same engineID: the same Engine
  ASSERT_EQ(first.engineId(), second.engineId());

  const auto expectCounts = [&client](std::size_t engines, const char* when) {
    const auto counts = detail::CacheView::counts(client);
    EXPECT_EQ(counts.engines, engines) << when;
    EXPECT_EQ(counts.localizedKeys, engines) << when;
  };
  // One GET to an Agent, and then what follows it.
  const auto get = [&](ScriptedV3Agent& agent, std::function<void()> then) {
    client.asyncGet(targetFor(agent), creds, {sysDescr},
                    [then = std::move(then)](net::ErrorCode e, const Response&) {
                      EXPECT_FALSE(e) << e.message();
                      then();
                    });
  };

  bool finished = false;
  get(first, [&] {
    get(second, [&] {
      expectCounts(1, "one Engine, two Targets");
      first.setEngineId(engineIdNumbered(2));
      get(first, [&] {
        expectCounts(2, "the shared Engine stays for the second Target");
        const int secondSeen = second.requestsSeen();
        get(second, [&, secondSeen] {
          EXPECT_EQ(second.requestsSeen() - secondSeen, 1) << "no rediscovery: still cached";
          expectCounts(2, "still mapped from the second Target");
          second.setEngineId(engineIdNumbered(3));
          get(second, [&] {
            expectCounts(2, "the shared Engine is gone once neither Target maps to it");
            finished = true;
            client.stop();
            first.close();
            second.close();
          });
        });
      });
    });
  });
  io.run();
  EXPECT_TRUE(finished);
}

}  // namespace
}  // namespace snmpio
