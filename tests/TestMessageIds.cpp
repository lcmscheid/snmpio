#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/detail/MessageIdView.hpp>

#include "Deadlines.hpp"
#include "ScriptedAgent.hpp"
#include "ScriptedV3Agent.hpp"

// Message IDs and request-ids, as the Agent sees them: unpredictable, fresh for every
// transmission, and never shared by two Outstanding Requests (threat model R7). Every check is made
// at the Scripted Agent, since what matters is what goes out on the wire.
namespace snmpio {
namespace {

using detail::MessageIdView;
using test::echoAnswer;
using test::longDeadlineTarget;
using test::respondWith;
using test::ScriptedAgent;
using test::ScriptedV3Agent;
using test::targetFor;

const Community publicCommunity{Community("public")};
const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};

Credentials credentials() {
  return Credentials{"bert",       SecurityLevel::AuthPriv, AuthProtocol::Sha256,
                     "maplesyrup", PrivProtocol::Aes128,    "privatepass"};
}

// One io_context on the test thread, stopped once every operation has completed, so that a hung
// operation is a hung test rather than a flake.
struct Fixture {
  net::IoContext io;
  Client client{io.get_executor()};
  std::function<void()> closeAgent;
  int expected = 1;
  int completions = 0;

  void finish() {
    if (++completions < expected) return;
    client.stop();
    if (closeAgent) closeAgent();
  }

  void run() {
    io.run();
    EXPECT_EQ(completions, expected) << "an operation never completed";
  }
};

// True if any two neighbours are one apart, which a counter's IDs are.
bool anyConsecutive(const std::vector<std::int32_t>& ids) {
  for (std::size_t i = 1; i < ids.size(); ++i) {
    if (static_cast<std::int64_t>(ids[i]) - ids[i - 1] == 1) return true;
  }
  return false;
}

bool allDistinct(const std::vector<std::int32_t>& ids) {
  return std::set<std::int32_t>(ids.begin(), ids.end()).size() == ids.size();
}

// The request-ids one Client sends for `count` GETs, in the order its Agent read them.
std::vector<std::int32_t> requestIdsOfOneClient(int count) {
  Fixture f;
  f.expected = count;
  std::vector<std::int32_t> ids;
  ScriptedAgent agent(f.io, [&ids](const V2cMessage& msg) {
    ids.push_back(msg.pdu.requestId);
    return respondWith({Varbind{msg.pdu.varbinds.at(0).name, null}});
  });
  f.closeAgent = [&agent] { agent.close(); };

  for (int i = 0; i < count; ++i) {
    f.client.asyncGet(longDeadlineTarget(agent), publicCommunity, {sysDescr},
                      [&f](net::ErrorCode ec, const Response&) {
                        EXPECT_FALSE(ec) << ec.message();
                        f.finish();
                      });
  }
  f.run();
  return ids;
}

TEST(MessageIds, ConsecutiveRequestIdsAreNotSequential) {
  const auto ids = requestIdsOfOneClient(64);
  ASSERT_EQ(ids.size(), 64U);
  // A counter would put every one a step from the last, and an Agent that sees some would know
  // the rest -- those outstanding at every other Target included.
  EXPECT_FALSE(anyConsecutive(ids));
  EXPECT_TRUE(allDistinct(ids));
}

TEST(MessageIds, TwoClientsDrawDifferentIds) {
  // Each Client keys its own: two that drew the same key would hand each other's Agents the IDs.
  const auto first = requestIdsOfOneClient(16);
  const auto second = requestIdsOfOneClient(16);
  ASSERT_EQ(first.size(), 16U);
  ASSERT_EQ(second.size(), 16U);
  EXPECT_NE(first, second);
}

TEST(MessageIds, EachRetransmissionCarriesAFreshRequestId) {
  Fixture f;
  std::vector<std::int32_t> ids;
  ScriptedAgent agent(f.io, [&ids](const V2cMessage& msg) {
    ids.push_back(msg.pdu.requestId);
    return std::nullopt;
  });
  f.closeAgent = [&agent] { agent.close(); };

  f.client.asyncGet(targetFor(agent, 3), publicCommunity, {sysDescr},
                    [&f](net::ErrorCode ec, const Response&) {
                      EXPECT_EQ(ec, Errc::Timeout);
                      f.finish();
                    });
  f.run();

  ASSERT_EQ(ids.size(), 4U);  // the first attempt and three retransmissions
  EXPECT_TRUE(allDistinct(ids));
}

// Every exchange is answered only on its second transmission: Engine Discovery's two phases, then
// the request itself. Each phase must have sent two different Message IDs, and the request two
// different request-ids as well.
TEST(MessageIds, EachV3RetransmissionCarriesAFreshMessageIdDiscoveryIncluded) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.closeAgent = [&agent] { agent.close(); };

  enum class Phase { Identity, TimeSync, Request };
  std::map<Phase, std::vector<std::int32_t>> msgIds;
  std::vector<std::int32_t> requestIds;
  std::vector<std::int32_t> everyMsgId;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        const auto& m = req.message;
        Phase phase = Phase::Request;
        if (m.security.engineId.empty()) {
          phase = Phase::Identity;
        } else if (m.scoped.pdu.varbinds.empty()) {
          phase = Phase::TimeSync;
        }
        auto& ids = msgIds[phase];
        ids.push_back(m.header.msgId);
        everyMsgId.push_back(m.header.msgId);
        if (phase == Phase::Request) requestIds.push_back(m.scoped.pdu.requestId);
        if (ids.size() == 1) return std::nullopt;  // the first transmission is lost
        return agent.behaveLikeACompliantAgent(req);
      });

  f.client.asyncGet(targetFor(agent, 1), credentials(), {sysDescr},
                    [&f](net::ErrorCode ec, const Response& r) {
                      EXPECT_FALSE(ec) << ec.message();
                      EXPECT_EQ(r.varbinds.size(), 1U);
                      f.finish();
                    });
  f.run();

  for (const auto phase : {Phase::Identity, Phase::TimeSync, Phase::Request}) {
    ASSERT_EQ(msgIds[phase].size(), 2U);
    EXPECT_NE(msgIds[phase][0], msgIds[phase][1]);
  }
  ASSERT_EQ(requestIds.size(), 2U);
  EXPECT_NE(requestIds[0], requestIds[1]);
  // One generator serves every exchange, discovery's too, and none of it counts up.
  EXPECT_TRUE(allDistinct(everyMsgId));
  EXPECT_FALSE(anyConsecutive(everyMsgId));
}

// The reply to the first transmission arrives only once the retransmission has gone out: a reply
// delayed in the network, which must still count (CONTEXT.md, Message ID).
TEST(MessageIds, AReplyToTheFirstTransmissionCountsAfterARetransmission) {
  Fixture f;
  std::optional<V2cMessage> first;
  ScriptedAgent* self = nullptr;
  ScriptedAgent agent(f.io, [&](const V2cMessage& msg) -> std::optional<Pdu> {
    if (!first) {
      first = msg;
      return std::nullopt;
    }
    EXPECT_NE(msg.pdu.requestId, first->pdu.requestId);
    self->answerLate(*first, respondWith({Varbind{sysDescr, std::int32_t{7}}}));
    return std::nullopt;
  });
  self = &agent;
  f.closeAgent = [&agent] { agent.close(); };

  f.client.asyncGet(targetFor(agent, 1), publicCommunity, {sysDescr},
                    [&f](net::ErrorCode ec, const Response& r) {
                      EXPECT_FALSE(ec) << ec.message();
                      ASSERT_EQ(r.varbinds.size(), 1U);
                      EXPECT_EQ(r.varbinds[0].val, Value(std::int32_t{7}));
                      f.finish();
                    });
  f.run();

  EXPECT_EQ(agent.requestsSeen(), 2);
}

TEST(MessageIds, AV3ReplyToTheFirstTransmissionCountsAfterARetransmission) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.closeAgent = [&agent] { agent.close(); };

  std::optional<ScriptedV3Agent::Request> first;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (req.message.scoped.pdu.varbinds.empty()) return agent.behaveLikeACompliantAgent(req);
        if (!first) {
          first = req;
          return std::nullopt;
        }
        EXPECT_NE(req.message.header.msgId, first->message.header.msgId);
        const auto reply = agent.behaveLikeACompliantAgent(*first);
        if (reply) agent.answerLate(*first, *reply);
        return std::nullopt;
      });

  f.client.asyncGet(targetFor(agent, 1), credentials(), {sysDescr},
                    [&f](net::ErrorCode ec, const Response& r) {
                      EXPECT_FALSE(ec) << ec.message();
                      EXPECT_EQ(r.varbinds.size(), 1U);
                      f.finish();
                    });
  f.run();

  // Two for Engine Discovery, two for the request.
  EXPECT_EQ(agent.requestsSeen(), 4);
}

// Both transmissions are held, then answered with each one's msgID and the other's request-id. A
// compliant Agent copies both from one message, so the pair must be one a transmission went out
// with: net-snmp drops the same mismatch (snmpv3_verify_msg), and so does snmpio. Neither reply
// counts, and the request times out.
TEST(MessageIds, AV3ReplyQuotingTwoTransmissionsIdsIsDropped) {
  Fixture f;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.closeAgent = [&agent] { agent.close(); };

  std::vector<ScriptedV3Agent::Request> held;
  agent.setResponder(
      [&](const ScriptedV3Agent::Request& req) -> std::optional<ScriptedV3Agent::Reply> {
        if (req.message.scoped.pdu.varbinds.empty()) return agent.behaveLikeACompliantAgent(req);
        held.push_back(req);
        if (held.size() == 2) {
          const auto& first = held[0].message;
          const auto& second = held[1].message;
          for (const auto& [msgId, requestId] :
               {std::pair{first.header.msgId, second.scoped.pdu.requestId},
                std::pair{second.header.msgId, first.scoped.pdu.requestId}}) {
            auto reply = agent.behaveLikeACompliantAgent(held[0]);
            if (reply) agent.answerQuoting(msgId, requestId, *reply);
          }
        }
        return std::nullopt;
      });

  f.client.asyncGet(targetFor(agent, 1), credentials(), {sysDescr},
                    [&f](net::ErrorCode ec, const Response&) {
                      EXPECT_EQ(ec, make_error_code(Errc::Timeout)) << ec.message();
                      f.finish();
                    });
  f.run();

  ASSERT_EQ(held.size(), 2U);
  EXPECT_NE(held[0].message.header.msgId, held[1].message.header.msgId);
}

// A request whose PDU cannot be encoded fails with why, sends nothing, and leaves nothing mapped:
// the ID drawn for it is spent, and the next request goes out and is answered as usual.
TEST(MessageIds, ARequestThatCannotBeEncodedSendsNothingAndLeavesNothingBehind) {
  Fixture f;
  f.expected = 2;
  ScriptedAgent agent(f.io, [](const V2cMessage& msg) {
    return respondWith({Varbind{msg.pdu.varbinds.at(0).name, null}});
  });
  f.closeAgent = [&agent] { agent.close(); };

  const Oid unencodable{7};  // one arc, where BER needs two to begin with
  f.client.asyncGet(longDeadlineTarget(agent), publicCommunity, {unencodable},
                    [&](net::ErrorCode ec, const Response&) {
                      EXPECT_EQ(ec, make_error_code(Errc::OidNotEncodable)) << ec.message();
                      EXPECT_EQ(agent.requestsSeen(), 0);
                      f.client.asyncGet(longDeadlineTarget(agent), publicCommunity, {sysDescr},
                                        [&f](net::ErrorCode ec2, const Response& r) {
                                          EXPECT_FALSE(ec2) << ec2.message();
                                          EXPECT_EQ(r.varbinds.size(), 1U);
                                          f.finish();
                                        });
                      f.finish();
                    });
  f.run();

  EXPECT_EQ(agent.requestsSeen(), 1);
  EXPECT_EQ(MessageIdView::outstandingIds(f.client), 0U);
}

// The same at v3, where the PDU is encoded only once Engine Discovery has run.
TEST(MessageIds, AV3RequestThatCannotBeEncodedSendsNothingAndLeavesNothingBehind) {
  Fixture f;
  f.expected = 2;
  ScriptedV3Agent agent(f.io, credentials(), echoAnswer);
  f.closeAgent = [&agent] { agent.close(); };

  const Oid unencodable{7};
  f.client.asyncGet(targetFor(agent, 1), credentials(), {unencodable},
                    [&](net::ErrorCode ec, const Response&) {
                      EXPECT_EQ(ec, make_error_code(Errc::OidNotEncodable)) << ec.message();
                      EXPECT_EQ(agent.requestsSeen(), 2);  // Engine Discovery's two phases
                      f.client.asyncGet(targetFor(agent, 1), credentials(), {sysDescr},
                                        [&f](net::ErrorCode ec2, const Response& r) {
                                          EXPECT_FALSE(ec2) << ec2.message();
                                          EXPECT_EQ(r.varbinds.size(), 1U);
                                          f.finish();
                                        });
                      f.finish();
                    });
  f.run();

  EXPECT_EQ(agent.requestsSeen(), 3);
  EXPECT_EQ(MessageIdView::outstandingIds(f.client), 0U);
}

// The generator is stepped back while a request is outstanding, so its next draw is that request's
// own ID, as it would be once the counter had gone all the way round. The second request must skip
// it (RFC 3412 section 6.2): sharing it, one request would get the other's answer, or none.
TEST(MessageIds, AnIdComeRoundAgainWhileOutstandingIsSkipped) {
  Fixture f;
  f.expected = 2;
  const Oid firstAsked{1, 3, 6, 1, 4, 1, 99999, 1};
  const Oid secondAsked{1, 3, 6, 1, 4, 1, 99999, 2};
  const auto expectAnswerTo = [&f](const Oid& asked) {
    return [&f, asked](net::ErrorCode ec, const Response& r) {
      // EXPECT rather than ASSERT, so that a wrong answer still finishes, and fails, the test.
      EXPECT_FALSE(ec) << ec.message();
      EXPECT_EQ(r.varbinds.size(), 1U);
      if (!r.varbinds.empty()) {
        EXPECT_EQ(r.varbinds[0].name, asked);
      }
      f.finish();
    };
  };
  std::vector<V2cMessage> held;
  ScriptedAgent* self = nullptr;
  ScriptedAgent agent(f.io, [&](const V2cMessage& msg) -> std::optional<Pdu> {
    held.push_back(msg);
    if (held.size() == 1) {
      MessageIdView::rewindIds(f.client, 1);
      f.client.asyncGet(longDeadlineTarget(*self), publicCommunity, {secondAsked},
                        expectAnswerTo(secondAsked));
    } else if (held.size() == 2) {
      for (const auto& h : held) {
        self->answerLate(h, respondWith({Varbind{h.pdu.varbinds.at(0).name, null}}));
      }
    }
    return std::nullopt;
  });
  self = &agent;
  f.closeAgent = [&agent] { agent.close(); };

  f.client.asyncGet(longDeadlineTarget(agent), publicCommunity, {firstAsked},
                    expectAnswerTo(firstAsked));
  f.run();

  ASSERT_EQ(held.size(), 2U);
  EXPECT_NE(held[0].pdu.requestId, held[1].pdu.requestId);
  EXPECT_EQ(MessageIdView::outstandingIds(f.client), 0U);
}

// Every request is held until the Agent has read them all, so that all of them are outstanding at
// once, and then each is answered with its own OID: one ID shared by two would hand one of them
// the other's answer, or leave it unanswered.
TEST(MessageIds, NoIdIsSharedByTwoOutstandingRequests) {
  constexpr int count = 100;
  Fixture f;
  f.expected = count;
  std::vector<V2cMessage> held;
  ScriptedAgent* self = nullptr;
  ScriptedAgent agent(f.io, [&](const V2cMessage& msg) -> std::optional<Pdu> {
    held.push_back(msg);
    if (held.size() == count) {
      for (const auto& h : held) {
        self->answerLate(h, respondWith({Varbind{h.pdu.varbinds.at(0).name, null}}));
      }
    }
    return std::nullopt;
  });
  self = &agent;
  f.closeAgent = [&agent] { agent.close(); };

  for (std::uint32_t i = 0; i < count; ++i) {
    const Oid asked{1, 3, 6, 1, 4, 1, 99999, i};
    f.client.asyncGet(longDeadlineTarget(agent), publicCommunity, {asked},
                      [&f, asked](net::ErrorCode ec, const Response& r) {
                        // EXPECT rather than ASSERT, so that a wrong answer still finishes, and
                        // fails, the test.
                        EXPECT_FALSE(ec) << ec.message();
                        EXPECT_EQ(r.varbinds.size(), 1U);
                        if (!r.varbinds.empty()) {
                          EXPECT_EQ(r.varbinds[0].name, asked);
                        }
                        f.finish();
                      });
  }
  f.run();

  std::vector<std::int32_t> ids;
  ids.reserve(held.size());
  for (const auto& h : held) ids.push_back(h.pdu.requestId);
  ASSERT_EQ(ids.size(), static_cast<std::size_t>(count));
  EXPECT_TRUE(allDistinct(ids));
}

}  // namespace
}  // namespace snmpio
