#ifndef SNMPIO_TESTS_SCRIPTEDV3AGENT_HPP
#define SNMPIO_TESTS_SCRIPTEDV3AGENT_HPP

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <snmpio/Target.hpp>
#include <snmpio/Usm.hpp>
#include <snmpio/V3Message.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/ber/Writer.hpp>
#include <snmpio/detail/Net.hpp>

#include "ReplyDelivery.hpp"

namespace snmpio::test {

// The v3 sibling of ScriptedAgent, and the same thing it is: an in-process command responder on
// loopback whose every answer a test can rewrite. Separate from the v2c one rather than a mode of
// it -- the two share a socket loop and nothing else, and folding them together would mean a
// conditional on every line that matters.
//
// Out of the box it behaves: it discovers, it authenticates, it enforces its own Time Window, and
// it answers the data plane from a callback. Every one of those is a knob, because the paths worth
// testing here are the ones a correct Agent never takes (ADR-0006).
class ScriptedV3Agent {
 public:
  struct Request {
    V3Message message;
    bool authenticated = false;  // the digest verified against the key this Agent holds
  };

  // What to send back. Anything left default is filled in from the Agent's own state.
  struct Reply {
    ScopedPdu scoped;
    SecurityLevel level = SecurityLevel::AuthNoPriv;
    std::optional<std::int32_t> boots;
    std::optional<std::int32_t> time;
    std::optional<Octets> engineId;
    // Sign with a key that is not the Agent's, so the Command Generator must reject it.
    bool corruptDigest = false;
    // Encrypt with a key that is not the Agent's, so the reply cannot be opened.
    bool corruptPrivKey = false;
    // Another user name than the Agent's own, signed with the Agent's key all the same.
    std::optional<std::string> userName;
    // Another user altogether: signed, and encrypted at authPriv, with the keys these Credentials
    // localize to at this Agent's engineID, under their user name. A reply the Agent really did
    // send, for someone other than the request's user.
    std::optional<Credentials> signer;
    // A digest this many octets wide instead of the protocol's: the CVE-2008-0960 forgery. Its
    // octets are the leading ones of the true digest over the message as sent, which is all that a
    // verifier comparing only as many octets as arrived would check -- such a verifier accepts it.
    // Unencrypted replies only.
    std::optional<std::size_t> digestWidth;
  };

  // The data plane: what a well-formed, authenticated, timely request gets back.
  using Answer = std::function<Pdu(const Pdu& request)>;
  // A total override of everything below, for the Agent that misbehaves on purpose.
  using Responder = std::function<std::optional<Reply>(const Request&)>;

  ScriptedV3Agent(net::IoContext& io, Credentials creds, Answer answer)
      : m_socket(net::asio::make_strand(io),
                 net::UdpEndpoint(net::asio::ip::make_address("127.0.0.1"), 0)),
        m_creds(std::move(creds)),
        m_answer(std::move(answer)) {
    setEngineId({std::byte{0x80}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x88},
                 std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}});
    receive();
  }

  [[nodiscard]] net::UdpEndpoint endpoint() const { return m_socket.local_endpoint(); }
  // The strand the socket runs on, so that a test running the io_context on several threads can
  // close() it there rather than race the receive.
  [[nodiscard]] net::Executor executor() { return m_socket.get_executor(); }
  [[nodiscard]] int requestsSeen() const noexcept { return m_requestsSeen; }
  [[nodiscard]] const Octets& engineId() const noexcept { return m_engineId; }

  void setEngineId(Octets id) {
    m_engineId = std::move(id);
    net::ErrorCode ec;
    m_key = localizedAuthKey(m_creds, m_engineId, ec);
    m_privKey = m_creds.privProtocol == PrivProtocol::None
                    ? SecretOctets{}
                    : localizedPrivKey(m_creds, m_engineId, ec);
  }
  void setBoots(std::int32_t boots) noexcept { m_boots = boots; }
  void setTime(std::int32_t time) noexcept { m_time = time; }
  void setResponder(Responder responder) { m_responder = std::move(responder); }
  // Every datagram this Agent receives, for the tests that care what actually went out rather
  // than what it decoded to.
  void setOnDatagram(std::function<void(std::span<const std::byte>)> onDatagram) {
    m_onDatagram = std::move(onDatagram);
  }
  // How each reply goes out: late, twice, or behind malformed datagrams, chosen from the
  // request's own PDU. One copy, at once, without it. A Report for a payload that would not open
  // always goes out at once: there is no request PDU to choose from.
  void setDelivery(DeliveryPlan plan) { m_delivery = std::move(plan); }
  [[nodiscard]] const DeliveryCounts& deliveries() const noexcept { return m_sender.counts(); }

  // The compliant behaviour, for a Responder that wants to misbehave in one place only.
  std::optional<Reply> behaveLikeACompliantAgent(const Request& req) { return behave(req); }

  // Answers an earlier request now. A Responder holds a reply back by answering silence, and lets
  // it go at a moment of its own choosing, as a reply delayed in the network would arrive. Unlike
  // a delayed delivery, the order against the other replies is the test's, not a timer's. Leave the
  // reply's boots and time unset and they are the Agent's clock now, not as it was when it was
  // asked. It goes out as one copy, at once: setDelivery's plan is not consulted.
  void answerLate(const Request& req, Reply reply) {
    send(std::move(reply), req.message.header.msgId, req.message.scoped.pdu.requestId, {});
  }
  // The same, quoting whichever msgID and request-id the test names: an Agent that mixed up two
  // transmissions, or a forger that saw one ID of each.
  void answerQuoting(std::int32_t msgId, std::int32_t requestId, Reply reply) {
    send(std::move(reply), msgId, requestId, {});
  }

  // RFC 3414 section 5's counters, so that a test says which Report it means rather than which
  // number it is.
  static constexpr std::uint32_t unsupportedSecLevels = 1;
  static constexpr std::uint32_t notInTimeWindows = 2;
  static constexpr std::uint32_t unknownUserNames = 3;
  static constexpr std::uint32_t unknownEngineIds = 4;
  static constexpr std::uint32_t wrongDigests = 5;
  static constexpr std::uint32_t decryptionErrors = 6;

  // The Report a real Agent sends for each of the usmStats counters. Public because a misbehaving
  // Agent is written by handing one of these back at the wrong moment.
  [[nodiscard]] static Reply report(std::uint32_t counter, SecurityLevel level) {
    Reply r;
    r.level = level;
    r.scoped.pdu.type = PduType::Report;
    r.scoped.pdu.varbinds = {Varbind{Oid{1, 3, 6, 1, 6, 3, 15, 1, 1, counter, 0}, Counter32{1}}};
    return r;
  }

  void close() {
    m_sender.cancel();
    net::ErrorCode ignored;
    m_socket.close(ignored);
  }

 private:
  // The compliant Agent, in the order RFC 3414 section 3.2 checks things.
  std::optional<Reply> behave(const Request& req) {
    const UsmParameters& usm = req.message.security;

    // Discovery: no engineID means the Command Generator does not yet know who we are.
    if (usm.engineId.empty()) return report(unknownEngineIds, SecurityLevel::NoAuthNoPriv);
    if (usm.engineId != m_engineId) {
      return report(unknownEngineIds, SecurityLevel::NoAuthNoPriv);
    }
    if (isAuthenticated(req.message.header.level)) {
      if (usm.userName != m_creds.userName) {
        return report(unknownUserNames, SecurityLevel::NoAuthNoPriv);
      }
      if (!req.authenticated) return report(wrongDigests, SecurityLevel::NoAuthNoPriv);
      if (usm.boots != m_boots || std::abs(usm.time - m_time) > timeWindow) {
        return report(notInTimeWindows, m_creds.level);
      }
    }

    Reply reply;
    reply.level = req.message.header.level;
    reply.scoped.pdu = m_answer(req.message.scoped.pdu);
    return reply;
  }

  void receive() {
    m_socket.async_receive_from(net::asio::buffer(m_buf), m_from,
                                [this](net::ErrorCode ec, std::size_t n) {
                                  if (ec) return;
                                  ++m_requestsSeen;
                                  answer(std::span<const std::byte>(m_buf).first(n));
                                  receive();
                                });
  }

  void answer(std::span<const std::byte> datagram) {
    if (m_onDatagram) m_onDatagram(datagram);
    net::ErrorCode ec;
    auto decoded = decodeV3Message(datagram, ec);
    if (!decoded) return;

    Request req;
    req.authenticated = isAuthenticated(decoded->header.level) &&
                        verifyAuth(datagram, *decoded, m_creds.authProtocol, m_key, ec);
    // RFC 3414 section 3.2 step 8: decryption comes after authentication, and a payload that will
    // not open is a usmStatsDecryptionErrors Report rather than silence. A real Agent checks
    // timeliness in between (step 7); this one checks it in behave(), below, which only means an
    // untimely message is decrypted before being refused for a reason that has nothing to do with
    // its ciphertext.
    if (isEncrypted(decoded->header.level) &&
        !decryptScopedPdu(*decoded, m_creds.privProtocol, m_privKey, ec)) {
      send(report(decryptionErrors, SecurityLevel::AuthNoPriv), decoded->header.msgId, 0, {});
      return;
    }
    req.message = std::move(*decoded);

    auto reply = m_responder ? m_responder(req) : behave(req);
    if (!reply) return;  // silence, which is what a dead Agent looks like

    const auto delivery = m_delivery ? m_delivery(req.message.scoped.pdu) : ReplyDelivery{};
    send(std::move(*reply), req.message.header.msgId, req.message.scoped.pdu.requestId, delivery);
  }

  void send(Reply reply, std::int32_t msgId, std::int32_t requestId,
            const ReplyDelivery& delivery) {
    V3Header header;
    header.msgId = msgId;
    header.level = reply.level;
    header.reportable = false;

    UsmParameters usm;
    usm.engineId = reply.engineId.value_or(m_engineId);
    usm.boots = reply.boots.value_or(m_boots);
    usm.time = reply.time.value_or(m_time);
    const Credentials& signing = reply.signer ? *reply.signer : m_creds;
    usm.userName = reply.userName.value_or(signing.userName);

    ScopedPdu scoped = std::move(reply.scoped);
    if (scoped.contextEngineId.empty()) scoped.contextEngineId = usm.engineId;
    if (scoped.pdu.type == PduType::Response) scoped.pdu.requestId = requestId;

    net::ErrorCode ec;
    auto key = m_key;
    auto privKey = m_privKey;
    if (reply.signer) {
      key = localizedAuthKey(signing, m_engineId, ec);
      privKey = signing.privProtocol == PrivProtocol::None
                    ? SecretOctets{}
                    : localizedPrivKey(signing, m_engineId, ec);
      if (ec) return;
    }
    if (reply.corruptDigest && !key.empty()) key.front() ^= std::byte{0xff};
    if (reply.corruptPrivKey && !privKey.empty()) privKey.front() ^= std::byte{0xff};

    m_out = reply.digestWidth ? withShortDigest(header, usm, scoped, *reply.digestWidth, key, ec)
                              : encodeV3Message(header, usm, scoped, signing.authProtocol, key, ec,
                                                signing.privProtocol, privKey);
    if (ec) return;
    m_sender.send(m_out, m_from, delivery);
  }

  // encodeV3Message's layout, by hand, because it will only write a digest of the protocol's width.
  std::vector<std::byte> withShortDigest(const V3Header& header, const UsmParameters& usm,
                                         const ScopedPdu& scoped, std::size_t width,
                                         std::span<const std::byte> key, net::ErrorCode& ec) const {
    ber::Writer usmContent;
    usmContent.octetString(usm.engineId);
    usmContent.integer(usm.boots);
    usmContent.integer(usm.time);
    usmContent.octetString(usm.userName);
    usmContent.octetString(Octets(width, std::byte{0}));
    usmContent.octetString(Octets{});
    ber::Writer usmParams;
    usmParams.tlv(ber::tag::sequence, usmContent.bytes());

    ber::Writer body;
    body.integer(versionV3);
    {
      const auto scope = body.beginSequence();
      body.integer(header.msgId);
      body.integer(header.maxSize);
      const auto flags = static_cast<std::byte>(header.level);
      body.octetString(std::span(&flags, 1));
      body.integer(header.securityModel);
    }
    body.octetString(usmParams.bytes());
    encodeScopedPdu(body, scoped);
    ber::Writer w;
    w.tlv(ber::tag::sequence, body.bytes());
    auto out = w.take();

    // The field is blank, as RFC 3414 section 6.3.1 has it blanked at the protocol's width, so
    // this is the true digest over the message as sent.
    const auto msg = decodeV3Message(out, ec);
    if (!msg) return {};
    const auto digest = authDigest(m_creds.authProtocol, key, out, ec);
    if (ec) return {};
    std::copy_n(digest.begin(), std::min(width, digest.size()),
                out.begin() + static_cast<std::ptrdiff_t>(msg->authParamsOffset));
    return out;
  }

  static constexpr std::int32_t timeWindow = 150;

  net::UdpSocket m_socket;
  Credentials m_creds;
  Answer m_answer;
  Responder m_responder;
  std::function<void(std::span<const std::byte>)> m_onDatagram;
  DeliveryPlan m_delivery;
  ReplySender m_sender{m_socket};
  Octets m_engineId;
  SecretOctets m_key;
  SecretOctets m_privKey;
  std::int32_t m_boots = 3;
  std::int32_t m_time = 1000;
  net::UdpEndpoint m_from;
  std::vector<std::byte> m_buf = std::vector<std::byte>(65535);
  std::vector<std::byte> m_out;
  int m_requestsSeen = 0;
};

inline Target targetFor(const ScriptedV3Agent& agent, int retries = 1) {
  Target t;
  t.endpoint = agent.endpoint();
  t.timeout = std::chrono::milliseconds(50);
  t.retries = retries;
  return t;
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_SCRIPTEDV3AGENT_HPP
