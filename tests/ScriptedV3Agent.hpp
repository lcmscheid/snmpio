#ifndef SNMPIO_TESTS_SCRIPTEDV3AGENT_HPP
#define SNMPIO_TESTS_SCRIPTEDV3AGENT_HPP

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
#include <snmpio/detail/Net.hpp>

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
  };

  // The data plane: what a well-formed, authenticated, timely request gets back.
  using Answer = std::function<Pdu(const Pdu& request)>;
  // A total override of everything below, for the Agent that misbehaves on purpose.
  using Responder = std::function<std::optional<Reply>(const Request&)>;

  ScriptedV3Agent(net::IoContext& io, Credentials creds, Answer answer)
      : m_socket(io, net::UdpEndpoint(net::asio::ip::make_address("127.0.0.1"), 0)),
        m_creds(std::move(creds)),
        m_answer(std::move(answer)) {
    setEngineId({std::byte{0x80}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x88},
                 std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}});
    receive();
  }

  [[nodiscard]] net::UdpEndpoint endpoint() const { return m_socket.local_endpoint(); }
  [[nodiscard]] int requestsSeen() const noexcept { return m_requestsSeen; }
  [[nodiscard]] const Octets& engineId() const noexcept { return m_engineId; }

  void setEngineId(Octets id) {
    m_engineId = std::move(id);
    net::ErrorCode ec;
    m_key = localizedAuthKey(m_creds, m_engineId, ec);
    m_privKey = m_creds.privProtocol == PrivProtocol::None
                    ? Octets{}
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

  // The compliant behaviour, for a Responder that wants to misbehave in one place only.
  std::optional<Reply> behaveLikeACompliantAgent(const Request& req) { return behave(req); }

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
      send(report(decryptionErrors, SecurityLevel::AuthNoPriv), decoded->header.msgId, 0);
      return;
    }
    req.message = std::move(*decoded);

    auto reply = m_responder ? m_responder(req) : behave(req);
    if (!reply) return;  // silence, which is what a dead Agent looks like

    send(std::move(*reply), req.message.header.msgId, req.message.scoped.pdu.requestId);
  }

  void send(Reply reply, std::int32_t msgId, std::int32_t requestId) {
    V3Header header;
    header.msgId = msgId;
    header.level = reply.level;
    header.reportable = false;

    UsmParameters usm;
    usm.engineId = reply.engineId.value_or(m_engineId);
    usm.boots = reply.boots.value_or(m_boots);
    usm.time = reply.time.value_or(m_time);
    usm.userName = m_creds.userName;

    ScopedPdu scoped = std::move(reply.scoped);
    if (scoped.contextEngineId.empty()) scoped.contextEngineId = usm.engineId;
    if (scoped.pdu.type == PduType::Response) scoped.pdu.requestId = requestId;

    auto key = m_key;
    if (reply.corruptDigest && !key.empty()) key.front() ^= std::byte{0xff};
    auto privKey = m_privKey;
    if (reply.corruptPrivKey && !privKey.empty()) privKey.front() ^= std::byte{0xff};

    net::ErrorCode ec;
    m_out = encodeV3Message(header, usm, scoped, m_creds.authProtocol, key, ec,
                            m_creds.privProtocol, privKey);
    if (ec) return;
    m_socket.send_to(net::asio::buffer(m_out), m_from, 0, ec);
  }

  static constexpr std::int32_t timeWindow = 150;

  net::UdpSocket m_socket;
  Credentials m_creds;
  Answer m_answer;
  Responder m_responder;
  std::function<void(std::span<const std::byte>)> m_onDatagram;
  Octets m_engineId;
  Octets m_key;
  Octets m_privKey;
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
