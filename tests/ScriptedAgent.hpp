#ifndef SNMPIO_TESTS_SCRIPTEDAGENT_HPP
#define SNMPIO_TESTS_SCRIPTEDAGENT_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <snmpio/Pdu.hpp>
#include <snmpio/Target.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/detail/Net.hpp>

namespace snmpio::test {

// An in-process command responder on loopback, whose every answer is supplied by the test.
//
// This is not the Simulator of ADR-0006 -- that one is a separate published container and stays
// CI's interop target. This is the unit-level equivalent, and it exists for the same reason: the
// paths worth testing here are the ones a correct Agent never exercises, so the Agent has to be
// scriptable down to the individual Response.
class ScriptedAgent {
 public:
  // Returns the Response to send, or nullopt to stay silent (which is how a lost datagram and a
  // dead Target both look from the Command Generator's side).
  using Responder = std::function<std::optional<Pdu>(const V2cMessage&)>;

  ScriptedAgent(net::IoContext& io, Responder responder)
      : m_socket(io, net::UdpEndpoint(net::asio::ip::make_address("127.0.0.1"), 0)),
        m_responder(std::move(responder)) {
    receive();
  }

  [[nodiscard]] net::UdpEndpoint endpoint() const { return m_socket.local_endpoint(); }
  [[nodiscard]] int requestsSeen() const noexcept { return m_requestsSeen; }

  // What the Agent quotes back as the community. Empty means "echo whatever arrived".
  void setCommunityOverride(std::string community) { m_communityOverride = std::move(community); }

  void close() {
    net::ErrorCode ignored;
    m_socket.close(ignored);
  }

 private:
  void receive() {
    m_socket.async_receive_from(
        net::asio::buffer(m_buf), m_from, [this](net::ErrorCode ec, std::size_t n) {
          if (ec) return;
          ++m_requestsSeen;
          net::ErrorCode decodeEc;
          if (auto msg = decodeV2cMessage(std::span<const std::byte>(m_buf).first(n), decodeEc)) {
            if (auto reply = m_responder(*msg)) {
              reply->requestId = msg->pdu.requestId;
              const auto community =
                  m_communityOverride.empty() ? msg->community : m_communityOverride;
              net::ErrorCode encodeEc;
              m_out = encodeV2cMessage(community, *reply, encodeEc);
              if (!encodeEc) {
                m_socket.send_to(net::asio::buffer(m_out), m_from, 0, encodeEc);
              }
            }
          }
          receive();
        });
  }

  net::UdpSocket m_socket;
  Responder m_responder;
  net::UdpEndpoint m_from;
  std::vector<std::byte> m_buf = std::vector<std::byte>(65535);
  std::vector<std::byte> m_out;
  std::string m_communityOverride;
  int m_requestsSeen = 0;
};

// The Target every test in this file points at: the scripted Agent, with the timeouts wound down
// so a test that is supposed to time out does not take two seconds to say so.
inline Target targetFor(const ScriptedAgent& agent, int retries = 1) {
  Target t;
  t.endpoint = agent.endpoint();
  t.timeout = std::chrono::milliseconds(50);
  t.retries = retries;
  return t;
}

// A Response echoing the request's varbinds with the given values substituted in order.
inline Pdu respondWith(std::vector<Varbind> varbinds) {
  Pdu p;
  p.type = PduType::Response;
  p.varbinds = std::move(varbinds);
  return p;
}

inline Pdu respondWithError(ErrorStatus status, std::int32_t index) {
  Pdu p;
  p.type = PduType::Response;
  p.errorStatus = static_cast<std::int32_t>(status);
  p.errorIndex = index;
  return p;
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_SCRIPTEDAGENT_HPP
