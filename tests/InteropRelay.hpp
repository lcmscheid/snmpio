#ifndef SNMPIO_TESTS_INTEROPRELAY_HPP
#define SNMPIO_TESTS_INTEROPRELAY_HPP

#include <array>
#include <cstddef>
#include <functional>
#include <span>
#include <utility>

#include <snmpio/detail/Net.hpp>

namespace snmpio::test {

// Sits between the Client and the Agent and counts the datagrams the Client sends.
//
// Discovery is deliberately invisible from the API -- stage 3 put it underneath every operation
// precisely so that no caller has to think about it -- so counting what actually went over the
// wire is the only honest way to ask what the first request against an unknown Engine cost.
//
// The same is true of a Walk's max-repetitions: it is a number this library chooses and revises
// on its own, and the wire is the only place it is visible. `onRequest` hands each datagram to the
// test before it is forwarded, which is also the one place a fault can be turned off at an exact
// point in an exchange rather than after a hopeful sleep.
class CountingRelay {
 public:
  // Called with each datagram from the Client, before it is forwarded. Empty by default.
  using RequestHook = std::function<void(std::span<const std::byte>)>;

  CountingRelay(net::IoContext& io, net::UdpEndpoint target, RequestHook onRequest = {})
      : m_target(std::move(target)),
        m_onRequest(std::move(onRequest)),
        // Both sockets in the Target's own family, because makeInteropTarget takes a v6 literal
        // and a relay that only ever binds v4 would turn "[::1]" into a timeout. The client-side
        // one binds loopback rather than the wildcard: its address is what the Client is handed to
        // send to, and nothing can send to 0.0.0.0.
        m_clientSide(
            io,
            net::UdpEndpoint(
                net::asio::ip::make_address(m_target.address().is_v6() ? "::1" : "127.0.0.1"), 0)),
        m_targetSide(io, net::UdpEndpoint(m_target.protocol(), 0)) {
    receiveFromClient();
    receiveFromTarget();
  }

  [[nodiscard]] net::UdpEndpoint endpoint() const { return m_clientSide.local_endpoint(); }
  [[nodiscard]] int datagramsFromClient() const noexcept { return m_fromClient; }
  // What the Agent sent back, which is the difference between "the Response was dropped" and
  // "nothing ever arrived" -- two things a Timeout looks identical from.
  [[nodiscard]] int datagramsFromTarget() const noexcept { return m_fromTarget; }

  void close() {
    // Boost.Asio hands the error_code back as the return value as well, standalone Asio returns
    // void, and the ec overload is the only form both spell the same way (ADR-0002). There is
    // nothing to do with it on a socket being discarded either way.
    //
    // NOLINTBEGIN(bugprone-unused-return-value,cert-err33-c)
    net::ErrorCode ignored;
    m_clientSide.close(ignored);
    m_targetSide.close(ignored);
    // NOLINTEND(bugprone-unused-return-value,cert-err33-c)
  }

 private:
  void receiveFromClient() {
    m_clientSide.async_receive_from(
        net::asio::buffer(m_clientBuf), m_client, [this](net::ErrorCode ec, std::size_t n) {
          if (ec) return;
          ++m_fromClient;
          if (m_onRequest) m_onRequest(std::span<const std::byte>(m_clientBuf).first(n));
          net::ErrorCode ignored;
          m_targetSide.send_to(net::asio::buffer(m_clientBuf, n), m_target, 0, ignored);
          receiveFromClient();
        });
  }

  void receiveFromTarget() {
    m_targetSide.async_receive_from(
        net::asio::buffer(m_targetBuf), m_targetFrom, [this](net::ErrorCode ec, std::size_t n) {
          if (ec) return;
          ++m_fromTarget;
          net::ErrorCode ignored;
          m_clientSide.send_to(net::asio::buffer(m_targetBuf, n), m_client, 0, ignored);
          receiveFromTarget();
        });
  }

  net::UdpEndpoint m_target;
  RequestHook m_onRequest;
  net::UdpSocket m_clientSide;
  net::UdpSocket m_targetSide;
  net::UdpEndpoint m_client;
  net::UdpEndpoint m_targetFrom;
  std::array<std::byte, 4096> m_clientBuf{};
  std::array<std::byte, 4096> m_targetBuf{};
  int m_fromClient = 0;
  int m_fromTarget = 0;
};

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPRELAY_HPP
