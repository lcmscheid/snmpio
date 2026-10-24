#ifndef SNMPIO_TESTS_REPLYDELIVERY_HPP
#define SNMPIO_TESTS_REPLYDELIVERY_HPP

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <snmpio/Pdu.hpp>
#include <snmpio/detail/Net.hpp>

namespace snmpio::test {

// How a Scripted Agent puts a reply it has already decided on onto the wire: when, how many times,
// and whether a truncated copy goes first. The default is what both Agents always did, one copy at
// once.
struct ReplyDelivery {
  std::chrono::milliseconds delay{0};
  int copies = 1;
  bool truncatedCopyFirst = false;
};

// Chooses the delivery from the request being answered.
using DeliveryPlan = std::function<ReplyDelivery(const Pdu& request)>;

// What every delivery came to, for a test that wants to know its misbehaviours actually ran.
struct DeliveryCounts {
  int delayed = 0;
  int duplicated = 0;
  int truncated = 0;
};

// The sending half both Agents share. Lives on the Agent's strand, as everything in an Agent does:
// a delayed reply waits on a timer on the socket's own executor, and cancel() -- which the Agent's
// close() calls -- cancels every one still waiting.
class ReplySender {
 public:
  explicit ReplySender(net::UdpSocket& socket) : m_socket(socket) {}

  void send(std::span<const std::byte> reply, const net::UdpEndpoint& to,
            const ReplyDelivery& delivery) {
    if (delivery.delay <= std::chrono::milliseconds::zero()) {
      put(reply, to, delivery);
      return;
    }
    ++m_counts.delayed;
    auto timer = std::make_shared<net::SteadyTimer>(m_socket.get_executor(), delivery.delay);
    m_pending.push_back(timer);
    timer->async_wait(
        [this, timer, to, delivery,
         bytes = std::vector<std::byte>(reply.begin(), reply.end())](net::ErrorCode ec) {
          std::erase(m_pending, timer);
          if (!ec) put(bytes, to, delivery);
        });
  }

  void cancel() {
    for (const auto& timer : m_pending) timer->cancel();
  }

  [[nodiscard]] const DeliveryCounts& counts() const noexcept { return m_counts; }

 private:
  void put(std::span<const std::byte> reply, const net::UdpEndpoint& to,
           const ReplyDelivery& delivery) {
    net::ErrorCode ignored;
    if (delivery.truncatedCopyFirst && reply.size() > 1) {
      ++m_counts.truncated;
      m_socket.send_to(net::asio::buffer(reply.data(), reply.size() / 2), to, 0, ignored);
    }
    if (delivery.copies > 1) ++m_counts.duplicated;
    for (int i = 0; i < delivery.copies; ++i)
      m_socket.send_to(net::asio::buffer(reply.data(), reply.size()), to, 0, ignored);
  }

  net::UdpSocket& m_socket;
  std::vector<std::shared_ptr<net::SteadyTimer>> m_pending;
  DeliveryCounts m_counts;
};

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_REPLYDELIVERY_HPP
