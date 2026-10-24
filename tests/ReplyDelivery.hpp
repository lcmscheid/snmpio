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
// and whether malformed datagrams go first. The default is what both Agents always did, one copy at
// once.
struct ReplyDelivery {
  std::chrono::milliseconds delay{0};
  int copies = 1;
  // Ahead of the reply: a datagram whose outer SEQUENCE claims four gigabytes, then a truncated
  // copy of the reply itself.
  bool malformedFirst = false;
  // Called just before the first whole copy goes out, on the Agent's strand, for a test that has
  // to know when a reply could first have reached its Client.
  std::function<void()> onAnswer;
};

// Chooses the delivery from the request being answered.
using DeliveryPlan = std::function<ReplyDelivery(const Pdu& request)>;

// What every delivery came to, for a test that wants to know its misbehaviours actually ran.
struct DeliveryCounts {
  int delayed = 0;
  int duplicated = 0;
  int malformed = 0;

  DeliveryCounts& operator+=(const DeliveryCounts& other) {
    delayed += other.delayed;
    duplicated += other.duplicated;
    malformed += other.malformed;
    return *this;
  }
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
    if (delivery.malformedFirst && reply.size() > 1) {
      ++m_counts.malformed;
      std::vector<std::byte> overlong{std::byte{0x30}, std::byte{0x84}, std::byte{0xff},
                                      std::byte{0xff}, std::byte{0xff}, std::byte{0xff}};
      overlong.insert(overlong.end(), reply.begin(), reply.end());
      m_socket.send_to(net::asio::buffer(overlong), to, 0, ignored);
      m_socket.send_to(net::asio::buffer(reply.data(), reply.size() / 2), to, 0, ignored);
    }
    if (delivery.onAnswer) delivery.onAnswer();
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
