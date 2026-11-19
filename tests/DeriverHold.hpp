#ifndef SNMPIO_TESTS_DERIVERHOLD_HPP
#define SNMPIO_TESTS_DERIVERHOLD_HPP

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>

#include <snmpio/Client.hpp>
#include <snmpio/detail/DeriverView.hpp>

namespace snmpio::test {

// What holds the Deriver a Client runs on busy (detail::DeriverView), for every Client on its
// io_context, and lets it go: on release(), or when it goes out of scope, so that a test failing
// early does not leave the Deriver's join waiting on it. Declare it after the io_context and the
// Client it occupies, so that it goes first.
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

  // Releases the Deriver once `after` has passed on `io`: long enough for every request the test
  // has made to reach the derivation it queues behind, over loopback.
  void releaseAfter(net::IoContext& io, std::chrono::milliseconds after) {
    m_timer.emplace(io, after);
    m_timer->async_wait([this](net::ErrorCode) { release(); });
  }

 private:
  std::shared_ptr<std::atomic<bool>> m_released = std::make_shared<std::atomic<bool>>(false);
  std::optional<net::SteadyTimer> m_timer;
};

// How long the tests hold the Deriver before releasing it.
constexpr std::chrono::milliseconds derivationHeld{200};

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_DERIVERHOLD_HPP
