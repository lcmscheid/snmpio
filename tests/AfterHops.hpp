#ifndef SNMPIO_TESTS_AFTERHOPS_HPP
#define SNMPIO_TESTS_AFTERHOPS_HPP

#include <functional>
#include <utility>

#include <snmpio/detail/Net.hpp>

namespace snmpio::test {

// Runs `then` after `hops` trips through the io_context. Nothing in the public API lands an event
// at a chosen step inside the Client, so a sweep tries every step in turn: which hop count lands
// in which step is Asio's business and may change, and the rule has to hold at all of them.
inline void afterHops(net::IoContext& io, int hops, std::function<void()> then) {
  // Built inside out, one post wrapped around the next, so that nothing here recurses.
  for (int i = 0; i < hops; ++i) {
    then = [&io, next = std::move(then)]() mutable { net::asio::post(io, std::move(next)); };
  }
  then();
}

// Enough hops to walk an event across every step of one exchange.
inline constexpr int sweepHops = 8;

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_AFTERHOPS_HPP
