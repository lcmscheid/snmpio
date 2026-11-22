#ifndef SNMPIO_TESTS_OUTSTANDINGREADS_HPP
#define SNMPIO_TESTS_OUTSTANDINGREADS_HPP

#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <ostream>
#include <thread>

#include <snmpio/Client.hpp>
#include <snmpio/detail/OutstandingView.hpp>

namespace snmpio::detail {

// So that a failed comparison says which count was left over, rather than dumping bytes. Found by
// GoogleTest through ADL, so it lives beside the type.
inline void PrintTo(const OutstandingCounts& counts, std::ostream* os) {
  *os << "{exchanges " << counts.exchanges << ", discoveries " << counts.discoveries
      << ", derivations " << counts.derivations << ", waiters " << counts.waiters << "}";
}

}  // namespace snmpio::detail

namespace snmpio::test {

// Reads the view on the Client's strand, from a thread that is not running it, while other threads
// may be (detail::OutstandingView::countsOnStrand), and waits up to `limit` for the answer. Empty
// if the strand never got to it: nothing ran the io_context in time.
inline std::optional<detail::OutstandingCounts> countsOnStrand(
    const Client& client, std::chrono::milliseconds limit = std::chrono::seconds(5)) {
  // Shared with the handler, which may still run after a read that gave up on it.
  auto read = std::make_shared<std::promise<detail::OutstandingCounts>>();
  auto answer = read->get_future();
  detail::OutstandingView::countsOnStrand(
      client, [read](const detail::OutstandingCounts& counts) { read->set_value(counts); });
  if (answer.wait_for(limit) != std::future_status::ready) return std::nullopt;
  return answer.get();
}

// Reads on the strand until the Client holds nothing, or until `limit` has passed, and returns
// what it last read: so that work a request was allowed to leave running -- a discovery carrying
// on after the request that started it was cancelled (ADR-0003) -- has its own deadlines to settle
// in, and only work that outlives them all reads as held.
inline std::optional<detail::OutstandingCounts> settledOnStrand(const Client& client,
                                                                std::chrono::milliseconds limit) {
  const auto giveUpAt = std::chrono::steady_clock::now() + limit;
  for (;;) {
    auto counts = countsOnStrand(client, limit);
    if (!counts || *counts == detail::OutstandingCounts{}) return counts;
    if (std::chrono::steady_clock::now() >= giveUpAt) return counts;
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_OUTSTANDINGREADS_HPP
