#ifndef SNMPIO_DETAIL_OUTSTANDINGVIEW_HPP
#define SNMPIO_DETAIL_OUTSTANDINGVIEW_HPP

#include <cstddef>

#include <snmpio/Client.hpp>

namespace snmpio::detail {

// What a Client still holds on behalf of Outstanding Requests: the work that ends when they do, or
// when nothing is left waiting on it. All zero once every request has completed and every Engine
// Discovery and derivation they started has settled, which is what the tests assert after their
// quiet periods (threat model L1, #51).
struct OutstandingCounts {
  // Exchanges awaiting a reply: a request's own, or an Engine Discovery phase's. One per exchange,
  // however many Message IDs its retransmissions have mapped to it (MessageIdView counts those).
  std::size_t exchanges = 0;
  // Engine Discoveries in flight, one per Target endpoint.
  std::size_t discoveries = 0;
  // Password-to-key derivations in flight: Master Keys from passwords, and Reeder's extensions.
  std::size_t derivations = 0;
  // Coroutines parked on one of the two above: requests queued behind a discovery or a derivation,
  // and a discovery waiting on the keys its time-sync phase needs. A waiter outlives the work it
  // waited on until it resumes, so this can stay above zero after the work itself has gone.
  std::size_t waiters = 0;

  [[nodiscard]] bool none() const noexcept {
    return exchanges == 0 && discoveries == 0 && derivations == 0 && waiters == 0;
  }
  friend bool operator==(const OutstandingCounts&, const OutstandingCounts&) = default;
};

// Test-only, as CacheView is: so that a test can see the Client is left holding nothing, where the
// public API shows only what reaches the wire. Not part of the API, and nothing outside the tests
// calls it.
//
// It reads the Client directly rather than through its strand, so it is only safe while nothing
// else is running that strand: once io_context::run() has returned, or from a handler on the same
// single-threaded io_context.
struct OutstandingView {
  [[nodiscard]] static OutstandingCounts counts(const Client& client);
};

}  // namespace snmpio::detail

#endif  // SNMPIO_DETAIL_OUTSTANDINGVIEW_HPP
