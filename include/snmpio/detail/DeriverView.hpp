#ifndef SNMPIO_DETAIL_DERIVERVIEW_HPP
#define SNMPIO_DETAIL_DERIVERVIEW_HPP

#include <functional>

#include <snmpio/Client.hpp>

namespace snmpio::detail {

// Test-only, as CacheView is: a way to keep the Deriver a Client runs on busy, the private thread
// its io_context's password-to-key runs on, so that the tests can hold a derivation queued behind
// it and see what the strand does meanwhile, and to ask whether it has started at all. Not part of
// the API, and nothing outside the tests calls it.
//
// It reaches the Client directly rather than through its strand, so it is only safe while nothing
// else is running that strand: before io_context::run() is first called, or from a handler on the
// same single-threaded io_context.
struct DeriverView {
  // Runs `job` on the Client's io_context's Deriver, starting it if it has not started yet.
  // Whatever the job blocks on must be released before the io_context goes, whose destruction joins
  // the Deriver.
  static void occupy(Client& client, std::function<void()> job);
  // Whether the Client's io_context's Deriver has started its thread, which the first derivation
  // on that io_context does. Lets a test that keeps the Deriver from starting check that it was
  // the start it failed, and not something else of the same size.
  [[nodiscard]] static bool started(const Client& client);
};

}  // namespace snmpio::detail

#endif  // SNMPIO_DETAIL_DERIVERVIEW_HPP
