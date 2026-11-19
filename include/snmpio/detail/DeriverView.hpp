#ifndef SNMPIO_DETAIL_DERIVERVIEW_HPP
#define SNMPIO_DETAIL_DERIVERVIEW_HPP

#include <functional>

#include <snmpio/Client.hpp>

namespace snmpio::detail {

// Test-only, as CacheView is: a way to keep a Client's deriver busy, the private thread its
// password-to-key runs on, so that the tests can hold a derivation queued behind it and see what
// the strand does meanwhile. Not part of the API, and nothing outside the tests calls it.
//
// It reaches the Client directly rather than through its strand, so it is only safe while nothing
// else is running that strand: before io_context::run() is first called, or from a handler on the
// same single-threaded io_context.
struct DeriverView {
  // Runs `job` on the Client's deriver, starting it if it has not started yet. Whatever the job
  // blocks on must be released before the Client's state goes, which joins the deriver. A
  // derivation queued behind the job keeps the state alive until then; with none, the state can go
  // on the io_context's thread while the job still blocks, and that join then waits on it.
  static void occupy(Client& client, std::function<void()> job);
};

}  // namespace snmpio::detail

#endif  // SNMPIO_DETAIL_DERIVERVIEW_HPP
