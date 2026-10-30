#ifndef SNMPIO_DETAIL_MESSAGEIDVIEW_HPP
#define SNMPIO_DETAIL_MESSAGEIDVIEW_HPP

#include <cstddef>
#include <cstdint>

#include <snmpio/Client.hpp>

namespace snmpio::detail {

// Test-only, as CacheView is: a window onto the Message IDs a Client holds, so that the tests can
// make its generator reach an ID still outstanding, and see that none is left mapped once every
// request has ended. Not part of the API, and nothing outside the tests calls it.
//
// It reaches the Client directly rather than through its strand, so it is only safe while nothing
// else is running that strand: once io_context::run() has returned, or from a handler on the same
// single-threaded io_context.
struct MessageIdView {
  // How many IDs are mapped to Outstanding Requests: each transmission's, until its request ends.
  [[nodiscard]] static std::size_t outstandingIds(const Client& client);
  // Steps the Client's generator back, so that its next draws repeat IDs it has handed out.
  static void rewindIds(Client& client, std::uint32_t steps);
};

}  // namespace snmpio::detail

#endif  // SNMPIO_DETAIL_MESSAGEIDVIEW_HPP
