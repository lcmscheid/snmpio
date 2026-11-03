#ifndef SNMPIO_DETAIL_CACHEVIEW_HPP
#define SNMPIO_DETAIL_CACHEVIEW_HPP

#include <cstddef>

#include <snmpio/Client.hpp>

namespace snmpio::detail {

// How many entries a Client's caches hold, and how often it has had to fill one, and nothing about
// what is in them.
struct CacheCounts {
  std::size_t engines = 0;        // one per engineID that some Target maps to (threat model B2)
  std::size_t masterKeys = 0;     // derived from a password; one per (hash, password)
  std::size_t localizedKeys = 0;  // one per (engineID, hash, Master Key, privacy protocol)
  // Password-to-key runs that produced a Master Key, over the Client's life. A cache that worked
  // only by deduplicating on insert would still show one entry per password, so the size alone
  // cannot say a password was derived once. Reeder's extension, which reruns password-to-key over
  // a Localized Key, is not a Master Key and is not counted.
  std::size_t masterKeyDerivations = 0;
};

// Test-only: so that what the caches do is asserted rather than inferred. Not part of the API,
// and nothing outside the tests calls it.
//
// It reads the caches directly rather than through the Client's strand, so it is only safe while
// nothing else is running that strand: once io_context::run() has returned, or from a handler on
// the same single-threaded io_context, as MessageIdView is.
struct CacheView {
  [[nodiscard]] static CacheCounts counts(const Client& client);
};

}  // namespace snmpio::detail

#endif  // SNMPIO_DETAIL_CACHEVIEW_HPP
