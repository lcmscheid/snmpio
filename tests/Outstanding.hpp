#ifndef SNMPIO_TESTS_OUTSTANDING_HPP
#define SNMPIO_TESTS_OUTSTANDING_HPP

#include <ostream>

#include <snmpio/detail/OutstandingView.hpp>

namespace snmpio::detail {

// So that a failed comparison says which count was left over, rather than dumping bytes. Found by
// GoogleTest through ADL, so it lives beside the type.
inline void PrintTo(const OutstandingCounts& counts, std::ostream* os) {
  *os << "{exchanges " << counts.exchanges << ", discoveries " << counts.discoveries
      << ", derivations " << counts.derivations << ", waiters " << counts.waiters << "}";
}

}  // namespace snmpio::detail

#endif  // SNMPIO_TESTS_OUTSTANDING_HPP
