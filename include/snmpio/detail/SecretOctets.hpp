#ifndef SNMPIO_DETAIL_SECRETOCTETS_HPP
#define SNMPIO_DETAIL_SECRETOCTETS_HPP

#include <cstddef>
#include <memory>
#include <type_traits>
#include <vector>

// Not part of the API: what snmpio keeps its own copies of keys in. Installed only because
// Client.hpp's private members name it.
namespace snmpio::detail {

// OPENSSL_cleanse (ADR-0001), declared here so that no installed header includes OpenSSL's: zeros
// that dead-store elimination cannot remove, as a memset before a free may be.
void cleanse(void* p, std::size_t n) noexcept;

// An allocator that wipes every buffer it hands back, before handing it on to Upstream. Botan's
// secure_vector is the same arrangement: a std::vector whose allocator cleanses, which covers the
// buffer a growing vector leaves behind as well as the last one, where a destructor would see only
// the last. Upstream is a test seam, so that a test can watch the bytes as they are returned
// rather than read memory after it is freed.
template <typename T, typename Upstream = std::allocator<T>>
class CleansingAllocator {
  static_assert(std::is_trivially_copyable_v<T>, "a cleanse overwrites the bytes in place");
  using UpstreamTraits = std::allocator_traits<Upstream>;

 public:
  // The allocator requirements fix these names, as the standard's own spelling, so the naming
  // check has to give way to them -- as it does for make_error_code.
  // NOLINTBEGIN(readability-identifier-naming)
  using value_type = T;

  // Spelled out rather than left to allocator_traits, which would rebind T and keep
  // Upstream<T> -- an upstream of the wrong value type.
  template <typename U>
  struct rebind {
    using other = CleansingAllocator<U, typename UpstreamTraits::template rebind_alloc<U>>;
  };
  // NOLINTEND(readability-identifier-naming)

  CleansingAllocator() noexcept(noexcept(Upstream())) = default;
  explicit CleansingAllocator(const Upstream& upstream) noexcept : m_upstream(upstream) {}
  // Implicit, as the allocator requirements ask of a rebinding copy.
  template <typename U, typename UpstreamU>
  // NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor)
  CleansingAllocator(const CleansingAllocator<U, UpstreamU>& other) noexcept
      : m_upstream(other.upstream()) {}

  [[nodiscard]] T* allocate(std::size_t n) { return UpstreamTraits::allocate(m_upstream, n); }
  void deallocate(T* p, std::size_t n) noexcept {
    cleanse(p, n * sizeof(T));
    UpstreamTraits::deallocate(m_upstream, p, n);
  }

  [[nodiscard]] const Upstream& upstream() const noexcept { return m_upstream; }

  friend bool operator==(const CleansingAllocator& a, const CleansingAllocator& b) noexcept {
    return a.m_upstream == b.m_upstream;
  }

 private:
  [[no_unique_address]] Upstream m_upstream;
};

// Octets that wipe themselves when snmpio is done with them: every Master Key and Localized Key
// snmpio keeps, and the buffers key derivation works in. Deliberately not Octets -- the two do not
// convert implicitly, so a key cannot slip into unwiped storage by assignment. Both are contiguous
// bytes, so a std::span reads either.
using SecretOctets = std::vector<std::byte, CleansingAllocator<std::byte>>;

}  // namespace snmpio::detail

#endif  // SNMPIO_DETAIL_SECRETOCTETS_HPP
