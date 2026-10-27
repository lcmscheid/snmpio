#ifndef SNMPIO_SECRETOCTETS_HPP
#define SNMPIO_SECRETOCTETS_HPP

#include <cstddef>
#include <memory>
#include <type_traits>
#include <vector>

namespace snmpio {

namespace detail {

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
  // Bytes overwritten in place are only a wipe for a type that is nothing but its bytes. Every
  // rebind is held to it too, so a container that rebinds to a node type with a destructor will
  // not compile with this allocator -- std::vector, the one container it is for, never rebinds.
  static_assert(std::is_trivially_copyable_v<T>, "a cleanse overwrites the bytes in place");
  using UpstreamTraits = std::allocator_traits<Upstream>;

 public:
  // The allocator requirements fix these names, as the standard's own spelling, so the naming
  // check has to give way to them -- as it does for make_error_code.
  // NOLINTBEGIN(readability-identifier-naming)
  using value_type = T;
  // Whatever Upstream says, rather than what allocator_traits would infer from this class being
  // empty: [[no_unique_address]] makes it so on GCC and Clang, but not on MSVC.
  using is_always_equal = UpstreamTraits::is_always_equal;
  using propagate_on_container_copy_assignment =
      UpstreamTraits::propagate_on_container_copy_assignment;
  using propagate_on_container_move_assignment =
      UpstreamTraits::propagate_on_container_move_assignment;
  using propagate_on_container_swap = UpstreamTraits::propagate_on_container_swap;

  // Spelled out rather than left to allocator_traits, which would rebind T and keep
  // Upstream<T> -- an upstream of the wrong value type.
  template <typename U>
  struct rebind {
    using other = CleansingAllocator<U, typename UpstreamTraits::template rebind_alloc<U>>;
  };
  // NOLINTEND(readability-identifier-naming)

  CleansingAllocator() noexcept(noexcept(Upstream())) = default;
  explicit CleansingAllocator(const Upstream& upstream) noexcept : m_upstream(upstream) {}
  // Implicit, as std::allocator's and pmr::polymorphic_allocator's converting constructors are.
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

 private:
  [[no_unique_address]] Upstream m_upstream;
};

// Across value types, as std::allocator's and pmr::polymorphic_allocator's are: the allocator
// requirements ask that a == b hold for an allocator and its rebound copy.
template <typename T, typename UpstreamT, typename U, typename UpstreamU>
[[nodiscard]] bool operator==(const CleansingAllocator<T, UpstreamT>& a,
                              const CleansingAllocator<U, UpstreamU>& b) noexcept {
  return a.upstream() == b.upstream();
}

}  // namespace detail

// Octets that wipe themselves when they are done with: every Master Key and Localized Key, in
// snmpio's keeping and in the caller's -- Credentials carry them in this, and the key derivations
// return it. Deliberately not Octets: the two do not convert implicitly, so a key cannot slip into
// unwiped storage by assignment. Both are contiguous bytes, so a std::span reads either.
using SecretOctets = std::vector<std::byte, detail::CleansingAllocator<std::byte>>;

}  // namespace snmpio

#endif  // SNMPIO_SECRETOCTETS_HPP
