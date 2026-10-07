#ifndef SNMPIO_TESTS_FAILINGALLOCATION_HPP
#define SNMPIO_TESTS_FAILINGALLOCATION_HPP

#include <cstddef>

namespace snmpio::test {

// Makes one allocation fail on purpose, so that a test can throw through code that never throws by
// design (threat model, L7). FailingAllocation.cpp replaces the global operator new for the whole
// test binary, and the replacement only fails anything while one of these is alive, and then only
// on the thread that created it: the first allocation there of exactly `size` bytes throws
// bad_alloc, and every other allocation succeeds as usual.
//
// Matched on the size rather than counted to the Nth allocation, because a count would drift with
// every change to the code under test. Pick a size nothing else allocates on that thread, and
// check rather than assume it: a size that is not a multiple of 8 rules out anything holding a
// pointer, but not an array of bytes or of 32-bit words. A SHA-224 key is 28 bytes, for instance,
// and so is the storage of a decoded Oid whose encoding is 6 bytes long.
//
// Asio's own allocations never reach this. It takes its handlers and coroutine frames from
// std::aligned_alloc wherever the C library has it, so the cleanup that Client::stop() dispatches
// cannot be made to fail from here.
class FailingAllocation {
 public:
  explicit FailingAllocation(std::size_t size) noexcept;
  ~FailingAllocation();

  FailingAllocation(const FailingAllocation&) = delete;
  FailingAllocation& operator=(const FailingAllocation&) = delete;
  FailingAllocation(FailingAllocation&&) = delete;
  FailingAllocation& operator=(FailingAllocation&&) = delete;

  // Whether this build replaces operator new at all. A Clang sanitizer build cannot, because its
  // runtime brings its own (tests/CMakeLists.txt), and a test that needs one skips there.
  [[nodiscard]] static constexpr bool available() noexcept {
    return SNMPIO_TESTS_REPLACE_OPERATOR_NEW != 0;
  }

  // Whether the allocation has been failed. Only once: after that, everything succeeds.
  [[nodiscard]] bool fired() const noexcept { return m_fired; }

  // Called by the replacement operator new. True if this allocation is the one to fail.
  static bool shouldFail(std::size_t size) noexcept;

 private:
  std::size_t m_size;
  bool m_fired = false;
};

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_FAILINGALLOCATION_HPP
