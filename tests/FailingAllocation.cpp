#include "FailingAllocation.hpp"

#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <new>

namespace snmpio::test {
namespace {

// A plain pointer, so that it needs no dynamic initialisation: operator new can run before main
// and on a thread's first allocation, and has to be able to read this then. Mutable and global
// because the replacement operator new has no other way to find the scope that armed it.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
thread_local FailingAllocation* armed = nullptr;

}  // namespace

FailingAllocation::FailingAllocation(std::size_t size) noexcept : m_size(size) {
  assert(armed == nullptr && "one FailingAllocation per thread at a time");
  armed = this;
}

FailingAllocation::~FailingAllocation() {
  armed = nullptr;
}

bool FailingAllocation::shouldFail(std::size_t size) noexcept {
  FailingAllocation* const scope = armed;
  if (scope == nullptr || scope->m_fired || size != scope->m_size) return false;
  scope->m_fired = true;
  return true;
}

}  // namespace snmpio::test

#if SNMPIO_TESTS_REPLACE_OPERATOR_NEW

namespace {

// The replaceable operator new, built on malloc and the new-handler protocol as the standard
// describes it.
void* allocate(std::size_t size) {
  if (snmpio::test::FailingAllocation::shouldFail(size)) throw std::bad_alloc();
  if (size == 0) size = 1;
  for (;;) {
    // An untyped pointer, not a gsl::owner: operator new's signature says what it returns.
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
    if (void* p = std::malloc(size)) return p;
    const std::new_handler handler = std::get_new_handler();
    if (handler == nullptr) throw std::bad_alloc();
    handler();
  }
}

void release(void* p) noexcept {
  // The other half of allocate(), and as untyped.
  // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
  std::free(p);
}

}  // namespace

// Every unaligned form, new and delete alike. A sanitizer runtime brings its own operator new and
// delete, and memory one of them allocates must not be freed by the other: replacing only some of
// these would leave the set mixed, which ASan reports as a mismatch. The aligned forms are left
// alone, since they only ever pair with each other. Each returns or takes an untyped pointer, not a
// gsl::owner, because the signatures the standard fixes say what they own.
//
// NOLINTBEGIN(cppcoreguidelines-owning-memory)
void* operator new(std::size_t size) {
  return allocate(size);
}

void* operator new[](std::size_t size) {
  return allocate(size);
}

void* operator new(std::size_t size, const std::nothrow_t& /*tag*/) noexcept {
  try {
    return allocate(size);
  } catch (const std::bad_alloc&) {
    return nullptr;
  }
}

void* operator new[](std::size_t size, const std::nothrow_t& /*tag*/) noexcept {
  try {
    return allocate(size);
  } catch (const std::bad_alloc&) {
    return nullptr;
  }
}

void operator delete(void* p) noexcept {
  release(p);
}

void operator delete[](void* p) noexcept {
  release(p);
}

void operator delete(void* p, std::size_t /*size*/) noexcept {
  release(p);
}

void operator delete[](void* p, std::size_t /*size*/) noexcept {
  release(p);
}

void operator delete(void* p, const std::nothrow_t& /*tag*/) noexcept {
  release(p);
}

void operator delete[](void* p, const std::nothrow_t& /*tag*/) noexcept {
  release(p);
}
// NOLINTEND(cppcoreguidelines-owning-memory)

#endif  // SNMPIO_TESTS_REPLACE_OPERATOR_NEW
