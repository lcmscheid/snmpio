#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstring>

#include "ScopedDeathTestStyle.hpp"

// SNMPIO_HARDENING (CMakeLists.txt) applies the OpenSSF hardening flags to our own targets (#46).
// As with StdlibHardening, a flag on the compile line proves nothing on its own: this test fails if
// _FORTIFY_SOURCE stopped reaching the compile line, or stopped being honoured. It is the one flag
// in the set whose effect a test can observe; the hardened CI cell reads the linker's half off the
// binaries instead. Without SNMPIO_HARDENING the test skips -- glibc's fortification is the
// toolchain's default on some distributions and not on others, so an unhardened build has no
// outcome to pin.
//
// The level is pinned at compile time below, since a copy any level would stop cannot tell them
// apart, and a copy only level 3 stops depends on what the compiler can see of the destination.

namespace snmpio::test {
namespace {

#if SNMPIO_TESTS_HARDENED
static_assert(_FORTIFY_SOURCE == 3, "SNMPIO_HARDENING asks for _FORTIFY_SOURCE=3");

// The destination is a local of a plain function rather than one a lambda captures: GCC loses track
// of a captured array's size, falls back to the unchecked memcpy, and the test would fail for want
// of a check rather than for want of hardening. The volatile read keeps the copy, which would
// otherwise be a dead store, optimised away along with its check.
void copyIntoFourOctets(const char* source, std::size_t length) {
  std::array<char, 4> destination{};
  std::memcpy(destination.data(), source, length);
  static_cast<void>(*static_cast<volatile char*>(destination.data()));
}
#endif

TEST(CompilerHardening, FortifySourceStopsAnOverflowingCopy) {
#if SNMPIO_TESTS_HARDENED
  const ScopedDeathTestStyle threadsafe("threadsafe");
  const std::array<char, 16> source{};
  // volatile, so the compiler cannot see the length overruns the destination, and the copy is
  // checked when it runs rather than refused when it compiles.
  const volatile std::size_t length = source.size();
  EXPECT_DEATH(copyIntoFourOctets(source.data(), length), "buffer overflow detected");
#else
  GTEST_SKIP() << "built without SNMPIO_HARDENING";
#endif
}

}  // namespace
}  // namespace snmpio::test
