#include <gtest/gtest.h>

#include <cstddef>
#include <vector>

#if defined(_LIBCPP_VERSION)
#include <sys/wait.h>

#include <csignal>
#endif

#include "FreshProcess.hpp"

// Standard-library hardening (SNMPIO_STDLIB_HARDENING in CMakeLists.txt) is two macros, one per
// library, and each library ignores the other's. Setting a macro proves nothing on its own: this
// is the test that fails if the one for the library actually in use stopped reaching the compile
// line, or stopped being honoured. The libc++ CI cell is what runs it against libc++ (#44).
//
// Each library is held to its own way of failing, so a crash of some other kind does not pass for
// hardening. libstdc++ aborts with the failed precondition's text. libc++'s fast mode traps, with
// no message: SIGILL where the trap is x86's ud2, SIGTRAP on Arm.

namespace snmpio::test {
namespace {

TEST(StdlibHardening, StopsAnOutOfBoundsIndex) {
  const ScopedDeathTestStyle threadsafe("threadsafe");
  const std::vector<int> values(1);
  // volatile, so the compiler can neither see the index is out of range nor drop the read.
  const volatile std::size_t index = 1;
#if defined(_LIBCPP_VERSION)
  const auto trapped = [](int status) {
    return WIFSIGNALED(status) && (WTERMSIG(status) == SIGILL || WTERMSIG(status) == SIGTRAP);
  };
  EXPECT_EXIT(static_cast<void>(values[index]), trapped, "");
#elif defined(__GLIBCXX__)
  EXPECT_DEATH(static_cast<void>(values[index]), "__n < this->size\\(\\)");
#else
  GTEST_SKIP() << "no hardening mode is set for this standard library";
#endif
}

}  // namespace
}  // namespace snmpio::test
