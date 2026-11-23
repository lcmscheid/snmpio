#ifndef SNMPIO_TESTS_FRESHPROCESS_HPP
#define SNMPIO_TESTS_FRESHPROCESS_HPP

#include <cstdio>
#include <cstdlib>
#include <string>

#include <gtest/gtest.h>

#include "ScopedDeathTestStyle.hpp"

namespace snmpio::test {

// Runs `body` in a process of its own -- this test binary re-executed to run this one test, by
// gtest's threadsafe death-test style -- in which nothing has been fetched yet. A test of a first
// fetch needs one: a fetch that succeeds is held for the process's life, and ctest runs each test
// in a process of its own but the binary run by hand does not. `body` returns what went wrong, or
// an empty string; it must come first in the test, since the child reruns the test up to here. The
// child leaves through std::exit, so it also runs every static destructor snmpio has.
template <typename Body>
void expectInFreshProcess(Body body) {
  const ScopedDeathTestStyle threadsafe("threadsafe");
  EXPECT_EXIT(
      {
        const std::string wrong = body();
        std::fputs(wrong.c_str(), stderr);
        std::exit(wrong.empty() ? EXIT_SUCCESS : EXIT_FAILURE);
      },
      ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_FRESHPROCESS_HPP
