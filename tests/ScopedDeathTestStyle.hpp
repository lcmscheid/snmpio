#ifndef SNMPIO_TESTS_SCOPEDDEATHTESTSTYLE_HPP
#define SNMPIO_TESTS_SCOPEDDEATHTESTSTYLE_HPP

#include <string>

#include <gtest/gtest.h>

namespace snmpio::test {

// Sets gtest's death-test style for one scope, and puts the one before it back however the scope
// is left: a GTEST_SKIP or a failed ASSERT returns past any statement that would.
class ScopedDeathTestStyle {
 public:
  explicit ScopedDeathTestStyle(const char* style) : m_previous(GTEST_FLAG_GET(death_test_style)) {
    GTEST_FLAG_SET(death_test_style, style);
  }
  ~ScopedDeathTestStyle() { GTEST_FLAG_SET(death_test_style, m_previous); }
  ScopedDeathTestStyle(const ScopedDeathTestStyle&) = delete;
  ScopedDeathTestStyle& operator=(const ScopedDeathTestStyle&) = delete;
  ScopedDeathTestStyle(ScopedDeathTestStyle&&) = delete;
  ScopedDeathTestStyle& operator=(ScopedDeathTestStyle&&) = delete;

 private:
  std::string m_previous;
};

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_SCOPEDDEATHTESTSTYLE_HPP
