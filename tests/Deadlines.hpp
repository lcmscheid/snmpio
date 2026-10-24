#ifndef SNMPIO_TESTS_DEADLINES_HPP
#define SNMPIO_TESTS_DEADLINES_HPP

#include <chrono>

#include <snmpio/Target.hpp>

namespace snmpio::test {

// A deadline long enough that a request ended by anything else -- a cancellation, Stopping, an
// exception, a reply -- cannot be mistaken for one its deadline ended, and short enough that a
// request which does wait it out fails the test rather than hanging it.
inline constexpr auto longDeadline = std::chrono::seconds(5);

// A Target that gives up only after longDeadline, with no retransmission to stretch it further.
// Works for either scripted Agent: targetFor is found next to the Agent's type.
template <typename Agent>
Target longDeadlineTarget(const Agent& agent) {
  auto t = targetFor(agent, 0);
  t.timeout = longDeadline;
  return t;
}

// What a request that has to end without waiting out its deadline may take -- one dropped by a
// terminal signal or by Stopping, or one answered at once -- measured from what should end it to
// its completion. Waiting out the deadline instead takes the whole of it, less the moment between
// the attempt going out and the Agent seeing it, so half of it tells the two apart with room to
// spare for a sanitizer's overhead.
template <typename Rep, typename Period>
constexpr auto atOnceLimit(std::chrono::duration<Rep, Period> deadline) {
  return deadline / 2;
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_DEADLINES_HPP
