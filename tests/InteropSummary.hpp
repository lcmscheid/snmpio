#ifndef SNMPIO_TESTS_INTEROPSUMMARY_HPP
#define SNMPIO_TESTS_INTEROPSUMMARY_HPP

#include <string>

// A shared scratchpad for what an interop run proved, printed as a summary after all tests finish.
//
// The interop tests call these from their test bodies; when no interop Target is configured nothing
// is recorded and nothing is printed. The summary is meant to be transcribed into the pre-release
// checklist, so it lists every protocol pair that was exercised and every pair that was skipped,
// with the reason for each skip.
namespace snmpio::test {

void recordSysDescr(const std::string& sysDescr);
void recordPair(const std::string& label, bool succeeded, const std::string& error = {});
void recordSkip(const std::string& label, std::string reason);

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPSUMMARY_HPP
