#ifndef SNMPIO_TESTS_INTEROPSUMMARY_HPP
#define SNMPIO_TESTS_INTEROPSUMMARY_HPP

#include <cstdint>
#include <string>

// A shared scratchpad for what an interop run proved, printed as a summary after all tests finish.
//
// The interop tests call these from their test bodies; when no interop Target is configured nothing
// is recorded and nothing is printed. The summary is meant to be transcribed into the pre-release
// checklist, so it lists every protocol pair that was exercised and every pair that was skipped,
// with the reason for each skip.
namespace snmpio::test {

void recordSysDescr(const std::string& sysDescr);
// `detail` is the failure for a pair that failed, and whatever the check left out for one that
// succeeded.
void recordPair(const std::string& label, bool succeeded, const std::string& detail = {});
void recordSkip(const std::string& label, std::string reason);

enum class RowOutcome : std::uint8_t { Ok, Failed, Skipped };

// Whether `incoming` replaces `existing` on a row two tests reach, which is printed once and says
// the worst they found. A result replaces a skip, which only means that one test did not reach the
// row, and a failure replaces an ok -- so neither test order nor which of the two ran second can
// print a row as proven that one of them disproved.
[[nodiscard]] bool replaces(RowOutcome incoming, RowOutcome existing);

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPSUMMARY_HPP
