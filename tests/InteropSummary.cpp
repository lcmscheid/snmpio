#include "InteropSummary.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <ctime>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace snmpio::test {
namespace {

struct PairResult {
  std::string label;
  RowOutcome state;
  // What the run did not prove about this row: the failure message for a Failed pair, the reason
  // for a Skipped one, and for an Ok one whatever the check it passed left out.
  std::string reason;
};

// The tests feed this serially on the one thread GTest runs them on, and `print` runs on that
// same thread after the last one -- so no locking is needed. GTest's per-process execution, and
// ctest -j runs whole processes rather than threads, are what keep it single-threaded.
class InteropSummary {
 public:
  static InteropSummary& instance() {
    static InteropSummary s;
    return s;
  }

  void setSysDescr(const std::string& sysDescr) { m_sysDescr = sysDescr; }

  void record(PairResult result) {
    auto* const existing = find(result.label);
    if (existing == nullptr) {
      m_pairs.push_back(std::move(result));
    } else if (replaces(result.state, existing->state)) {
      *existing = std::move(result);
    }
  }

  void print() const {
    if (m_sysDescr.empty() && m_pairs.empty()) return;

    std::cout << "\n== snmpio interop run summary ==\n";
    if (!m_sysDescr.empty()) {
      std::cout << "Device/firmware: " << m_sysDescr << "\n";
    }

    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    // NOLINTNEXTLINE(concurrency-mt-unsafe): single-threaded test program shutdown.
    const std::tm* const local = std::localtime(&time);
    if (local != nullptr) {
      std::array<char, 32> buffer{};
      if (std::strftime(buffer.data(), buffer.size(), "%Y-%m-%d", local) != 0) {
        std::cout << "Date: " << buffer.data() << "\n";
      }
    }

    if (!m_pairs.empty()) {
      std::cout << "\nProtocols exercised:\n";
      for (const auto& pair : m_pairs) {
        switch (pair.state) {
          case RowOutcome::Ok:
            std::cout << "  ok   ";
            break;
          case RowOutcome::Failed:
            std::cout << "  fail ";
            break;
          case RowOutcome::Skipped:
            std::cout << "  skip ";
            break;
        }
        std::cout << pair.label;
        if (!pair.reason.empty()) {
          std::cout << "  -- " << pair.reason;
        }
        std::cout << "\n";
      }
    }

    std::cout << "\n";
  }

 private:
  InteropSummary() = default;

  [[nodiscard]] PairResult* find(std::string_view label) {
    const auto found = std::ranges::find(m_pairs, label, &PairResult::label);
    return found == m_pairs.end() ? nullptr : &*found;
  }

  std::string m_sysDescr;
  std::vector<PairResult> m_pairs;
};

class SummaryPrinter : public testing::EmptyTestEventListener {
 public:
  void OnTestProgramEnd(const testing::UnitTest& /*unitTest*/) override {
    InteropSummary::instance().print();
  }
};

struct ListenerRegistrar {
  ListenerRegistrar() {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): GTest's Append() takes ownership.
    testing::UnitTest::GetInstance()->listeners().Append(new SummaryPrinter);
  }
};

// Register the printer before main() runs, so it fires after GTest has run every test.
const ListenerRegistrar gRegistrar;

}  // namespace

void recordSysDescr(const std::string& sysDescr) {
  InteropSummary::instance().setSysDescr(sysDescr);
}

void recordPair(const std::string& label, bool succeeded, const std::string& detail) {
  InteropSummary::instance().record(
      {label, succeeded ? RowOutcome::Ok : RowOutcome::Failed, detail});
}

void recordSkip(const std::string& label, std::string reason) {
  InteropSummary::instance().record({label, RowOutcome::Skipped, std::move(reason)});
}

bool replaces(RowOutcome incoming, RowOutcome existing) {
  if (incoming == RowOutcome::Skipped) return false;
  return existing == RowOutcome::Skipped ||
         (existing == RowOutcome::Ok && incoming == RowOutcome::Failed);
}

}  // namespace snmpio::test
