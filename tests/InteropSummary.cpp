#include "InteropSummary.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <ctime>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

namespace snmpio::test {
namespace {

struct PairResult {
  std::string label;
  enum class State { Ok, Failed, Skipped } state;
  // What kept the row from being Ok: the failure message for a Failed pair, or the reason for a
  // Skipped one. The two say the same thing -- the reason the run did not prove this row.
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

  void recordPair(const std::string& label, bool succeeded, const std::string& error) {
    if (hasLabel(label)) return;
    m_pairs.push_back(
        {label, succeeded ? PairResult::State::Ok : PairResult::State::Failed, error});
  }

  void recordSkip(const std::string& label, std::string reason) {
    if (hasLabel(label)) return;
    m_pairs.push_back({label, PairResult::State::Skipped, std::move(reason)});
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
          case PairResult::State::Ok:
            std::cout << "  ok   ";
            break;
          case PairResult::State::Failed:
            std::cout << "  fail ";
            break;
          case PairResult::State::Skipped:
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

  [[nodiscard]] bool hasLabel(std::string_view label) const {
    return std::ranges::any_of(m_pairs, [label](const auto& pair) { return pair.label == label; });
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

void recordPair(const std::string& label, bool succeeded, const std::string& error) {
  InteropSummary::instance().recordPair(label, succeeded, error);
}

void recordSkip(const std::string& label, std::string reason) {
  InteropSummary::instance().recordSkip(label, std::move(reason));
}

}  // namespace snmpio::test
