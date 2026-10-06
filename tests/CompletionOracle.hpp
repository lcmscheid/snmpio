#ifndef SNMPIO_TESTS_COMPLETIONORACLE_HPP
#define SNMPIO_TESTS_COMPLETIONORACLE_HPP

#include <gtest/gtest.h>

#include <initializer_list>
#include <memory>
#include <utility>
#include <vector>

#include <snmpio/detail/Net.hpp>

namespace snmpio::test {

// Proves that one Outstanding Request completed exactly once (threat model, L1).
//
// handler() wraps a completion handler and binds it to a caller executor that is not the Client's
// own. The wrapper records every invocation -- its ordinal, whether it ran on that executor, and
// the code -- and the destruction of the one live handler object; a moved-from shell counts for
// nothing.
//
// A test initiates with the handler, stops the Client once it has completed, and runs the
// io_context until it drains; completedExactlyOnce() then asks for everything at once. A request
// stranded without completing still holds its handler, which shows as a missing invocation or, if
// the stop forces it out, a late one. What the oracle cannot see is anything the Client keeps
// after the handler has gone: the handler has left it by then. A test covers that by watching the
// wire for longer than the request's deadlines before it stops the Client, as the disruption
// matrix does.
//
// The record is shared with the handler rather than held here, so a handler destroyed late -- in
// the io_context's destructor, say, by a bug that stranded it -- never reaches a dead oracle.
class CompletionOracle {
 public:
  struct Invocation {
    int ordinal = 0;
    bool onCallerExecutor = false;
    net::ErrorCode code;
  };

  explicit CompletionOracle(net::IoContext& io)
      : m_record(std::make_shared<Record>(net::Strand(net::Executor(io.get_executor())))) {}

  // The wrapped handler, bound to the caller executor. `then` receives the completion's arguments
  // after they are recorded, and is where a test stops the Client.
  template <typename Then>
  auto handler(Then then) {
    return net::asio::bind_executor(m_record->caller, Handler<Then>(m_record, std::move(then)));
  }

  [[nodiscard]] net::Strand callerExecutor() const { return m_record->caller; }
  [[nodiscard]] const std::vector<Invocation>& invocations() const { return m_record->invocations; }
  [[nodiscard]] int destructions() const { return m_record->destructions; }

  [[nodiscard]] testing::AssertionResult completedExactlyOnce(
      std::initializer_list<net::ErrorCode> allowed) const {
    const auto& calls = m_record->invocations;
    if (calls.size() != 1) {
      return testing::AssertionFailure()
             << "completed " << calls.size() << " times, not exactly once";
    }
    if (!calls.front().onCallerExecutor) {
      return testing::AssertionFailure() << "completed off the caller's executor";
    }
    bool permitted = false;
    for (const auto& code : allowed) permitted = permitted || calls.front().code == code;
    if (!permitted) {
      return testing::AssertionFailure()
             << "completed with " << calls.front().code.category().name() << ":"
             << calls.front().code.value() << " (" << calls.front().code.message()
             << "), not a code allowed here";
    }
    if (m_record->destructions != 1) {
      return testing::AssertionFailure()
             << "the handler was destroyed " << m_record->destructions << " times, not once";
    }
    return testing::AssertionSuccess();
  }

 private:
  struct Record {
    explicit Record(net::Strand ex) : caller(std::move(ex)) {}
    net::Strand caller;
    std::vector<Invocation> invocations;
    int destructions = 0;
  };

  template <typename Then>
  class Handler {
   public:
    Handler(std::shared_ptr<Record> record, Then then)
        : m_record(std::move(record)), m_then(std::move(then)) {}
    Handler(Handler&& other) noexcept
        : m_record(std::exchange(other.m_record, nullptr)), m_then(std::move(other.m_then)) {}
    Handler(const Handler&) = delete;
    Handler& operator=(const Handler&) = delete;
    Handler& operator=(Handler&&) = delete;
    ~Handler() {
      if (m_record) ++m_record->destructions;
    }

    template <typename... Rest>
    void operator()(net::ErrorCode ec, Rest&&... rest) {
      if (!m_record) {
        ADD_FAILURE() << "a moved-from completion handler was invoked";
        return;
      }
      auto& calls = m_record->invocations;
      calls.push_back(Invocation{static_cast<int>(calls.size()) + 1,
                                 m_record->caller.running_in_this_thread(), ec});
      m_then(ec, std::forward<Rest>(rest)...);
    }

   private:
    std::shared_ptr<Record> m_record;
    Then m_then;
  };

  std::shared_ptr<Record> m_record;
};

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_COMPLETIONORACLE_HPP
