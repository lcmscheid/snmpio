#ifndef SNMPIO_SRC_DERIVER_HPP
#define SNMPIO_SRC_DERIVER_HPP

#include <snmpio/detail/Net.hpp>

#include <memory>
#include <mutex>

namespace snmpio::detail {

// The thread password-to-key runs on: one per execution context, shared by every Client on it,
// and started the first time one of them needs it (ADR-0003's amendment of 2026-11-19). A service
// of the context, as Asio's resolver service is, which keeps a private thread for the blocking
// getaddrinfo in the same way. A context shuts its services down newest first, and every Client
// looks this one up after its strand exists, so this joins its thread before the strand's service
// shuts down: a derivation that finishes meanwhile hands its result to a strand that is still
// there. Services newer than this one, the reactor's and the timers', may already have destroyed
// their own pending operations by then, which is harmless: what those hold co-owns the Client's
// state, as the derivations do. A thread a Client owned could outlive the context, and hand its
// result to freed memory.
class Deriver : public net::asio::execution_context::service {
 public:
  // The key Asio looks a service up by, by this name. Its constructor is empty and cannot throw,
  // though it is not declared noexcept.
  static inline net::asio::execution_context::id
      id;  // NOLINT(bugprone-throwing-static-initialization,cert-err58-cpp)

  explicit Deriver(net::asio::execution_context& context) : service(context) {}
  Deriver(const Deriver&) = delete;
  Deriver& operator=(const Deriver&) = delete;
  Deriver(Deriver&&) = delete;
  Deriver& operator=(Deriver&&) = delete;
  ~Deriver() override = default;

  // Where a derivation runs, starting the thread if it has not started yet. From any thread, since
  // the Clients sharing it may run on different strands.
  net::ThreadPool::executor_type executor() {
    const std::scoped_lock lock(m_mutex);
    if (!m_pool) m_pool = std::make_unique<net::ThreadPool>(1);
    return m_pool->get_executor();
  }

 private:
  // The context's shutdown, ahead of any handler of its being destroyed. The derivation in progress
  // runs to its end, since a megabyte hash cannot be interrupted; those queued behind it are
  // abandoned, as the resolver abandons the lookups queued behind the one in progress. Abandoned
  // here, while every service of the context still exists, if shut down, for what they hold to be
  // destroyed against.
  void shutdown() override {
    std::unique_ptr<net::ThreadPool> pool;
    {
      const std::scoped_lock lock(m_mutex);
      pool = std::move(m_pool);
    }
    if (!pool) return;
    pool->stop();
    pool->join();
  }

  std::mutex m_mutex;
  std::unique_ptr<net::ThreadPool> m_pool;
};

}  // namespace snmpio::detail

#endif  // SNMPIO_SRC_DERIVER_HPP
