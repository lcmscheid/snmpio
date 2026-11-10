#ifndef SNMPIO_SRC_OPENSSL_HPP
#define SNMPIO_SRC_OPENSSL_HPP

#include <atomic>
#include <memory>
#include <mutex>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace snmpio::detail {

// Frees an OpenSSL handle with its own free function, which is what lets std::unique_ptr own one:
// OpenSslPtr<EVP_MD_CTX, EVP_MD_CTX_free>, and so on.
template <auto Free>
struct OpenSslFree {
  template <typename T>
  void operator()(T* handle) const noexcept {
    Free(handle);
  }
};

template <typename T, auto Free>
using OpenSslPtr = std::unique_ptr<T, OpenSslFree<Free>>;

using DigestPtr = OpenSslPtr<EVP_MD, EVP_MD_free>;
using CipherPtr = OpenSslPtr<EVP_CIPHER, EVP_CIPHER_free>;

// The handle a FetchOnce holds, or nullptr while it holds none.
template <typename Ptr>
[[nodiscard]] auto* rawOrNull(const Ptr* held) noexcept {
  return held == nullptr ? nullptr : held->get();
}

// Something fetched from OpenSSL once and then held for the process's life, which is the reuse
// OpenSSL's guide asks for of anything run many times: "it is recommended to use a single explicit
// fetch" (ossl-guide-libcrypto-introduction(7), Performance). Every later get() reads one atomic
// and touches none of OpenSSL's lazy state, so two Clients' strands never race into it (#47, #90).
//
// Only a success is held. A fetch that fails -- memory, or a provider configured after the first
// try -- is tried again by the next get(), the way std::call_once tries again after a call that
// throws, rather than failing every request for the rest of the process.
//
// Constructing one initialises OpenSSL first, which registers OpenSSL's atexit cleanup before this
// object's destructor is registered, so the destructor runs, and frees what it holds, while
// OpenSSL is still there to free it into.
//
// T is held in place, so a fetch allocates nothing of ours: an OpenSslPtr, or a struct of them
// whose explicit operator bool says whether all of it fetched.
template <typename T>
class FetchOnce {
 public:
  FetchOnce() noexcept { OPENSSL_init_crypto(0, nullptr); }
  ~FetchOnce() = default;

  FetchOnce(const FetchOnce&) = delete;
  FetchOnce& operator=(const FetchOnce&) = delete;
  FetchOnce(FetchOnce&&) = delete;
  FetchOnce& operator=(FetchOnce&&) = delete;

  // What `fetch` returned the first time it returned a T that tests true, or nullptr while it has
  // not. `fetch` must not throw.
  template <typename Fetch>
  [[nodiscard]] const T* get(Fetch&& fetch) noexcept {
    if (m_ready.load(std::memory_order_acquire)) return &m_value;
    const std::scoped_lock lock(m_mutex);
    if (!m_ready.load(std::memory_order_relaxed)) {
      T fetched = std::forward<Fetch>(fetch)();
      if (!fetched) return nullptr;
      m_value = std::move(fetched);
      m_ready.store(true, std::memory_order_release);
    }
    return &m_value;
  }

 private:
  std::mutex m_mutex;
  T m_value{};
  std::atomic<bool> m_ready{false};
};

// Makes the process's first draw from OpenSSL's CSPRNG, once and alone; snmpio calls it before
// each draw of its own. That first draw fetches the generator's algorithms into OpenSSL's method
// cache, and every thread's first draw after it only looks them up. Two threads making the first
// draw together both write that cache, guarded by libcrypto's own atomics, which TSan cannot see
// into, so it reported them as racing (#90). Run under a function-local static, the first draw
// finishes before any caller goes on, and TSan sees the ordering. One that fails costs only the
// ordering: each draw still fetches what it needs for itself.
inline void primeRandom() noexcept {
  static const bool primed = [] {
    unsigned char discarded = 0;
    return RAND_bytes(&discarded, 1) == 1;
  }();
  static_cast<void>(primed);
}

}  // namespace snmpio::detail

#endif  // SNMPIO_SRC_OPENSSL_HPP
