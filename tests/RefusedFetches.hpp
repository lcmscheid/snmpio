#ifndef SNMPIO_TESTS_REFUSEDFETCHES_HPP
#define SNMPIO_TESTS_REFUSEDFETCHES_HPP

#include <memory>
#include <string>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace snmpio::test {

// While one is alive, OpenSSL's default library context can fetch no algorithm: its default
// property query names a provider that does not exist, so every fetch fails, implicit or explicit.
// A call that still succeeds under it fetched nothing, which is what #47 asks of every crypt and
// HMAC a request makes, sent or received. The query in force before is put back on the way out.
// OpenSSL before 3.5 has no getter for it (EVP_get1_default_properties was added in 3.5), so there
// the empty query, OpenSSL's own default and what the test runs start with, is put back instead.
class RefusedFetches {
 public:
  RefusedFetches() {
#if OPENSSL_VERSION_PREREQ(3, 5)
    const std::unique_ptr<char, void (*)(char*)> before(EVP_get1_default_properties(nullptr),
                                                        [](char* p) { OPENSSL_free(p); });
    m_before = before ? before.get() : "";
#endif
    m_refusing = EVP_set_default_properties(nullptr, "provider=snmpio-refuses-fetches") == 1;
  }
  ~RefusedFetches() { EVP_set_default_properties(nullptr, m_before.c_str()); }

  RefusedFetches(const RefusedFetches&) = delete;
  RefusedFetches& operator=(const RefusedFetches&) = delete;
  RefusedFetches(RefusedFetches&&) = delete;
  RefusedFetches& operator=(RefusedFetches&&) = delete;

  // Whether the query took, without which a passing test proves nothing.
  [[nodiscard]] bool refusing() const noexcept { return m_refusing; }

 private:
  std::string m_before;
  bool m_refusing = false;
};

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_REFUSEDFETCHES_HPP
