#ifndef SNMPIO_SRC_MESSAGEIDS_HPP
#define SNMPIO_SRC_MESSAGEIDS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <snmpio/SecretOctets.hpp>
#include <snmpio/detail/Net.hpp>

// OpenSSL's, declared rather than included, so that only MessageIds.cpp sees OpenSSL's headers.
struct evp_cipher_ctx_st;
struct ossl_lib_ctx_st;

// Internal to the library, and not installed.
namespace snmpio::detail {

// The Message IDs and request-ids one Client sends (CONTEXT.md, Message ID; threat model R7): FF1
// (NIST SP 800-38G) over a counter, at radix 2 and 31 numerals, so a permutation of 0..2^31-1, the
// range RFC 3412 gives msgID. Being a permutation, it repeats no ID until the counter has gone all
// the way round. Being keyed, an Agent that sees some of the IDs learns nothing about the rest --
// those outstanding at every other Target included -- where a counter alone would give them all
// away (research note 1.2.2). Why FF1, and why implemented here: ADR-0012.
//
// The key is drawn from OpenSSL's CSPRNG the first time an ID is asked for, once per Client, and
// lives only inside the cipher context, which wipes it when it goes. Not thread-safe: the Client
// asks for IDs on its strand alone.
class MessageIds {
 public:
  static constexpr std::size_t keyBytes = 16;  // AES-128

  // Keyed from OpenSSL's default library context.
  MessageIds() noexcept = default;
  // Keyed from `libctx` instead, as OpenSSL's own _ex functions take one: for the tests, which
  // hand it a context with no provider in it to fail with.
  explicit MessageIds(ossl_lib_ctx_st* libctx) noexcept : m_libctx(libctx) {}
  // A known key and starting counter rather than random ones, for the known-answer tests.
  MessageIds(std::span<const std::byte, keyBytes> key, std::uint32_t counter);
  ~MessageIds();

  MessageIds(const MessageIds&) = delete;
  MessageIds& operator=(const MessageIds&) = delete;
  MessageIds(MessageIds&&) = delete;
  MessageIds& operator=(MessageIds&&) = delete;

  // The next ID, in 1..2^31-1, for which isOutstanding(id) is false. Never 0, as net-snmp never
  // sends one and snmpio's counter never did before this. Never one still outstanding, as RFC 3412
  // section 6.2 asks: the permutation can only reach one once the counter has gone all the way
  // round, and then the next is drawn instead -- which ends, since fewer than 2^31 - 1 IDs can be
  // outstanding at once. CryptoFailure, and 0, if OpenSSL has no key to give or cannot encrypt; the
  // keying is tried again on the next call.
  template <typename IsOutstanding>
  [[nodiscard]] std::int32_t next(IsOutstanding isOutstanding, net::ErrorCode& ec) {
    for (;;) {
      const std::int32_t id = draw(ec);
      if (ec) return 0;
      if (id != 0 && !isOutstanding(id)) return id;
    }
  }

 private:
  // FF1 of the counter, and the counter moved on.
  std::int32_t draw(net::ErrorCode& ec);
  bool ensureKeyed(net::ErrorCode& ec);
  [[nodiscard]] std::uint32_t ff1Encrypt(std::uint32_t x, net::ErrorCode& ec) const;

  ossl_lib_ctx_st* m_libctx = nullptr;
  SecretOctets m_fixedKey;  // the known-answer tests' key; empty for one from the CSPRNG
  evp_cipher_ctx_st* m_ctx = nullptr;
  // FF1's P block encrypted once: the first step of every round's CBC-MAC, which P never changes.
  std::array<std::byte, 16> m_encryptedP{};
  std::uint32_t m_counter = 0;
};

}  // namespace snmpio::detail

#endif  // SNMPIO_SRC_MESSAGEIDS_HPP
