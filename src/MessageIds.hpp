#ifndef SNMPIO_SRC_MESSAGEIDS_HPP
#define SNMPIO_SRC_MESSAGEIDS_HPP

#include <cstdint>
#include <optional>

#include <snmpio/detail/Net.hpp>

// OpenSSL's, declared rather than included, so that only MessageIds.cpp sees OpenSSL's headers.
struct evp_cipher_ctx_st;

// Internal to the library, and not installed.
namespace snmpio::detail {

// The Message IDs and request-ids one Client sends (CONTEXT.md, Message ID; threat model R7): a
// keyed permutation of a counter over 0..2^31-1, the range RFC 3412 gives msgID. Being a
// permutation, it repeats no ID until the counter has gone all the way round, which is the
// uniqueness RFC 3414 section 11.1 asks for. Being keyed, an Agent that sees some of the IDs
// learns nothing about the rest -- those in flight to every other Target included -- where a
// counter alone would give them all away (research note 1.2.2).
//
// The key is drawn from OpenSSL's CSPRNG the first time an ID is asked for, once per Client, and
// lives only inside the cipher context, which wipes it when it goes. Not thread-safe: the Client
// asks for IDs on its strand alone.
class MessageIds {
 public:
  MessageIds() noexcept = default;
  ~MessageIds();

  MessageIds(const MessageIds&) = delete;
  MessageIds& operator=(const MessageIds&) = delete;
  MessageIds(MessageIds&&) = delete;
  MessageIds& operator=(MessageIds&&) = delete;

  // The next ID, in 0..2^31-1. Nothing, with CryptoFailure, if OpenSSL has no key to give or
  // cannot encrypt.
  [[nodiscard]] std::optional<std::int32_t> next(net::ErrorCode& ec);

 private:
  bool keyed(net::ErrorCode& ec);
  [[nodiscard]] std::optional<std::uint32_t> permute(std::uint32_t x) const;

  evp_cipher_ctx_st* m_ctx = nullptr;
  std::uint32_t m_counter = 0;
};

}  // namespace snmpio::detail

#endif  // SNMPIO_SRC_MESSAGEIDS_HPP
