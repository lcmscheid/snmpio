#include "MessageIds.hpp"

#include <array>
#include <cstddef>
#include <utility>

#include <snmpio/Error.hpp>
#include <snmpio/SecretOctets.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace snmpio::detail {
namespace {

// The permutation is a Feistel network over 31 bits in the shape of NIST SP 800-38G's FF1 at radix
// 2: the halves are 15 and 16 bits, they trade places each round, and there are FF1's ten rounds.
// FF1 itself is not in OpenSSL, and its big-number arithmetic buys nothing at radix 2, so this is
// that structure with plain modular addition, around a round function that is AES-128 under the
// Client's key. The primitive is OpenSSL's; the construction around it is ours, which stretches
// CLAUDE.md's "never our own" crypto rule, deliberately: OpenSSL has no small-domain permutation,
// and #33 asks for one. What rests on it is unpredictability of IDs, not confidentiality.
constexpr unsigned idBits = 31;
constexpr unsigned shortHalf = idBits / 2;         // 15
constexpr unsigned longHalf = idBits - shortHalf;  // 16
constexpr int rounds = 10;
constexpr std::uint32_t idMask = (std::uint32_t{1} << idBits) - 1;

constexpr std::size_t aesBlock = 16;
constexpr std::size_t aesKey = 16;

constexpr std::uint32_t lowBits(unsigned n) noexcept {
  return (std::uint32_t{1} << n) - 1;
}

}  // namespace

MessageIds::~MessageIds() {
  EVP_CIPHER_CTX_free(m_ctx);  // which cleanses the key schedule it holds
}

bool MessageIds::keyed(net::ErrorCode& ec) {
  if (m_ctx != nullptr) return true;
  SecretOctets key(aesKey);
  EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, "AES-128-ECB", nullptr);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  const bool ok =
      cipher != nullptr && ctx != nullptr &&
      RAND_bytes(reinterpret_cast<unsigned char*>(key.data()), static_cast<int>(key.size())) == 1 &&
      EVP_EncryptInit_ex2(ctx, cipher, reinterpret_cast<const unsigned char*>(key.data()), nullptr,
                          nullptr) == 1 &&
      EVP_CIPHER_CTX_set_padding(ctx, 0) == 1;
  EVP_CIPHER_free(cipher);  // the context keeps its own reference
  if (!ok) {
    EVP_CIPHER_CTX_free(ctx);
    ec = make_error_code(Errc::CryptoFailure);
    return false;
  }
  m_ctx = ctx;
  return true;
}

// One block per round: the round number and the half that goes in, encrypted, and the first four
// Octets of the result cut to the width of the half that comes out.
std::optional<std::uint32_t> MessageIds::permute(std::uint32_t x) const {
  std::uint32_t a = x >> longHalf;          // the high 15 bits
  std::uint32_t b = x & lowBits(longHalf);  // the low 16
  for (int i = 0; i < rounds; ++i) {
    std::array<unsigned char, aesBlock> in{};
    in[0] = static_cast<unsigned char>(i);
    in[1] = static_cast<unsigned char>(b >> 24U);
    in[2] = static_cast<unsigned char>(b >> 16U);
    in[3] = static_cast<unsigned char>(b >> 8U);
    in[4] = static_cast<unsigned char>(b);
    std::array<unsigned char, aesBlock> out{};
    int written = 0;
    if (EVP_EncryptUpdate(m_ctx, out.data(), &written, in.data(), static_cast<int>(in.size())) !=
            1 ||
        std::cmp_not_equal(written, aesBlock)) {
      return std::nullopt;
    }
    const std::uint32_t y = (std::uint32_t{out[0]} << 24U) | (std::uint32_t{out[1]} << 16U) |
                            (std::uint32_t{out[2]} << 8U) | std::uint32_t{out[3]};
    // FF1's alternation: A is the short half on even rounds and the long one on odd rounds, and the
    // sum is taken at A's width, so the halves keep their widths as they trade places.
    const unsigned width = i % 2 == 0 ? shortHalf : longHalf;
    const std::uint32_t c = (a + y) & lowBits(width);
    a = b;
    b = c;
  }
  // An even number of rounds leaves A at 15 bits and B at 16, where they started.
  return (a << longHalf) | b;
}

std::int32_t MessageIds::next(net::ErrorCode& ec) {
  ec = {};
  if (!keyed(ec)) return 0;
  const auto id = permute(m_counter);
  if (!id) {
    ec = make_error_code(Errc::CryptoFailure);
    return 0;
  }
  m_counter = (m_counter + 1) & idMask;
  return static_cast<std::int32_t>(*id);
}

}  // namespace snmpio::detail
