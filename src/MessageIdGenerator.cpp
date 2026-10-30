#include "MessageIdGenerator.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>

#include <snmpio/Error.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace snmpio::detail {
namespace {

// FF1, NIST SP 800-38G Rev. 1 section 6.2, Algorithm 7, at radix 2 over n = 31 numerals with an
// empty tweak. The numeral string is the 31-bit integer, most significant bit first, so NUM and STR
// are plain shifts. FF1 is in neither OpenSSL nor any library snmpio already depends on, so this is
// the SP's algorithm written out over OpenSSL's AES -- a standard construction implemented here,
// as RFC 3414's password-to-key is, rather than one of our own (ADR-0012). The SP's names are kept
// so that each line can be checked against it.
constexpr unsigned n = 31;
constexpr unsigned u = n / 2;  // 15: A, the high half
constexpr unsigned v = n - u;  // 16: B, the low half
constexpr int rounds = 10;

constexpr std::size_t aesBlockBytes = 16;
using Block = std::array<std::byte, aesBlockBytes>;

// b = ceil(ceil(v * log2(radix)) / 8) bytes for NUM(B); d = 4 * ceil(b / 4) + 4 bytes of R for y.
constexpr std::size_t b = (v + 7) / 8;  // 2
constexpr std::size_t d = 8;            // 4 * ceil(2 / 4) + 4

// Step 5: P = [1]^1 || [2]^1 || [1]^1 || [radix]^3 || [10]^1 || [u mod 256]^1 || [n]^4 || [t]^4.
constexpr Block p{std::byte{1}, std::byte{2}, std::byte{1},  std::byte{0},
                  std::byte{0}, std::byte{2}, std::byte{10}, std::byte{u},
                  std::byte{0}, std::byte{0}, std::byte{0},  std::byte{n},
                  std::byte{0}, std::byte{0}, std::byte{0},  std::byte{0}};

constexpr std::uint32_t lowBits(unsigned bits) noexcept {
  return (std::uint32_t{1} << bits) - 1;
}

constexpr std::uint32_t idMask = lowBits(n);

// One AES block under the context's key: ECB, which on one block is the bare cipher.
bool encryptBlock(evp_cipher_ctx_st* ctx, const Block& in, Block& out) {
  int written = 0;
  return EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(out.data()), &written,
                           reinterpret_cast<const unsigned char*>(in.data()),
                           static_cast<int>(in.size())) == 1 &&
         std::cmp_equal(written, aesBlockBytes);
}

}  // namespace

MessageIdGenerator::MessageIdGenerator(std::span<const std::byte, keyBytes> key,
                                       std::uint32_t counter)
    : m_fixedKey(key.begin(), key.end()), m_counter(counter & idMask) {}

MessageIdGenerator::~MessageIdGenerator() {
  EVP_CIPHER_CTX_free(m_ctx);  // which cleanses the key schedule it holds
  cleanse(m_encryptedP.data(), m_encryptedP.size());
}

bool MessageIdGenerator::ensureKeyed(net::ErrorCode& ec) {
  if (m_ctx != nullptr) return true;
  SecretOctets key = m_fixedKey;
  EVP_CIPHER* cipher = EVP_CIPHER_fetch(m_libctx, "AES-128-ECB", nullptr);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  bool ok = cipher != nullptr && ctx != nullptr;
  if (ok && key.empty()) {
    key.resize(keyBytes);
    ok = RAND_bytes_ex(m_libctx, reinterpret_cast<unsigned char*>(key.data()), key.size(), 0) == 1;
  }
  ok = ok &&
       EVP_EncryptInit_ex2(ctx, cipher, reinterpret_cast<const unsigned char*>(key.data()), nullptr,
                           nullptr) == 1 &&
       EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 && encryptBlock(ctx, p, m_encryptedP);
  EVP_CIPHER_free(cipher);  // the context keeps its own reference
  if (!ok) {
    EVP_CIPHER_CTX_free(ctx);
    ec = make_error_code(Errc::CryptoFailure);
    return false;
  }
  m_ctx = ctx;
  return true;
}

// Algorithm 7, steps 2 and 6 to 7, for one 31-bit X.
std::uint32_t MessageIdGenerator::ff1Encrypt(std::uint32_t x, net::ErrorCode& ec) {
  std::uint32_t a = x >> v;              // step 2: A = X[1..u]
  std::uint32_t bHalf = x & lowBits(v);  //         B = X[u+1..n]
  for (int i = 0; i < rounds; ++i) {
    // 6.i: Q = T || [0]^((-t-b-1) mod 16) || [i]^1 || [NUM(B)]^b, the tweak T being empty.
    Block q{};
    q[aesBlockBytes - b - 1] = static_cast<std::byte>(i);
    q[aesBlockBytes - 2] = static_cast<std::byte>(bHalf >> 8U);
    q[aesBlockBytes - 1] = static_cast<std::byte>(bHalf);
    // 6.ii: R = PRF(P || Q), the CBC-MAC of the two blocks, whose first step is m_encryptedP.
    Block chained{};
    std::ranges::transform(m_encryptedP, q, chained.begin(), std::bit_xor<>());
    Block r{};
    if (!encryptBlock(m_ctx, chained, r)) {
      ec = make_error_code(Errc::CryptoFailure);
      return 0;
    }
    // 6.iii-iv: S is R's first d bytes, as d is no more than a block, and y = NUM(S).
    std::uint64_t y = 0;
    for (std::size_t j = 0; j < d; ++j) y = (y << 8U) | std::to_integer<std::uint64_t>(r.at(j));
    // 6.v-vii: m = u on even rounds and v on odd ones, c = (NUM(A) + y) mod 2^m. 2^m divides 2^64,
    // so y may be cut to m bits first.
    const unsigned m = i % 2 == 0 ? u : v;
    const std::uint32_t c = (a + static_cast<std::uint32_t>(y & lowBits(m))) & lowBits(m);
    // 6.viii-ix: A = B, B = C.
    a = bHalf;
    bHalf = c;
  }
  // Step 7: A || B. Ten rounds, an even number, leave A at u bits and B at v, where they started.
  return (a << v) | bHalf;
}

void MessageIdGenerator::rewind(std::uint32_t steps) noexcept {
  m_counter = (m_counter - steps) & idMask;
}

std::int32_t MessageIdGenerator::draw(net::ErrorCode& ec) {
  ec = {};
  if (!ensureKeyed(ec)) return 0;
  const std::uint32_t id = ff1Encrypt(m_counter, ec);
  if (ec) return 0;
  m_counter = (m_counter + 1) & idMask;
  return static_cast<std::int32_t>(id);
}

}  // namespace snmpio::detail
