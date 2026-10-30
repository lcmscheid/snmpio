#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <set>
#include <span>
#include <string_view>

#include <snmpio/Error.hpp>

#include "MessageIds.hpp"

#include <openssl/crypto.h>
#include <openssl/provider.h>

// The generator behind every Message ID and request-id (threat model R7), tested on its own: what
// it computes, and what it refuses to hand out. TestMessageIds.cpp checks the same IDs as an Agent
// sees them.
namespace snmpio {
namespace {

using detail::MessageIds;

using Key = std::array<std::byte, MessageIds::keyBytes>;

// Upper-case hex, as the SPs print their keys.
Key keyFromHex(std::string_view hex) {
  constexpr std::string_view digits = "0123456789ABCDEF";
  const auto nibble = [&](std::size_t at) {
    return static_cast<unsigned>(digits.find(hex.at(at)));
  };
  Key key{};
  for (std::size_t i = 0; i < key.size(); ++i) {
    key.at(i) = static_cast<std::byte>((nibble(2 * i) << 4U) | nibble((2 * i) + 1));
  }
  return key;
}

// NIST's FF1 sample key (SP 800-38G's published samples, and SP 800-38A's AES-128 key).
const Key nistKey = keyFromHex("2B7E151628AED2A6ABF7158809CF4F3C");
const Key countingKey = keyFromHex("000102030405060708090A0B0C0D0E0F");

constexpr auto never = [](std::int32_t) { return false; };

std::int32_t draw(MessageIds& ids) {
  net::ErrorCode ec;
  const auto id = ids.next(never, ec);
  EXPECT_FALSE(ec) << ec.message();
  return id;
}

// FF1 (NIST SP 800-38G Rev. 1) at radix 2 over 31 numerals, with an empty tweak: each ID is
// FF1.Encrypt of the counter, written most significant bit first. No standard publishes radix-2
// vectors, so these were computed with an independent FF1 -- Python, any radix, written from the
// SP's Algorithms 7 and 8 over pyca/cryptography's AES -- which reproduces NIST's published FF1
// samples 1 to 3 before producing them. Like the SHA-2 key-derivation rows, they pin against drift
// rather than against being wrong.
struct Ff1Row {
  const Key* key;
  std::uint32_t counter;
  std::int32_t id;
};

const std::array ff1Rows{
    Ff1Row{&nistKey, 0x00000000, 0x3e24e95c},     Ff1Row{&nistKey, 0x00000001, 0x43bba4fc},
    Ff1Row{&nistKey, 0x00000002, 0x6e97bc71},     Ff1Row{&nistKey, 0x00000003, 0x19982df3},
    Ff1Row{&nistKey, 0x7ffffffe, 0x5d51c25a},     Ff1Row{&nistKey, 0x7fffffff, 0x1a5fb67c},
    Ff1Row{&countingKey, 0x00000000, 0x5495cd27}, Ff1Row{&countingKey, 0x00000001, 0x00d3c01f},
    Ff1Row{&countingKey, 0x00000002, 0x65102c8a}, Ff1Row{&countingKey, 0x00000003, 0x3fdcbb18},
    Ff1Row{&countingKey, 0x7ffffffe, 0x4a91f151}, Ff1Row{&countingKey, 0x7fffffff, 0x7ccbb3f5},
};

TEST(MessageIdGenerator, IsFf1AtRadixTwoOverThirtyOneBits) {
  for (const auto& row : ff1Rows) {
    MessageIds ids(*row.key, row.counter);
    EXPECT_EQ(draw(ids), row.id) << "counter " << row.counter;
  }
}

TEST(MessageIdGenerator, TheCounterWrapsAtThirtyOneBits) {
  MessageIds ids(nistKey, 0x7fffffff);
  EXPECT_EQ(draw(ids), 0x1a5fb67c);
  EXPECT_EQ(draw(ids), 0x3e24e95c);  // the counter's 0
}

// A permutation repeats nothing. Short of drawing all 2^31, a run long enough that an ad-hoc
// construction's collisions would show, every ID inside 0..2^31-1.
TEST(MessageIdGenerator, SixtyFiveThousandIdsAreAllDistinct) {
  constexpr std::size_t count = 65536;
  MessageIds ids;
  std::set<std::int32_t> seen;
  for (std::size_t i = 0; i < count; ++i) {
    const auto id = draw(ids);
    EXPECT_GE(id, 0);
    seen.insert(id);
  }
  EXPECT_EQ(seen.size(), count);
}

// The counter that FF1 maps to 0 under each key, and the IDs the two after it map to.
TEST(MessageIdGenerator, NeverHandsOutZero) {
  MessageIds nist(nistKey, 0x7f4053b8);
  EXPECT_EQ(draw(nist), 0x168dfc62);
  MessageIds counting(countingKey, 0x357087c6);
  EXPECT_EQ(draw(counting), 0x1d2b9496);
}

// RFC 3412 section 6.2: no re-use of a value still outstanding. Only once the counter has gone all
// the way round can the permutation reach one, so the test says which are.
TEST(MessageIdGenerator, SkipsAnIdStillOutstanding) {
  MessageIds ids(nistKey, 0);
  net::ErrorCode ec;
  const auto id = ids.next([](std::int32_t candidate) { return candidate == 0x3e24e95c; }, ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_EQ(id, 0x43bba4fc);  // the counter's 1: its 0 is outstanding
  EXPECT_EQ(draw(ids), 0x6e97bc71);
}

TEST(MessageIdGenerator, SkipsZeroAndOutstandingIdsInARow) {
  MessageIds ids(nistKey, 0x7f4053b8);
  net::ErrorCode ec;
  const auto id = ids.next([](std::int32_t candidate) { return candidate == 0x168dfc62; }, ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_EQ(id, 0x2c09007c);
}

// An OpenSSL with no provider that offers AES or a random number generator: the null provider,
// loaded into a library context of the test's own, which keeps the default one from loading there.
struct NoProviders {
  OSSL_LIB_CTX* ctx = OSSL_LIB_CTX_new();
  OSSL_PROVIDER* null = OSSL_PROVIDER_load(ctx, "null");

  NoProviders() = default;
  NoProviders(const NoProviders&) = delete;
  NoProviders& operator=(const NoProviders&) = delete;
  NoProviders(NoProviders&&) = delete;
  NoProviders& operator=(NoProviders&&) = delete;
  ~NoProviders() {
    OSSL_PROVIDER_unload(null);
    OSSL_LIB_CTX_free(ctx);
  }
};

TEST(MessageIdGenerator, NoKeyIsCryptoFailureAndNoId) {
  const NoProviders openssl;
  ASSERT_NE(openssl.ctx, nullptr);
  ASSERT_NE(openssl.null, nullptr);
  MessageIds ids(openssl.ctx);
  net::ErrorCode ec;
  EXPECT_EQ(ids.next(never, ec), 0);
  EXPECT_EQ(ec, make_error_code(Errc::CryptoFailure));
}

// Keying is retried on the next ID asked for, so a Client whose OpenSSL could not key it once is
// not left unable to send for the rest of its life.
TEST(MessageIdGenerator, AFailedKeyingIsTriedAgain) {
  const NoProviders openssl;
  ASSERT_NE(openssl.ctx, nullptr);
  MessageIds ids(openssl.ctx);
  net::ErrorCode ec;
  (void)ids.next(never, ec);
  ASSERT_EQ(ec, make_error_code(Errc::CryptoFailure));

  OSSL_PROVIDER* const provider = OSSL_PROVIDER_load(openssl.ctx, "default");
  ASSERT_NE(provider, nullptr);
  (void)ids.next(never, ec);
  EXPECT_FALSE(ec) << ec.message();
  OSSL_PROVIDER_unload(provider);
}

}  // namespace
}  // namespace snmpio
