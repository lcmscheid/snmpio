#include <gtest/gtest.h>

#include <array>

#include <snmpio/Usm.hpp>

#include "Bytes.hpp"

namespace snmpio {
namespace {

using test::bytes;
using test::hex;

// RFC 3414 appendix A.3 uses this password and this engineID for both of its worked examples, so
// the MD5 and SHA-1 rows below are the specification's own numbers rather than ours.
constexpr std::string_view password = "maplesyrup";

Octets engineId() {
  return bytes({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
}

Octets fromHex(std::string_view s) {
  Octets out;
  for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
    const auto nibble = [](char c) {
      return static_cast<unsigned>(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    };
    out.push_back(static_cast<std::byte>((nibble(s[i]) << 4) | nibble(s[i + 1])));
  }
  return out;
}

struct KeyVector {
  AuthProtocol protocol;
  std::string_view master;
  std::string_view localized;
};

// MD5 and SHA-1 are RFC 3414 A.3.1 and A.3.2 verbatim. RFC 7860 publishes no key-derivation
// vectors, so the four SHA-2 rows were computed from a separate implementation of appendix A.2 in
// Python over hashlib -- an independent witness rather than this code's own output. The two RFC
// rows are what pin the algorithm itself.
const std::array<KeyVector, 6> keyVectors = {{
    {AuthProtocol::Md5, "9faf3283884e92834ebc9847d8edd963", "526f5eed9fcce26f8964c2930787d82b"},
    {AuthProtocol::Sha1, "9fb5cc0381497b3793528939ff788d5d79145211",
     "6695febc9288e36282235fc7151f128497b38f3f"},
    {AuthProtocol::Sha224, "282a5867ee9aac639ad59df9572c7d3ac0fbc13a905b6df07dbbf00b",
     "0bd8827c6e29f8065e08e09237f177e410f69b90e1782be682075674"},
    {AuthProtocol::Sha256, "ab51014d1e077f6017df2b12bee5f5aa72993177e9bb569c4dff5a4ca0b4afac",
     "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"},
    {AuthProtocol::Sha384,
     "e06eccdf2c68a06ed034723c9c26e0db3b669e1e2efed49150b55377a2e98f383c86fb836857444654b287c93f51"
     "ff64",
     "3b298f16164a11184279d5432bf169e2d2a48307de02b3d3f7e2b4f36eb6f0455a53689a3937eea07319a633d2cc"
     "ba78"},
    {AuthProtocol::Sha512,
     "7e4396de5aadc77be853819b98c9406265b3a9c37cc3176569847a4e4f6fba63dd3a73d04924d31a63f95a601f93"
     "85af6be4ed1b37f87d040f7c6ed6f8d38a91",
     "22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099ad1ea87a8db096714d9788bd5440"
     "47c9021e4229ce27e4c0a69250adfcffbb0b"},
}};

TEST(PasswordToKey, MatchesTheKnownVectors) {
  for (const auto& v : keyVectors) {
    net::ErrorCode ec;
    const auto master = passwordToKey(v.protocol, password, ec);
    EXPECT_FALSE(ec) << ec.message();
    EXPECT_EQ(hex(master), hex(fromHex(v.master))) << "protocol " << static_cast<int>(v.protocol);
    EXPECT_EQ(master.size(), keySize(v.protocol));
  }
}

TEST(LocalizeKey, MatchesTheKnownVectors) {
  for (const auto& v : keyVectors) {
    net::ErrorCode ec;
    const auto master = passwordToKey(v.protocol, password, ec);
    const auto local = localizeKey(v.protocol, master, engineId(), ec);
    EXPECT_FALSE(ec) << ec.message();
    EXPECT_EQ(hex(local), hex(fromHex(v.localized))) << "protocol " << static_cast<int>(v.protocol);
  }
}

TEST(LocalizeKey, DiffersPerEngine) {
  net::ErrorCode ec;
  const auto master = passwordToKey(AuthProtocol::Sha256, password, ec);
  const auto a = localizeKey(AuthProtocol::Sha256, master, engineId(), ec);
  const auto b = localizeKey(AuthProtocol::Sha256, master, bytes({0x80, 0x00, 0x1f, 0x88}), ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_NE(a, b);
}

TEST(LocalizedAuthKey, IsPasswordToKeyThenLocalize) {
  const Credentials creds{"bert", SecurityLevel::AuthNoPriv, AuthProtocol::Sha1,
                          std::string(password)};
  net::ErrorCode ec;
  const auto direct = localizedAuthKey(creds, engineId(), ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_EQ(hex(direct), hex(fromHex(keyVectors[1].localized)));
}

TEST(KeyDerivation, RejectsNoAuthProtocol) {
  net::ErrorCode ec;
  EXPECT_TRUE(passwordToKey(AuthProtocol::None, password, ec).empty());
  EXPECT_EQ(ec, make_error_code(Errc::UnsupportedAuthProtocol));

  ec = {};
  EXPECT_TRUE(localizeKey(AuthProtocol::None, bytes({0x00}), engineId(), ec).empty());
  EXPECT_EQ(ec, make_error_code(Errc::UnsupportedAuthProtocol));
}

// RFC 7860 section 4.2: the truncation widths are the protocol's, not the hash's. Getting one of
// these wrong produces a message every Agent rejects and no test would otherwise notice.
TEST(AuthParamsSize, IsTheProtocolsTruncationWidth) {
  EXPECT_EQ(authParamsSize(AuthProtocol::None), 0U);
  EXPECT_EQ(authParamsSize(AuthProtocol::Md5), 12U);
  EXPECT_EQ(authParamsSize(AuthProtocol::Sha1), 12U);
  EXPECT_EQ(authParamsSize(AuthProtocol::Sha224), 16U);
  EXPECT_EQ(authParamsSize(AuthProtocol::Sha256), 24U);
  EXPECT_EQ(authParamsSize(AuthProtocol::Sha384), 32U);
  EXPECT_EQ(authParamsSize(AuthProtocol::Sha512), 48U);
}

TEST(KeySize, IsTheHashsFullDigest) {
  EXPECT_EQ(keySize(AuthProtocol::None), 0U);
  EXPECT_EQ(keySize(AuthProtocol::Md5), 16U);
  EXPECT_EQ(keySize(AuthProtocol::Sha1), 20U);
  EXPECT_EQ(keySize(AuthProtocol::Sha224), 28U);
  EXPECT_EQ(keySize(AuthProtocol::Sha256), 32U);
  EXPECT_EQ(keySize(AuthProtocol::Sha384), 48U);
  EXPECT_EQ(keySize(AuthProtocol::Sha512), 64U);
}

// RFC 2202's second HMAC-MD5 case, truncated the way USM truncates. HMAC is OpenSSL's, so what
// this pins is our key handling and our truncation, which are the parts we wrote.
TEST(AuthDigest, MatchesAKnownHmac) {
  const auto key = bytes({0x4a, 0x65, 0x66, 0x65});  // "Jefe"
  const auto message =
      bytes({0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
             0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f});
  net::ErrorCode ec;
  const auto digest = authDigest(AuthProtocol::Md5, key, message, ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_EQ(hex(digest), hex(fromHex("750c783e6ab0b503eaa86e31")));
}

TEST(AuthDigest, IsTruncatedToTheProtocolWidth) {
  net::ErrorCode ec;
  const auto key = passwordToKey(AuthProtocol::Sha512, password, ec);
  const auto digest = authDigest(AuthProtocol::Sha512, key, bytes({0x01, 0x02}), ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_EQ(digest.size(), authParamsSize(AuthProtocol::Sha512));
}

TEST(AuthDigest, DependsOnTheKey) {
  net::ErrorCode ec;
  const auto message = bytes({0x30, 0x03, 0x02, 0x01, 0x00});
  const auto a = authDigest(AuthProtocol::Sha256, bytes({0x01, 0x02, 0x03}), message, ec);
  const auto b = authDigest(AuthProtocol::Sha256, bytes({0x01, 0x02, 0x04}), message, ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_NE(a, b);
}

}  // namespace
}  // namespace snmpio
