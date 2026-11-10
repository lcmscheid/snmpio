#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <snmpio/Usm.hpp>

#include "Bytes.hpp"
#include "RefusedFetches.hpp"

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
      const unsigned u = static_cast<unsigned char>(c);
      return u <= '9' ? u - '0' : (u | 0x20U) - 'a' + 10;
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

// The expansion is hashed about 16 KiB at a time, from one buffer of the password repeated a whole
// number of times, so where each update starts depends on where the one before it ended. These
// lengths are the ones a mistake in that shows up at: the shortest RFC 3414 allows, two lengths
// that divide nothing, either side of RFC 3414's 64-Octet line, a password that fits the buffer
// only once and one that fits it exactly, one longer than the target, which is the buffer on its
// own, and one longer than the whole megabyte, of which only the first megabyte is hashed. Computed
// with Python's hashlib over the megabyte built whole.
TEST(PasswordToKey, MatchesAWholeMegabyteHashAtAwkwardLengths) {
  struct Row {
    std::string password;
    std::string_view master;
  };
  // A period of 16 divides the buffer and the megabyte, so the rows added for the buffer's and the
  // megabyte's edges use 17; the 5000-character row keeps the 16 it was pinned with.
  const auto patterned = [](std::size_t length, std::string_view period) {
    std::string out;
    while (out.size() < length) out += period;
    out.resize(length);
    return out;
  };
  const std::array<Row, 10> rows = {{
      {"eight888", "0e5e24d878d7db0e5635d6d65c00fb27a026cc64b7cca7156a1380f48dcf2a15"},
      {"ninechars", "4b033e5f3013a79a98ee2f7c8023104b6d79079929b09da7cc6d25381d9a2b6b"},
      {"elevenchars", "3b9059c889f9cf8661247e5a4ee5fce56716769e02796ea070d7b799afdef515"},
      {std::string(64, 'x'), "8f990ba0b577b51cf009ea049368c16bbda1b21e1b93be07a824758bb253c39b"},
      {std::string(65, 'y'), "34bc6ad8178071438d388d4680bc6c236abeb0c88be1cee99a16f921d7d84999"},
      {patterned(5000, "0123456789abcdef"),
       "1096a56a200363fa5ebe4063f8e5df3926098bd5df90945d860f31a02dbcfcb7"},
      {patterned(8193, "0123456789abcdefg"),
       "c456ce4de4bd0172d24a37cb11b3048b35c00107304e157720fab43e721ee0f3"},
      {patterned(16384, "0123456789abcdefg"),
       "116f587e8ea8ad1026058d86c7be2549488e1164534c79ed57922997e4e71173"},
      {patterned(16385, "0123456789abcdefg"),
       "1e05e89e71291aea33f665b7f6d8cfa1205f2058bde1dcbb8b6c439a67c52c4d"},
      {patterned(1048579, "0123456789abcdefg"),
       "b55ef8d0cda47fa1791f5f1c1fc0d3545cbb32a2e48b31bcd699765b18b77e28"},
  }};
  for (const auto& row : rows) {
    net::ErrorCode ec;
    const auto master = passwordToKey(AuthProtocol::Sha256, row.password, ec);
    EXPECT_FALSE(ec) << ec.message();
    EXPECT_EQ(hex(master), hex(fromHex(row.master))) << row.password.size() << " characters";
  }
}

// RFC 3414 section 11.2: "a password ... MUST be at least 8 characters". Refused here too, not
// only by the Client, so that a Master Key derived ahead of time is held to the same rule; empty is
// one of the lengths refused, not a fault of its own.
TEST(PasswordToKey, RefusesAPasswordShorterThanEightCharacters) {
  for (const std::string_view tooShort : {"", "a", "seven77"}) {
    net::ErrorCode ec;
    const auto master = passwordToKey(AuthProtocol::Sha256, tooShort, ec);
    EXPECT_EQ(ec, Errc::PasswordTooShort) << tooShort.size() << " characters";
    EXPECT_TRUE(master.empty());
  }
  net::ErrorCode ec;
  const auto master = passwordToKey(AuthProtocol::Sha256, "eight888", ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_EQ(master.size(), keySize(AuthProtocol::Sha256));
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
  const Credentials creds{"bert",
                          SecurityLevel::AuthNoPriv,
                          AuthProtocol::Sha1,
                          std::string(password),
                          PrivProtocol::None,
                          ""};
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

// ---------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------

// The engineID the privacy rows below are localized against. Not RFC 3414 A.3's, because no RFC
// publishes privacy key vectors -- these come from gosnmp, whose numbers are an independent
// witness in exactly the way the SHA-2 rows above are.
Octets privEngineId() {
  return bytes({0x80, 0x00, 0x1f, 0x88, 0x01, 0x02, 0x03, 0x04});
}

constexpr std::string_view privPassword = "privatepass";

Credentials privCreds(AuthProtocol auth, PrivProtocol priv) {
  return Credentials{"bert", SecurityLevel::AuthPriv,  auth, std::string(password),
                     priv,   std::string(privPassword)};
}

struct PrivKeyVector {
  AuthProtocol auth;
  PrivProtocol priv;
  std::string_view key;
};

// Generated with gosnmp 1.44.0 against auth password "maplesyrup", privacy password "privatepass"
// and engineID 80001f8801020304. The Blumenthal and Reeder rows differ from each other exactly
// where a Localized Key is shorter than the cipher's key, which is the whole of what the two
// drafts disagree about: at SHA-256 and above nothing needs extending and both spellings agree.
const std::array<PrivKeyVector, 10> privKeyVectors = {{
    {AuthProtocol::Md5, PrivProtocol::Des, "fbba0b84aca7ba2af2bae2421ba6f37f"},
    {AuthProtocol::Md5, PrivProtocol::Aes128, "fbba0b84aca7ba2af2bae2421ba6f37f"},
    {AuthProtocol::Md5, PrivProtocol::Aes192, "fbba0b84aca7ba2af2bae2421ba6f37f132bb40cf474514f"},
    {AuthProtocol::Md5, PrivProtocol::Aes256,
     "fbba0b84aca7ba2af2bae2421ba6f37f132bb40cf474514f6d390c6a3b4f3f04"},
    {AuthProtocol::Md5, PrivProtocol::Aes192C, "fbba0b84aca7ba2af2bae2421ba6f37ff056c7daa2baf273"},
    {AuthProtocol::Md5, PrivProtocol::Aes256C,
     "fbba0b84aca7ba2af2bae2421ba6f37ff056c7daa2baf2737b9a2cecfaa3201c"},
    {AuthProtocol::Sha1, PrivProtocol::Aes128, "7e64bf0cb2dc337bb93bea9c0a8d6939"},
    {AuthProtocol::Sha1, PrivProtocol::Aes256,
     "7e64bf0cb2dc337bb93bea9c0a8d6939be197653c125768fe44e0ae77c531696"},
    {AuthProtocol::Sha1, PrivProtocol::Aes256C,
     "7e64bf0cb2dc337bb93bea9c0a8d6939be197653f121f857f051e97b34d3678c"},
    {AuthProtocol::Sha512, PrivProtocol::Aes256,
     "fb65c12da7edcf6a20eaf571eecfd5f5aa8a6d6bebce9f3c747ba8a626044443"},
}};

TEST(LocalizedPrivKey, MatchesTheVectors) {
  for (const auto& v : privKeyVectors) {
    net::ErrorCode ec;
    const auto key = localizedPrivKey(privCreds(v.auth, v.priv), privEngineId(), ec);
    EXPECT_FALSE(ec) << ec.message();
    EXPECT_EQ(hex(key), hex(fromHex(v.key)))
        << "auth " << static_cast<int>(v.auth) << " priv " << static_cast<int>(v.priv);
  }
}

// The same rows from a Master Key the caller derived, which is how Credentials carrying one reach
// the Engine: what the password would have been expanded into, and nothing else, is the input.
TEST(LocalizedPrivKey, FromAMasterKeyMatchesTheVectors) {
  for (const auto& v : privKeyVectors) {
    net::ErrorCode ec;
    const auto master = passwordToKey(v.auth, privPassword, ec);
    ASSERT_FALSE(ec) << ec.message();
    const auto key = localizedPrivKey(v.auth, v.priv, master, privEngineId(), ec);
    EXPECT_FALSE(ec) << ec.message();
    EXPECT_EQ(hex(key), hex(fromHex(v.key)))
        << "auth " << static_cast<int>(v.auth) << " priv " << static_cast<int>(v.priv);
  }
}

// Credentials may carry either secret as a Master Key, and the Credentials overloads read it in
// place of the password.
TEST(LocalizedKeys, ReadAMasterKeyTheCredentialsCarry) {
  for (const auto& v : privKeyVectors) {
    net::ErrorCode ec;
    auto creds = privCreds(v.auth, v.priv);
    const auto viaPasswords = localizedAuthKey(creds, privEngineId(), ec);
    ASSERT_FALSE(ec) << ec.message();
    creds.authMasterKey = passwordToKey(v.auth, creds.authPassword.view(), ec);
    creds.privMasterKey = passwordToKey(v.auth, creds.privPassword.view(), ec);
    creds.authPassword.clear();
    creds.privPassword.clear();

    EXPECT_EQ(hex(localizedAuthKey(creds, privEngineId(), ec)), hex(viaPasswords));
    EXPECT_FALSE(ec) << ec.message();
    EXPECT_EQ(hex(localizedPrivKey(creds, privEngineId(), ec)), hex(fromHex(v.key)));
    EXPECT_FALSE(ec) << ec.message();
  }
}

// The two extensions are mutually incompatible (ADR-0005), so a key derived under one must never
// be usable under the other. Sharing a prefix is expected -- both start from the same Localized
// Key -- and is exactly why only the tail proves anything.
TEST(LocalizedPrivKey, BlumenthalAndReederDiffer) {
  net::ErrorCode ec;
  const auto blumenthal =
      localizedPrivKey(privCreds(AuthProtocol::Md5, PrivProtocol::Aes256), privEngineId(), ec);
  const auto reeder =
      localizedPrivKey(privCreds(AuthProtocol::Md5, PrivProtocol::Aes256C), privEngineId(), ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_NE(blumenthal, reeder);
  EXPECT_TRUE(std::equal(blumenthal.begin(), blumenthal.begin() + 16, reeder.begin()));
}

TEST(LocalizedPrivKey, RejectsNoPrivProtocol) {
  net::ErrorCode ec;
  const auto key =
      localizedPrivKey(privCreds(AuthProtocol::Sha1, PrivProtocol::None), privEngineId(), ec);
  EXPECT_TRUE(key.empty());
  EXPECT_EQ(ec, make_error_code(Errc::UnsupportedPrivProtocol));
}

TEST(PrivKeySize, IsTheCiphersKeyPlusDessPreIv) {
  EXPECT_EQ(privKeySize(PrivProtocol::None), 0U);
  EXPECT_EQ(privKeySize(PrivProtocol::Des), 16U);  // 8 of key, 8 of pre-IV
  EXPECT_EQ(privKeySize(PrivProtocol::Aes128), 16U);
  EXPECT_EQ(privKeySize(PrivProtocol::Aes192), 24U);
  EXPECT_EQ(privKeySize(PrivProtocol::Aes192C), 24U);
  EXPECT_EQ(privKeySize(PrivProtocol::Aes256), 32U);
  EXPECT_EQ(privKeySize(PrivProtocol::Aes256C), 32U);
}

// Known answers from Python's `cryptography`, over an IV built there from the draft's own
// description. What this pins is the IV -- the boots/time/salt order for AES, the pre-IV XOR for
// DES -- because the cipher underneath is OpenSSL's and needs no test of ours.
TEST(PrivDecrypt, MatchesAKnownAesAnswer) {
  const auto key = fromHex("7e64bf0cb2dc337bb93bea9c0a8d6939");
  const auto salt = fromHex("0011223344556677");
  Octets ciphertext;
  for (int i = 0; i < 32; ++i) ciphertext.push_back(static_cast<std::byte>(i));

  net::ErrorCode ec;
  const auto plain = privDecrypt(PrivProtocol::Aes128, key, 5, 1000, salt, ciphertext, ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_EQ(hex(plain),
            hex(fromHex("5e101faa4b0bc193da57972253a244622de32cba52a74625bfca9b72de5b2eef")));
}

TEST(PrivDecrypt, MatchesAKnownDesAnswer) {
  const auto key = fromHex("fbba0b84aca7ba2af2bae2421ba6f37f");
  const auto salt = fromHex("00000005aabbccdd");
  Octets ciphertext;
  for (int i = 0; i < 16; ++i) ciphertext.push_back(static_cast<std::byte>(i));

  net::ErrorCode ec;
  const auto plain = privDecrypt(PrivProtocol::Des, key, 5, 1000, salt, ciphertext, ec);
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_EQ(hex(plain), hex(fromHex("1d103b0998d524805851d0a948d6a39e")));
}

TEST(Privacy, RoundTripsUnderEveryProtocol) {
  const std::array<PrivProtocol, 6> protocols = {PrivProtocol::Des,     PrivProtocol::Aes128,
                                                 PrivProtocol::Aes192,  PrivProtocol::Aes256,
                                                 PrivProtocol::Aes192C, PrivProtocol::Aes256C};
  // 21 Octets: not a multiple of the DES block, so the padding path runs.
  Octets plaintext;
  for (int i = 0; i < 21; ++i) plaintext.push_back(static_cast<std::byte>(0x40 + i));

  for (const auto p : protocols) {
    net::ErrorCode ec;
    const auto key = localizedPrivKey(privCreds(AuthProtocol::Sha256, p), privEngineId(), ec);
    ASSERT_FALSE(ec) << ec.message();

    Octets salt;
    const auto ciphertext = privEncrypt(p, key, 7, 1234, plaintext, salt, ec);
    ASSERT_FALSE(ec) << ec.message();
    EXPECT_EQ(salt.size(), 8U);
    EXPECT_NE(hex(ciphertext), hex(plaintext));

    const auto back = privDecrypt(p, key, 7, 1234, salt, ciphertext, ec);
    ASSERT_FALSE(ec) << ec.message();
    // DES pads to the block, and RFC 3414 section 8.1.1.2 leaves the pad in place on the way back.
    ASSERT_GE(back.size(), plaintext.size());
    EXPECT_TRUE(std::equal(plaintext.begin(), plaintext.end(), back.begin()));
  }
}

// RFC 3414 section 8.1.1.1: the DES salt carries the boots count, so the same counter under two
// Engines cannot produce the same IV.
TEST(PrivEncrypt, DesSaltCarriesTheBootsCount) {
  const auto key = fromHex("fbba0b84aca7ba2af2bae2421ba6f37f");
  net::ErrorCode ec;
  Octets salt;
  static_cast<void>(privEncrypt(PrivProtocol::Des, key, 0x01020304, 9, bytes({0x00}), salt, ec));
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_EQ(hex(std::span(salt).first(4)), hex(fromHex("01020304")));
}

// The salt has to differ per message or the same key encrypts two messages under one IV.
TEST(PrivEncrypt, ChoosesAFreshSaltEachTime) {
  const auto key = fromHex("7e64bf0cb2dc337bb93bea9c0a8d6939");
  net::ErrorCode ec;
  Octets first;
  Octets second;
  static_cast<void>(privEncrypt(PrivProtocol::Aes128, key, 1, 1, bytes({0x00}), first, ec));
  static_cast<void>(privEncrypt(PrivProtocol::Aes128, key, 1, 1, bytes({0x00}), second, ec));
  EXPECT_FALSE(ec) << ec.message();
  EXPECT_NE(first, second);
}

// A misbehaving Agent's encryptedPDU (ADR-0006): both protocols fix msgPrivacyParameters at eight
// Octets and derive the IV by indexing it, so a short one has to be refused rather than read past.
TEST(PrivDecrypt, RejectsAShortSalt) {
  const auto key = fromHex("7e64bf0cb2dc337bb93bea9c0a8d6939");
  net::ErrorCode ec;
  const auto plain =
      privDecrypt(PrivProtocol::Aes128, key, 1, 1, bytes({0x00, 0x01}), bytes({0x00}), ec);
  EXPECT_TRUE(plain.empty());
  EXPECT_EQ(ec, make_error_code(Errc::DecryptionFailed));
}

TEST(PrivDecrypt, RejectsDesCiphertextThatIsNotWholeBlocks) {
  const auto key = fromHex("fbba0b84aca7ba2af2bae2421ba6f37f");
  net::ErrorCode ec;
  const auto plain = privDecrypt(PrivProtocol::Des, key, 1, 1, fromHex("0011223344556677"),
                                 bytes({0x00, 0x01, 0x02}), ec);
  EXPECT_TRUE(plain.empty());
  EXPECT_EQ(ec, make_error_code(Errc::DecryptionFailed));
}

TEST(PrivDecrypt, RejectsAKeyTooShortForTheProtocol) {
  net::ErrorCode ec;
  const auto plain = privDecrypt(PrivProtocol::Aes256, fromHex("00112233"), 1, 1,
                                 fromHex("0011223344556677"), bytes({0x00}), ec);
  EXPECT_TRUE(plain.empty());
  EXPECT_EQ(ec, make_error_code(Errc::UnsupportedPrivProtocol));
}

// ---------------------------------------------------------------------------
// Algorithm fetches (#47)
// ---------------------------------------------------------------------------

// Every derivation, digest and crypt a request makes under one pair of protocols, as one string:
// the keys, an HMAC, and a round trip through the cipher, or the first error met on the way.
std::string everyCryptoCall(AuthProtocol auth, PrivProtocol priv) {
  net::ErrorCode ec;
  const auto creds = privCreds(auth, priv);
  const auto authKey = localizedAuthKey(creds, privEngineId(), ec);
  if (ec) return "localizedAuthKey: " + ec.message();
  const auto privKey = localizedPrivKey(creds, privEngineId(), ec);
  if (ec) return "localizedPrivKey: " + ec.message();
  const auto digest = authDigest(auth, authKey, bytes({0x30, 0x03, 0x02, 0x01, 0x03}), ec);
  if (ec) return "authDigest: " + ec.message();
  const auto plaintext = bytes({0x30, 0x05, 0x04, 0x03, 0x61, 0x62, 0x63});
  Octets salt;
  const auto ciphertext = privEncrypt(priv, privKey, 7, 1234, plaintext, salt, ec);
  if (ec) return "privEncrypt: " + ec.message();
  const auto back = privDecrypt(priv, privKey, 7, 1234, salt, ciphertext, ec);
  if (ec) return "privDecrypt: " + ec.message();
  return hex(authKey) + " " + hex(privKey) + " " + hex(digest) + " " + hex(back);
}

// OpenSSL's guide asks for one explicit fetch, reused, by anything that runs the same algorithm
// many times. Once each pair of protocols has run, every call under it gives the same answer with
// fetching refused outright, which an implicit fetch at each call -- EVP_sha256() and HMAC() both
// make one -- or a fresh EVP_CIPHER_fetch would fail.
TEST(Algorithms, AreFetchedOnceAndReusedByEveryCall) {
  std::vector<std::pair<AuthProtocol, PrivProtocol>> pairs;
  for (const auto auth : {AuthProtocol::Md5, AuthProtocol::Sha1, AuthProtocol::Sha224,
                          AuthProtocol::Sha256, AuthProtocol::Sha384, AuthProtocol::Sha512}) {
    pairs.emplace_back(auth, PrivProtocol::Aes128);
  }
  for (const auto priv : {PrivProtocol::Des, PrivProtocol::Aes192, PrivProtocol::Aes256,
                          PrivProtocol::Aes192C, PrivProtocol::Aes256C}) {
    pairs.emplace_back(AuthProtocol::Md5, priv);  // MD5's 16 Octets need extending for all four AES
  }

  std::vector<std::string> fetching;
  for (const auto& [auth, priv] : pairs) {
    fetching.push_back(everyCryptoCall(auth, priv));
    ASSERT_EQ(fetching.back().find(':'), std::string::npos) << fetching.back();
  }

  const test::RefusedFetches refused;
  ASSERT_TRUE(refused.refusing());
  for (std::size_t i = 0; i < pairs.size(); ++i) {
    EXPECT_EQ(everyCryptoCall(pairs[i].first, pairs[i].second), fetching[i])
        << "auth " << static_cast<int>(pairs[i].first) << " priv "
        << static_cast<int>(pairs[i].second);
  }
}

}  // namespace
}  // namespace snmpio
