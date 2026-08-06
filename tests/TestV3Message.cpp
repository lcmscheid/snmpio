#include <gtest/gtest.h>

#include <algorithm>
#include <string>

#include <snmpio/V3Message.hpp>

#include "Bytes.hpp"

namespace snmpio {
namespace {

using test::bytes;

const Oid sysUpTime{1, 3, 6, 1, 2, 1, 1, 3, 0};

Octets engineId() {
  return bytes({0x80, 0x00, 0x1f, 0x88, 0x80, 0x3d, 0x1c, 0xa8});
}

ScopedPdu scopedGet() {
  ScopedPdu s;
  s.contextEngineId = engineId();
  s.pdu.type = PduType::Get;
  s.pdu.requestId = 0x2a;
  s.pdu.varbinds = {Varbind{sysUpTime, null}};
  return s;
}

UsmParameters params() {
  UsmParameters u;
  u.engineId = engineId();
  u.boots = 7;
  u.time = 12345;
  u.userName = "bert";
  return u;
}

Octets authKey(AuthProtocol p) {
  net::ErrorCode ec;
  const Credentials creds{"bert",       SecurityLevel::AuthNoPriv, p,
                          "maplesyrup", PrivProtocol::None,        ""};
  auto key = localizedAuthKey(creds, engineId(), ec);
  EXPECT_FALSE(ec) << ec.message();
  return key;
}

TEST(V3Message, RoundTripsNoAuthNoPriv) {
  V3Header header;
  header.msgId = 0x1234;
  header.level = SecurityLevel::NoAuthNoPriv;

  net::ErrorCode ec;
  const auto wire = encodeV3Message(header, params(), scopedGet(), AuthProtocol::None, {}, ec);
  ASSERT_FALSE(ec) << ec.message();

  const auto msg = decodeV3Message(wire, ec);
  ASSERT_TRUE(msg) << ec.message();
  EXPECT_EQ(msg->header.msgId, 0x1234);
  EXPECT_EQ(msg->header.maxSize, defaultMaxMessageSize);
  EXPECT_EQ(msg->header.level, SecurityLevel::NoAuthNoPriv);
  EXPECT_TRUE(msg->header.reportable);
  EXPECT_EQ(msg->header.securityModel, securityModelUsm);
  EXPECT_EQ(msg->security.engineId, engineId());
  EXPECT_EQ(msg->security.boots, 7);
  EXPECT_EQ(msg->security.time, 12345);
  EXPECT_EQ(msg->security.userName, "bert");
  EXPECT_TRUE(msg->security.authParams.empty());
  EXPECT_EQ(msg->scoped.contextEngineId, engineId());
  EXPECT_EQ(msg->scoped.pdu.type, PduType::Get);
  EXPECT_EQ(msg->scoped.pdu.requestId, 0x2a);
  EXPECT_EQ(msg->scoped.pdu.varbinds, scopedGet().pdu.varbinds);
}

TEST(V3Message, ReportableFlagRidesInMsgFlags) {
  V3Header header;
  header.reportable = false;
  net::ErrorCode ec;
  const auto wire = encodeV3Message(header, params(), scopedGet(), AuthProtocol::None, {}, ec);
  const auto msg = decodeV3Message(wire, ec);
  ASSERT_TRUE(msg) << ec.message();
  EXPECT_FALSE(msg->header.reportable);
}

// The whole point of the layer: every protocol's digest has to land in the right place with the
// right width, and has to verify against a message that was never touched.
TEST(V3Message, AuthenticatesAndVerifiesUnderEveryProtocol) {
  for (const auto protocol : {AuthProtocol::Md5, AuthProtocol::Sha1, AuthProtocol::Sha224,
                              AuthProtocol::Sha256, AuthProtocol::Sha384, AuthProtocol::Sha512}) {
    const auto key = authKey(protocol);
    V3Header header;
    header.level = SecurityLevel::AuthNoPriv;

    net::ErrorCode ec;
    const auto wire = encodeV3Message(header, params(), scopedGet(), protocol, key, ec);
    ASSERT_FALSE(ec) << ec.message();

    const auto msg = decodeV3Message(wire, ec);
    ASSERT_TRUE(msg) << ec.message();
    EXPECT_EQ(msg->header.level, SecurityLevel::AuthNoPriv);
    EXPECT_EQ(msg->security.authParams.size(), authParamsSize(protocol));
    EXPECT_TRUE(verifyAuth(wire, *msg, protocol, key, ec)) << ec.message();
    EXPECT_FALSE(ec) << ec.message();
  }
}

TEST(V3Message, RejectsATamperedMessage) {
  const auto key = authKey(AuthProtocol::Sha256);
  V3Header header;
  header.level = SecurityLevel::AuthNoPriv;

  net::ErrorCode ec;
  auto wire = encodeV3Message(header, params(), scopedGet(), AuthProtocol::Sha256, key, ec);
  ASSERT_FALSE(ec) << ec.message();

  // Flip a bit in the request-id, which lives in the ScopedPDU, well away from the digest.
  wire[wire.size() - 20] ^= std::byte{0x01};
  const auto msg = decodeV3Message(wire, ec);
  ASSERT_TRUE(msg) << ec.message();
  EXPECT_FALSE(verifyAuth(wire, *msg, AuthProtocol::Sha256, key, ec));
  EXPECT_EQ(ec, make_error_code(Errc::AuthFailed));
}

TEST(V3Message, RejectsTheWrongKey) {
  const auto key = authKey(AuthProtocol::Sha1);
  V3Header header;
  header.level = SecurityLevel::AuthNoPriv;

  net::ErrorCode ec;
  const auto wire = encodeV3Message(header, params(), scopedGet(), AuthProtocol::Sha1, key, ec);
  const auto msg = decodeV3Message(wire, ec);
  ASSERT_TRUE(msg) << ec.message();

  auto wrong = key;
  wrong.front() ^= std::byte{0xff};
  EXPECT_FALSE(verifyAuth(wire, *msg, AuthProtocol::Sha1, wrong, ec));
  EXPECT_EQ(ec, make_error_code(Errc::AuthFailed));
}

// A long user name pushes msgSecurityParameters past 127 Octets, which widens two length fields
// and moves the digest. If the offset were computed by assuming short-form lengths, this is the
// test that would catch it.
TEST(V3Message, PlacesTheDigestCorrectlyUnderLongFormLengths) {
  const auto key = authKey(AuthProtocol::Sha512);
  auto usm = params();
  usm.userName = std::string(200, 'u');

  V3Header header;
  header.level = SecurityLevel::AuthNoPriv;

  net::ErrorCode ec;
  const auto wire = encodeV3Message(header, usm, scopedGet(), AuthProtocol::Sha512, key, ec);
  ASSERT_FALSE(ec) << ec.message();

  const auto msg = decodeV3Message(wire, ec);
  ASSERT_TRUE(msg) << ec.message();
  EXPECT_EQ(msg->security.userName, usm.userName);
  EXPECT_TRUE(verifyAuth(wire, *msg, AuthProtocol::Sha512, key, ec)) << ec.message();
}

TEST(V3Message, AVerifiedMessageIsNotSelfAuthenticating) {
  // An unauthenticated message must never verify, whatever key it is offered: otherwise stripping
  // the auth flag would strip the authentication.
  V3Header header;
  header.level = SecurityLevel::NoAuthNoPriv;
  net::ErrorCode ec;
  const auto wire = encodeV3Message(header, params(), scopedGet(), AuthProtocol::None, {}, ec);
  const auto msg = decodeV3Message(wire, ec);
  ASSERT_TRUE(msg) << ec.message();
  EXPECT_FALSE(verifyAuth(wire, *msg, AuthProtocol::Sha256, authKey(AuthProtocol::Sha256), ec));
  EXPECT_EQ(ec, make_error_code(Errc::AuthFailed));
}

// A message may not claim privacy it has no protocol to provide: sending it in the clear under a
// flag saying otherwise is worse than not sending it.
TEST(V3Message, RefusesToClaimPrivacyWithoutAProtocol) {
  V3Header header;
  header.level = SecurityLevel::AuthPriv;
  net::ErrorCode ec;
  EXPECT_TRUE(encodeV3Message(header, params(), scopedGet(), AuthProtocol::Sha256, {}, ec).empty());
  EXPECT_EQ(ec, make_error_code(Errc::UnsupportedPrivProtocol));
}

TEST(V3Message, RefusesToAuthenticateWithoutAProtocol) {
  V3Header header;
  header.level = SecurityLevel::AuthNoPriv;
  net::ErrorCode ec;
  EXPECT_TRUE(encodeV3Message(header, params(), scopedGet(), AuthProtocol::None, {}, ec).empty());
  EXPECT_EQ(ec, make_error_code(Errc::UnsupportedAuthProtocol));
}

// Everything below is a misbehaving Agent's message, which is the half of the decoder that a
// correct Target will never exercise.
TEST(V3Message, RejectsAnotherVersion) {
  net::ErrorCode ec;
  const V3Header header;
  auto wire = encodeV3Message(header, params(), scopedGet(), AuthProtocol::None, {}, ec);
  wire[4] = std::byte{0x01};  // SEQUENCE, length, INTEGER, length, version
  EXPECT_FALSE(decodeV3Message(wire, ec));
  EXPECT_EQ(ec, make_error_code(Errc::BadVersion));
}

TEST(V3Message, RejectsANonUsmSecurityModel) {
  net::ErrorCode ec;
  V3Header header;
  header.securityModel = 2;  // the v2c security model
  const auto wire = encodeV3Message(header, params(), scopedGet(), AuthProtocol::None, {}, ec);
  ASSERT_FALSE(ec) << ec.message();
  EXPECT_FALSE(decodeV3Message(wire, ec));
  EXPECT_EQ(ec, make_error_code(Errc::UnsupportedSecurityModel));
}

TEST(V3Message, RejectsPrivacyWithoutAuthentication) {
  net::ErrorCode ec;
  const V3Header header;
  auto wire = encodeV3Message(header, params(), scopedGet(), AuthProtocol::None, {}, ec);
  // msgFlags as encodeV3Message wrote it: OCTET STRING, one Octet, reportable and nothing else.
  const auto encoded = bytes({0x04, 0x01, 0x04});
  const auto flags = std::ranges::search(wire, encoded).begin();
  ASSERT_NE(flags, wire.end());
  *(flags + 2) = std::byte{0x02};  // priv set, auth clear
  EXPECT_FALSE(decodeV3Message(wire, ec));
  EXPECT_EQ(ec, make_error_code(Errc::BadMessageFlags));
}

// The flag decides which of the two shapes msgData is, so an Agent that claims authPriv and then
// sends a plaintext ScopedPDU is refused rather than read as though it had claimed nothing.
TEST(V3Message, RejectsAClaimOfPrivacyOverAPlaintextScopedPdu) {
  net::ErrorCode ec;
  const V3Header header;
  auto wire = encodeV3Message(header, params(), scopedGet(), AuthProtocol::None, {}, ec);
  const auto encoded = bytes({0x04, 0x01, 0x04});
  const auto flags = std::ranges::search(wire, encoded).begin();
  ASSERT_NE(flags, wire.end());
  *(flags + 2) = std::byte{0x07};  // authPriv, reportable
  EXPECT_FALSE(decodeV3Message(wire, ec));
  EXPECT_EQ(ec, make_error_code(Errc::UnexpectedTag));
}

// RFC 3414 section 2.4 fixes msgSecurityParameters at six fields. Anything after them is an Agent
// inventing structure, and the Reader's Scope has to be allowed to say so.
TEST(V3Message, RejectsTrailingDataInsideTheSecurityParameters) {
  ber::Writer usmContent(64);
  usmContent.octetString(engineId());
  usmContent.integer(0);
  usmContent.integer(0);
  usmContent.octetString("bert");
  usmContent.octetString(Octets{});
  usmContent.octetString(Octets{});
  usmContent.integer(99);  // a seventh field

  ber::Writer usmParams(96);
  usmParams.tlv(ber::tag::sequence, usmContent.bytes());

  ber::Writer body(256);
  body.integer(versionV3);
  {
    auto scope = body.beginSequence();
    body.integer(1);
    body.integer(defaultMaxMessageSize);
    body.octetString(bytes({0x04}));
    body.integer(securityModelUsm);
  }
  body.octetString(usmParams.bytes());
  encodeScopedPdu(body, scopedGet());

  ber::Writer w(320);
  w.tlv(ber::tag::sequence, body.bytes());

  net::ErrorCode ec;
  EXPECT_FALSE(decodeV3Message(w.bytes(), ec));
  EXPECT_EQ(ec, make_error_code(Errc::TrailingData));
}

TEST(V3Message, RejectsAnEncryptedPduTheFlagsDidNotClaim) {
  // msgData as an OCTET STRING is an encryptedPDU, and the flags here say noAuthNoPriv: the
  // mirror of the test above, and the other half of "the flag decides, not the payload".
  ber::Writer body(64);
  body.integer(versionV3);
  {
    auto scope = body.beginSequence();
    body.integer(1);
    body.integer(defaultMaxMessageSize);
    body.octetString(bytes({0x04}));  // reportable, and claiming no privacy
    body.integer(securityModelUsm);
  }
  ber::Writer usmContent(32);
  usmContent.octetString(engineId());
  usmContent.integer(0);
  usmContent.integer(0);
  usmContent.octetString("bert");
  usmContent.octetString(Octets(12, std::byte{0}));
  usmContent.octetString(Octets(8, std::byte{0}));
  ber::Writer usmParams(64);
  usmParams.tlv(ber::tag::sequence, usmContent.bytes());
  body.octetString(usmParams.bytes());
  body.octetString(bytes({0xde, 0xad, 0xbe, 0xef}));

  ber::Writer w(128);
  w.tlv(ber::tag::sequence, body.bytes());

  net::ErrorCode ec;
  EXPECT_FALSE(decodeV3Message(w.bytes(), ec));
  EXPECT_EQ(ec, make_error_code(Errc::UnexpectedTag));
}

TEST(V3Message, RejectsTruncatedInput) {
  net::ErrorCode ec;
  const V3Header header;
  const auto wire = encodeV3Message(header, params(), scopedGet(), AuthProtocol::None, {}, ec);
  for (std::size_t n = 1; n < wire.size(); ++n) {
    const std::span<const std::byte> prefix(wire.data(), n);
    EXPECT_FALSE(decodeV3Message(prefix, ec)) << "prefix of " << n << " Octets decoded";
    EXPECT_TRUE(ec);
  }
}

// ---------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------

Octets privKey(AuthProtocol auth, PrivProtocol priv) {
  net::ErrorCode ec;
  const Credentials creds{"bert", SecurityLevel::AuthPriv, auth, "maplesyrup", priv, "privatepass"};
  auto key = localizedPrivKey(creds, engineId(), ec);
  EXPECT_FALSE(ec) << ec.message();
  return key;
}

TEST(V3Message, RoundTripsAuthPriv) {
  V3Header header;
  header.msgId = 0x4321;
  header.level = SecurityLevel::AuthPriv;
  const auto auth = AuthProtocol::Sha256;
  const auto priv = PrivProtocol::Aes128;

  net::ErrorCode ec;
  const auto wire = encodeV3Message(header, params(), scopedGet(), auth, authKey(auth), ec, priv,
                                    privKey(auth, priv));
  ASSERT_FALSE(ec) << ec.message();

  auto msg = decodeV3Message(wire, ec);
  ASSERT_TRUE(msg) << ec.message();
  EXPECT_EQ(msg->header.level, SecurityLevel::AuthPriv);
  // The decode stops at the ciphertext: the ScopedPDU is not readable until a key turns up.
  EXPECT_FALSE(msg->encryptedPdu.empty());
  EXPECT_TRUE(msg->scoped.pdu.varbinds.empty());
  // The salt the encoder chose travels in the message; it is what the IV is rebuilt from.
  EXPECT_EQ(msg->security.privParams.size(), 8U);

  // The digest covers the finished message, ciphertext included -- verified before anything is
  // decrypted, which is the order RFC 3414 section 3.2 puts them in.
  EXPECT_TRUE(verifyAuth(wire, *msg, auth, authKey(auth), ec)) << ec.message();

  ASSERT_TRUE(decryptScopedPdu(*msg, priv, privKey(auth, priv), ec)) << ec.message();
  EXPECT_EQ(msg->scoped.contextEngineId, engineId());
  EXPECT_EQ(msg->scoped.pdu.type, PduType::Get);
  EXPECT_EQ(msg->scoped.pdu.requestId, 0x2a);
  ASSERT_EQ(msg->scoped.pdu.varbinds.size(), 1U);
  EXPECT_EQ(msg->scoped.pdu.varbinds[0].name, sysUpTime);
}

// DES pads the plaintext to its block size, so the ScopedPDU it decrypts to has trailing Octets
// the decoder has to walk past rather than call trailing data (RFC 3414 section 8.1.1.2).
TEST(V3Message, RoundTripsAuthPrivUnderDesPadding) {
  V3Header header;
  header.level = SecurityLevel::AuthPriv;
  const auto auth = AuthProtocol::Md5;
  const auto priv = PrivProtocol::Des;

  net::ErrorCode ec;
  const auto wire = encodeV3Message(header, params(), scopedGet(), auth, authKey(auth), ec, priv,
                                    privKey(auth, priv));
  ASSERT_FALSE(ec) << ec.message();

  auto msg = decodeV3Message(wire, ec);
  ASSERT_TRUE(msg) << ec.message();
  EXPECT_EQ(msg->encryptedPdu.size() % 8, 0U);
  ASSERT_TRUE(decryptScopedPdu(*msg, priv, privKey(auth, priv), ec)) << ec.message();
  ASSERT_EQ(msg->scoped.pdu.varbinds.size(), 1U);
  EXPECT_EQ(msg->scoped.pdu.varbinds[0].name, sysUpTime);
}

// A wrong key decrypts to noise, and noise is not a ScopedPDU. What matters is that it says so
// rather than naming whichever BER rule the noise happened to break first.
TEST(V3Message, RefusesAnEncryptedPduTheKeyDoesNotOpen) {
  V3Header header;
  header.level = SecurityLevel::AuthPriv;
  const auto auth = AuthProtocol::Sha256;
  const auto priv = PrivProtocol::Aes128;

  net::ErrorCode ec;
  const auto wire = encodeV3Message(header, params(), scopedGet(), auth, authKey(auth), ec, priv,
                                    privKey(auth, priv));
  ASSERT_FALSE(ec) << ec.message();
  auto msg = decodeV3Message(wire, ec);
  ASSERT_TRUE(msg) << ec.message();

  auto wrong = privKey(auth, priv);
  wrong.front() ^= std::byte{0xff};
  EXPECT_FALSE(decryptScopedPdu(*msg, priv, wrong, ec));
  EXPECT_EQ(ec, make_error_code(Errc::DecryptionFailed));
}

// The digest is computed over the message the ciphertext is already in, so flipping a bit of the
// ciphertext has to fail authentication before decryption is ever attempted.
TEST(V3Message, AuthenticationCoversTheCiphertext) {
  V3Header header;
  header.level = SecurityLevel::AuthPriv;
  const auto auth = AuthProtocol::Sha1;
  const auto priv = PrivProtocol::Aes192C;

  net::ErrorCode ec;
  auto wire = encodeV3Message(header, params(), scopedGet(), auth, authKey(auth), ec, priv,
                              privKey(auth, priv));
  ASSERT_FALSE(ec) << ec.message();
  wire.back() ^= std::byte{0x01};

  const auto msg = decodeV3Message(wire, ec);
  ASSERT_TRUE(msg) << ec.message();
  EXPECT_FALSE(verifyAuth(wire, *msg, auth, authKey(auth), ec));
  EXPECT_EQ(ec, make_error_code(Errc::AuthFailed));
}

}  // namespace
}  // namespace snmpio
