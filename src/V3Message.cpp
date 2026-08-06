#include <snmpio/V3Message.hpp>

#include <algorithm>
#include <utility>

#include <openssl/crypto.h>

namespace snmpio {
namespace {

constexpr std::byte reportableFlag{0x04};
constexpr std::byte securityLevelMask{0x03};

// Not a Security Level: privacy without authentication is the one combination the model has no
// meaning for, and it is exactly what a stripped-flags attack would produce.
constexpr std::byte privWithoutAuth{0x02};

std::byte encodeFlags(const V3Header& h) noexcept {
  auto flags = static_cast<std::byte>(h.level);
  if (h.reportable) flags |= reportableFlag;
  return flags;
}

// Returns where the blank digest was written, relative to w.
std::size_t encodeUsmContent(ber::Writer& w, const UsmParameters& usm, std::size_t authWidth,
                             std::span<const std::byte> privParams) {
  w.octetString(usm.engineId);
  w.integer(usm.boots);
  w.integer(usm.time);
  w.octetString(usm.userName);
  // The placeholder the digest is written over once the whole message exists. Its length octet is
  // short-form for certain -- the widest protocol truncates to 48 Octets -- so the content starts
  // two Octets after the tag.
  const Octets blank(authWidth, std::byte{0});
  const auto authOffset = w.size() + 2;
  w.octetString(blank);
  w.octetString(privParams);
  return authOffset;
}

}  // namespace

void encodeScopedPdu(ber::Writer& w, const ScopedPdu& s) {
  auto scope = w.beginSequence();
  w.octetString(s.contextEngineId);
  w.octetString(s.contextName);
  encodePdu(w, s.pdu);
}

std::optional<ScopedPdu> decodeScopedPdu(ber::Reader& r) {
  ScopedPdu s;
  {
    auto scope = r.enter(ber::tag::sequence);
    auto engine = r.octetString();
    auto context = r.octetString();
    if (!engine || !context) return std::nullopt;
    s.contextEngineId = std::move(*engine);
    s.contextName.assign(reinterpret_cast<const char*>(context->data()), context->size());
    auto pdu = decodePdu(r);
    if (!pdu) return std::nullopt;
    s.pdu = std::move(*pdu);
  }
  if (!r.ok()) return std::nullopt;
  return s;
}

std::vector<std::byte> encodeV3Message(const V3Header& header, const UsmParameters& usm,
                                       const ScopedPdu& scoped, AuthProtocol auth,
                                       std::span<const std::byte> localizedKey, net::ErrorCode& ec,
                                       PrivProtocol priv, std::span<const std::byte> privKey) {
  const bool encrypt = isEncrypted(header.level);
  if (encrypt && priv == PrivProtocol::None) {
    ec = make_error_code(Errc::UnsupportedPrivProtocol);
    return {};
  }
  const bool authenticate = isAuthenticated(header.level);
  if (authenticate && auth == AuthProtocol::None) {
    ec = make_error_code(Errc::UnsupportedAuthProtocol);
    return {};
  }
  const auto authWidth = authenticate ? authParamsSize(auth) : 0;

  // Encrypted first: the salt it picks travels in the security parameters, which are encoded
  // below, and the digest is computed over both once everything else is in place.
  ber::Writer scopedContent(128);
  encodeScopedPdu(scopedContent, scoped);
  Octets privParams;
  Octets ciphertext;
  if (encrypt) {
    ciphertext =
        privEncrypt(priv, privKey, usm.boots, usm.time, scopedContent.bytes(), privParams, ec);
    if (ec) return {};
  }

  // Each layer is built into its own buffer and then wrapped, rather than written through nested
  // Writer scopes. A scope patches its length octet in place when it closes, widening it if the
  // content grew past 127 Octets and shifting everything after it -- which would invalidate the
  // digest's offset. Wrapping a finished buffer makes each shift a subtraction we can do here.
  ber::Writer usmContent(64);
  auto authOffset =
      encodeUsmContent(usmContent, usm, authWidth, encrypt ? privParams : usm.privParams);

  ber::Writer usmParams(usmContent.size() + 4);
  usmParams.tlv(ber::tag::sequence, usmContent.bytes());
  authOffset += usmParams.size() - usmContent.size();

  ber::Writer body(256);
  body.integer(versionV3);
  {
    auto scope = body.beginSequence();
    body.integer(header.msgId);
    body.integer(header.maxSize);
    const auto flags = encodeFlags(header);
    body.octetString(std::span(&flags, 1));
    body.integer(header.securityModel);
  }
  body.octetString(usmParams.bytes());
  authOffset += body.size() - usmParams.size();
  // RFC 3412 section 6.8: msgData is either the ScopedPDU itself or an OCTET STRING holding its
  // ciphertext, and the msgFlags the receiver already read say which.
  if (encrypt) {
    body.octetString(ciphertext);
  } else {
    body.raw(scopedContent.bytes());
  }

  ber::Writer w(body.size() + 4);
  w.tlv(ber::tag::sequence, body.bytes());
  authOffset += w.size() - body.size();

  for (const auto& stage :
       {scopedContent.error(), usmContent.error(), usmParams.error(), body.error(), w.error()}) {
    if (stage) {
      ec = stage;
      return {};
    }
  }
  ec = {};
  auto out = w.take();

  if (!authenticate) return out;

  const auto digest = authDigest(auth, localizedKey, out, ec);
  if (ec) return {};
  std::ranges::copy(digest, out.begin() + static_cast<std::ptrdiff_t>(authOffset));
  return out;
}

std::optional<V3Message> decodeV3Message(std::span<const std::byte> datagram, net::ErrorCode& ec) {
  ber::Reader r(datagram);
  V3Message msg;
  {
    auto messageScope = r.enter(ber::tag::sequence);
    const auto version = r.integer();
    if (!version) {
      ec = r.error();
      return std::nullopt;
    }
    if (*version != versionV3) {
      ec = make_error_code(Errc::BadVersion);
      return std::nullopt;
    }

    {
      auto headerScope = r.enter(ber::tag::sequence);
      const auto msgId = r.integer();
      const auto maxSize = r.integer();
      const auto flags = r.octetString();
      const auto model = r.integer();
      if (!msgId || !maxSize || !flags || !model) {
        ec = r.error();
        return std::nullopt;
      }
      // RFC 3412 section 6.4 makes msgFlags exactly one Octet. Reserved bits above the three
      // defined ones carry no meaning, so they are ignored rather than rejected.
      if (flags->size() != 1 || (flags->front() & securityLevelMask) == privWithoutAuth) {
        ec = make_error_code(Errc::BadMessageFlags);
        return std::nullopt;
      }
      msg.header.msgId = *msgId;
      msg.header.maxSize = *maxSize;
      msg.header.level = static_cast<SecurityLevel>(
          std::to_integer<std::uint8_t>(flags->front() & securityLevelMask));
      msg.header.reportable = (flags->front() & reportableFlag) != std::byte{0};
      msg.header.securityModel = *model;
    }
    if (!r.ok()) {
      ec = r.error();
      return std::nullopt;
    }
    if (msg.header.securityModel != securityModelUsm) {
      ec = make_error_code(Errc::UnsupportedSecurityModel);
      return std::nullopt;
    }

    // Borrowed rather than copied, because the digest's offset has to be expressed in the
    // datagram's own coordinates.
    const auto params = r.octetStringView();
    if (!params) {
      ec = r.error();
      return std::nullopt;
    }
    const auto paramsBase = static_cast<std::size_t>(params->data() - datagram.data());
    ber::Reader sub(*params);
    {
      auto usmScope = sub.enter(ber::tag::sequence);
      auto engineId = sub.octetString();
      const auto boots = sub.integer();
      const auto time = sub.integer();
      auto userName = sub.octetString();
      auto authParams = sub.octetString();
      // Captured here, not after the next field: position() is just past what was read, so the
      // digest's start is exact whatever length form encoded it -- where assuming a short-form
      // length octet would not be.
      const auto afterAuthParams = sub.position();
      auto privParams = sub.octetString();
      if (!engineId || !boots || !time || !userName || !authParams || !privParams) {
        ec = sub.error();
        return std::nullopt;
      }
      msg.authParamsOffset = paramsBase + afterAuthParams - authParams->size();
      // RFC 3414 section 2.4 bounds msgUserName at 32 Octets and msgAuthoritativeEngineID at
      // 5..32. Not enforced: an over-long field is unambiguous -- it simply will not match any
      // user or Engine we know -- and rejecting it here would only turn a clear authentication
      // failure into an opaque decode failure.
      msg.security.engineId = std::move(*engineId);
      msg.security.boots = *boots;
      msg.security.time = *time;
      msg.security.userName.assign(reinterpret_cast<const char*>(userName->data()),
                                   userName->size());
      msg.security.authParams = std::move(*authParams);
      msg.security.privParams = std::move(*privParams);
    }
    // After the Scope, not inside it: trailing data is what its destructor reports, and a check
    // written one line earlier would run before the verdict existed. RFC 3414 section 2.4 fixes
    // the six fields, so anything after them is an Agent making things up.
    if (!sub.finish()) {
      ec = sub.error();
      return std::nullopt;
    }

    // RFC 3412 section 6.8: msgData is an encryptedPDU exactly when msgFlags said so. Which of
    // the two it is is read off the flag rather than off the tag, so a message whose flags and
    // payload disagree is refused rather than quietly interpreted the way the payload prefers.
    if (isEncrypted(msg.header.level)) {
      auto encrypted = r.octetString();
      if (!encrypted) {
        ec = r.error();
        return std::nullopt;
      }
      // Left encrypted: opening it needs the privacy key, which belongs to the request this
      // message answers and is not known here. decryptScopedPdu is the second half.
      msg.encryptedPdu = std::move(*encrypted);
    } else {
      auto scoped = decodeScopedPdu(r);
      if (!scoped) {
        ec = r.error();
        return std::nullopt;
      }
      msg.scoped = std::move(*scoped);
    }
  }
  if (!r.finish()) {
    ec = r.error();
    return std::nullopt;
  }
  ec = {};
  return msg;
}

bool decryptScopedPdu(V3Message& msg, PrivProtocol priv, std::span<const std::byte> privKey,
                      net::ErrorCode& ec) {
  const auto plain = privDecrypt(priv, privKey, msg.security.boots, msg.security.time,
                                 msg.security.privParams, msg.encryptedPdu, ec);
  if (ec) return false;

  ber::Reader r(plain);
  auto scoped = decodeScopedPdu(r);
  // Deliberately not r.finish(): DES pads the plaintext to its block size and RFC 3414 section
  // 8.1.1.2 leaves those Octets in place, so trailing bytes here are expected rather than an
  // Agent making things up -- which is the opposite of what they mean in the datagram itself.
  if (!scoped) {
    // A wrong key decrypts to noise, and noise is not a ScopedPDU. Saying "decryption failed"
    // rather than naming whichever BER rule the noise broke first is both truer and less of a
    // hint to whoever is guessing keys.
    ec = make_error_code(Errc::DecryptionFailed);
    return false;
  }
  msg.scoped = std::move(*scoped);
  ec = {};
  return true;
}

bool verifyAuth(std::span<const std::byte> datagram, const V3Message& msg, AuthProtocol auth,
                std::span<const std::byte> localizedKey, net::ErrorCode& ec) {
  if (!isAuthenticated(msg.header.level) ||
      msg.security.authParams.size() != authParamsSize(auth)) {
    ec = make_error_code(Errc::AuthFailed);
    return false;
  }
  if (msg.authParamsOffset + msg.security.authParams.size() > datagram.size()) {
    ec = make_error_code(Errc::AuthFailed);  // not reachable from a decode of this datagram
    return false;
  }

  std::vector<std::byte> blanked(datagram.begin(), datagram.end());
  std::fill_n(blanked.begin() + static_cast<std::ptrdiff_t>(msg.authParamsOffset),
              msg.security.authParams.size(), std::byte{0});

  const auto expected = authDigest(auth, localizedKey, blanked, ec);
  if (ec) return false;

  // Constant-time: a digest comparison that returns early leaks how much of it matched.
  if (expected.size() != msg.security.authParams.size() ||
      CRYPTO_memcmp(expected.data(), msg.security.authParams.data(), expected.size()) != 0) {
    ec = make_error_code(Errc::AuthFailed);
    return false;
  }
  ec = {};
  return true;
}

}  // namespace snmpio
