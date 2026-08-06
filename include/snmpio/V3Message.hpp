#ifndef SNMPIO_V3MESSAGE_HPP
#define SNMPIO_V3MESSAGE_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <snmpio/Error.hpp>
#include <snmpio/Pdu.hpp>
#include <snmpio/Usm.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/ber/Reader.hpp>
#include <snmpio/ber/Writer.hpp>

namespace snmpio {

// RFC 3411 section 8: SNMPv3 is version 3 on the wire. Unlike v2c's version 1, no off-by-one.
inline constexpr std::int32_t versionV3 = 3;

// RFC 3411 section 5: the User-based Security Model's number. It is the only one we implement,
// and the only one anything deployed uses.
inline constexpr std::int32_t securityModelUsm = 3;

// What we advertise as msgMaxSize: the largest UDP payload that fits in one IPv4 datagram. The
// specification's floor is 484 and its ceiling is 2^31-1; neither is a useful default.
inline constexpr std::int32_t defaultMaxMessageSize = 65507;

// RFC 3412 section 6.4 msgGlobalData.
struct V3Header {
  // The engine-level message identifier, distinct from the PDU's request-id: a message whose
  // decryption fails must still be attributable to the request that sent it (CONTEXT.md).
  std::int32_t msgId = 0;
  std::int32_t maxSize = defaultMaxMessageSize;
  SecurityLevel level = SecurityLevel::NoAuthNoPriv;
  // "Send me a Report rather than silence if you reject this." Set on every request a Command
  // Generator originates, because Reports are how discovery and resynchronisation happen.
  bool reportable = true;
  std::int32_t securityModel = securityModelUsm;
};

// RFC 3414 section 2.4: the USM half of msgSecurityParameters, which travels BER-encoded inside
// an OCTET STRING of the outer message rather than as a field of it.
struct UsmParameters {
  Octets engineId;
  std::int32_t boots = 0;
  std::int32_t time = 0;
  std::string userName;
  // Ignored by encodeV3Message, which computes it: its width is the protocol's, and a digest
  // supplied by a caller could only be a stale one.
  Octets authParams;
  Octets privParams;
};

// A PDU together with the context it is to be interpreted in. The unit privacy encrypts, which is
// why it is a type of its own rather than three more fields of the message.
struct ScopedPdu {
  Octets contextEngineId;
  std::string contextName;
  Pdu pdu;
};

struct V3Message {
  V3Header header;
  UsmParameters security;
  ScopedPdu scoped;
  // Where msgAuthenticationParameters' content begins in the datagram this was decoded from.
  // Authentication is defined over the message with that field blanked (RFC 3414 section 6.3.2),
  // so verifying it needs the position, and finding the position again by re-parsing would be
  // finding it a second time.
  std::size_t authParamsOffset = 0;
};

void encodeScopedPdu(ber::Writer& w, const ScopedPdu& s);
std::optional<ScopedPdu> decodeScopedPdu(ber::Reader& r);

// Encodes a whole message and, if header.level is authenticated, fills in its digest.
//
// authPriv is rejected with Errc::UnsupportedSecurityLevel until privacy arrives in stage 4 --
// an unencrypted message sent under a flag claiming encryption is worse than a refusal.
std::vector<std::byte> encodeV3Message(const V3Header& header, const UsmParameters& usm,
                                       const ScopedPdu& scoped, AuthProtocol auth,
                                       std::span<const std::byte> localizedKey, net::ErrorCode& ec);

std::optional<V3Message> decodeV3Message(std::span<const std::byte> datagram, net::ErrorCode& ec);

// Recomputes the digest over the datagram with msgAuthenticationParameters blanked and compares
// it in constant time. `msg` must be what decodeV3Message returned for this same datagram.
//
// Timeliness -- engine boots, time and the 150-second Time Window -- is deliberately not checked
// here. It needs the Engine's cached boots/time, which is stage 3's.
bool verifyAuth(std::span<const std::byte> datagram, const V3Message& msg, AuthProtocol auth,
                std::span<const std::byte> localizedKey, net::ErrorCode& ec);

}  // namespace snmpio

#endif  // SNMPIO_V3MESSAGE_HPP
