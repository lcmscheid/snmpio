#ifndef SNMPIO_USM_HPP
#define SNMPIO_USM_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <snmpio/Error.hpp>
#include <snmpio/Value.hpp>

namespace snmpio {

// The User-based Security Model's authentication protocols: RFC 3414's two, and RFC 7860's four.
//
// ADR-0005: MD5 and SHA-1 are here on purpose. Refusing them does not remove them from the
// network, it only removes us from the devices that require them.
enum class AuthProtocol : std::uint8_t {
  None,
  Md5,     // usmHMACMD5AuthProtocol
  Sha1,    // usmHMACSHA1AuthProtocol
  Sha224,  // usmHMAC128SHA224AuthProtocol
  Sha256,  // usmHMAC192SHA256AuthProtocol
  Sha384,  // usmHMAC256SHA384AuthProtocol
  Sha512,  // usmHMAC384SHA512AuthProtocol
};

// Whether a message is authenticated, and whether it is additionally encrypted.
//
// Valued as the msgFlags bits of RFC 3412 section 6.4 so that encoding is a cast -- the same
// trick PduType plays with its BER tags. There is no value 2: privacy without authentication is
// not a level the security model allows.
enum class SecurityLevel : std::uint8_t {
  NoAuthNoPriv = 0x00,
  AuthNoPriv = 0x01,
  AuthPriv = 0x03,
};

[[nodiscard]] constexpr bool isAuthenticated(SecurityLevel l) noexcept {
  return l != SecurityLevel::NoAuthNoPriv;
}
[[nodiscard]] constexpr bool isEncrypted(SecurityLevel l) noexcept {
  return l == SecurityLevel::AuthPriv;
}

// Octets of key material the protocol's hash produces. Both the Master Key and the Localized Key
// are one full digest wide; only the digest *in the message* is truncated.
[[nodiscard]] std::size_t keySize(AuthProtocol p) noexcept;

// Octets of msgAuthenticationParameters -- the HMAC, truncated. 12 for the RFC 3414 protocols;
// RFC 7860 section 4.2 sets its own width per hash, and the widths are not the hash's own.
[[nodiscard]] std::size_t authParamsSize(AuthProtocol p) noexcept;

// The user, the level they authenticate at, and the secret behind it.
//
// Independent of Target by construction (CONTEXT.md): the same Credentials may be used against
// many Targets. What binds a key to one Engine is localizeKey(), not this type.
struct Credentials {
  std::string userName;
  SecurityLevel level = SecurityLevel::NoAuthNoPriv;
  AuthProtocol authProtocol = AuthProtocol::None;
  std::string authPassword;
};

// RFC 3414 appendix A.2: the password repeated to exactly one megabyte and hashed once. The
// megabyte is the point -- it is what makes a dictionary attack against the Master Key expensive
// -- so this is not a function to call on a hot path.
[[nodiscard]] Octets passwordToKey(AuthProtocol p, std::string_view password, net::ErrorCode& ec);

// RFC 3414 section 2.6: hash(masterKey || engineId || masterKey). Binds a Master Key to one
// Authoritative Engine, so a key lifted from one Engine is useless against another.
[[nodiscard]] Octets localizeKey(AuthProtocol p, std::span<const std::byte> masterKey,
                                 std::span<const std::byte> engineId, net::ErrorCode& ec);

// passwordToKey followed by localizeKey. This is the expensive pair stage 3 will cache per
// (Credentials, engineID); it is deliberately not cached here, because a cache without an owner
// is a leak.
[[nodiscard]] Octets localizedAuthKey(const Credentials& creds, std::span<const std::byte> engineId,
                                      net::ErrorCode& ec);

// HMAC over a whole message, truncated to authParamsSize(p). The caller is responsible for having
// zeroed msgAuthenticationParameters first: RFC 3414 section 6.3.1 hashes the message with the
// digest field present but blank, which is why the field's width is fixed per protocol.
[[nodiscard]] Octets authDigest(AuthProtocol p, std::span<const std::byte> localizedKey,
                                std::span<const std::byte> message, net::ErrorCode& ec);

}  // namespace snmpio

#endif  // SNMPIO_USM_HPP
