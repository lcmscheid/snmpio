#ifndef SNMPIO_USM_HPP
#define SNMPIO_USM_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
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

// The User-based Security Model's privacy protocols: RFC 3414's DES, RFC 3826's AES-128, and the
// AES-192/256 pair the Blumenthal and Reeder drafts each extend a short Localized Key for.
//
// ADR-0005: DES is here for the same reason MD5 is. The `C` suffix is Reeder, spelled the way
// net-snmp, gosnmp and the Simulator all spell it. There is no enumerator for "AES-192, extension
// unspecified": the two extensions are mutually incompatible and never inferred (CONTEXT.md), so
// the choice is made where the protocol is named or not at all.
enum class PrivProtocol : std::uint8_t {
  None,
  Des,      // usmDESPrivProtocol
  Aes128,   // usmAesCfb128Protocol
  Aes192,   // Blumenthal key extension
  Aes256,   // Blumenthal key extension
  Aes192C,  // Reeder key extension
  Aes256C,  // Reeder key extension
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

// Octets of key material the cipher takes. DES's 16 is 8 of key and 8 of pre-IV (RFC 3414
// section 8.1.1.1), which is why it is not the 8 the cipher itself uses.
[[nodiscard]] std::size_t privKeySize(PrivProtocol p) noexcept;

// RFC 3414 section 11.2: the shortest password USM accepts. A shorter one -- an empty one
// included -- is refused with Errc::PasswordTooShort, by passwordToKey and by a Client before it
// sends anything. A Master Key supplied in its place is not a password, and is not held to it.
inline constexpr std::size_t minimumPasswordLength = 8;

// The user, the level they authenticate at, and the secrets behind it.
//
// Independent of Target by construction (CONTEXT.md): the same Credentials may be used against
// many Targets. What binds a key to one Engine is localizeKey(), not this type.
//
// Either secret may be given as the Master Key passwordToKey() derives from it, in place of the
// password: derived once, on a thread of the caller's choosing, and handed to every Client, it
// leaves no I/O thread a megabyte to hash and no Client a plaintext password to hold. A Master Key
// must be keySize(authProtocol) Octets -- the privacy one too, since USM derives it under the
// authentication protocol's hash -- and stands *instead of* its password, which is then left
// empty. A Client refuses either mistake with Errc::ArgumentOutOfRange before it sends anything.
struct Credentials {
  std::string userName;
  SecurityLevel level = SecurityLevel::NoAuthNoPriv;
  AuthProtocol authProtocol = AuthProtocol::None;
  std::string authPassword;
  PrivProtocol privProtocol = PrivProtocol::None;
  // USM derives the privacy key with the *authentication* protocol's hash, so there is no second
  // protocol to name here -- only a second secret.
  std::string privPassword;
  // Last, so that a braced initialiser naming the six fields above still means what it did; and
  // initialised, redundantly, because that is what keeps GCC's and Clang's
  // -Wmissing-field-initializers quiet about such an initialiser leaving these two out.
  std::optional<Octets> authMasterKey = std::nullopt;
  std::optional<Octets> privMasterKey = std::nullopt;
};

// RFC 3414 appendix A.2: the password repeated to exactly one megabyte and hashed once, giving
// the Master Key. The megabyte is the point -- it is what makes a dictionary attack against the
// Master Key expensive -- so this is not a function to call on a hot path, nor on an I/O thread:
// call it once per password, where blocking for a few milliseconds is harmless, and hand the
// result to every Client in Credentials::authMasterKey or privMasterKey. A password shorter than
// minimumPasswordLength is refused with Errc::PasswordTooShort.
//
// This and the derivations below copy their result out into Octets, which are the caller's: snmpio
// wipes its own copies of keys (threat model S5), and the caller's are theirs to wipe.
[[nodiscard]] Octets passwordToKey(AuthProtocol p, std::string_view password, net::ErrorCode& ec);

// RFC 3414 section 2.6: hash(masterKey || engineId || masterKey). Binds a Master Key to one
// Authoritative Engine, so a key lifted from one Engine is useless against another. One short
// hash: this is the authentication key's whole per-Engine cost once the Master Key is known.
[[nodiscard]] Octets localizeKey(AuthProtocol p, std::span<const std::byte> masterKey,
                                 std::span<const std::byte> engineId, net::ErrorCode& ec);

// The privacy key for one Engine, from the privacy secret's Master Key: localizeKey under the
// authentication protocol's hash, extended if the privacy protocol needs more key material than
// that hash produces, and truncated to privKeySize(priv).
//
// The extension is the whole of the Blumenthal/Reeder difference. Blumenthal appends the hash of
// the key so far; Reeder appends the key so far run back through password-to-key and localized
// again -- a megabyte per Engine whatever the caller supplied, which is why its caller caches it.
[[nodiscard]] Octets localizedPrivKey(AuthProtocol auth, PrivProtocol priv,
                                      std::span<const std::byte> masterKey,
                                      std::span<const std::byte> engineId, net::ErrorCode& ec);

// The same two keys from Credentials: the Master Key they carry, or else the one their password
// derives to, localized to one Engine. Each derivation from a password is the megabyte hash, and
// is deliberately not cached here, because a cache without an owner is a leak; the Client caches
// per Master Key and engineID.
[[nodiscard]] Octets localizedAuthKey(const Credentials& creds, std::span<const std::byte> engineId,
                                      net::ErrorCode& ec);
[[nodiscard]] Octets localizedPrivKey(const Credentials& creds, std::span<const std::byte> engineId,
                                      net::ErrorCode& ec);

// Encrypts a ScopedPDU and writes the msgPrivacyParameters it chose into `privParams`. The salt is
// this library's to pick -- RFC 3826 section 3.1.2.1 asks only that it never repeat for one key --
// so it is not an argument.
//
// `boots` and `time` are the Authoritative Engine's, and travel in the message: AES puts them in
// the IV, DES uses the boots half in the salt, and both sides therefore derive the same IV from
// what the message already carries.
[[nodiscard]] Octets privEncrypt(PrivProtocol p, std::span<const std::byte> privKey,
                                 std::int32_t boots, std::int32_t time,
                                 std::span<const std::byte> plaintext, Octets& privParams,
                                 net::ErrorCode& ec);

// The inverse. The plaintext keeps whatever padding DES needed: RFC 3414 section 8.1.1.2 leaves
// the pad Octets unspecified, so there is nothing here that could strip them -- the BER decoder
// stops at the end of the ScopedPDU's own SEQUENCE and never looks at them.
[[nodiscard]] Octets privDecrypt(PrivProtocol p, std::span<const std::byte> privKey,
                                 std::int32_t boots, std::int32_t time,
                                 std::span<const std::byte> privParams,
                                 std::span<const std::byte> ciphertext, net::ErrorCode& ec);

// HMAC over a whole message, truncated to authParamsSize(p). The caller is responsible for having
// zeroed msgAuthenticationParameters first: RFC 3414 section 6.3.1 hashes the message with the
// digest field present but blank, which is why the field's width is fixed per protocol.
[[nodiscard]] Octets authDigest(AuthProtocol p, std::span<const std::byte> localizedKey,
                                std::span<const std::byte> message, net::ErrorCode& ec);

}  // namespace snmpio

#endif  // SNMPIO_USM_HPP
