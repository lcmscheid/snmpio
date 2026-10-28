#ifndef SNMPIO_SRC_SECRET_HPP
#define SNMPIO_SRC_SECRET_HPP

#include <cstddef>
#include <optional>
#include <span>
#include <string_view>

#include <snmpio/Error.hpp>
#include <snmpio/SecretOctets.hpp>
#include <snmpio/Usm.hpp>

// Internal to the library, and not installed: what Client.cpp and Usm.cpp share about the
// Credentials' two secrets.
namespace snmpio::detail {

// One of the Credentials' two secrets, with what always travels beside it: the hash it is derived
// under -- the authentication protocol's for both, since USM names no second one -- the privacy
// protocol it is extended for (None for the authentication secret), whether the Security Level
// needs it, the Master Key the Credentials carry for it, if any, and its password. A view: it must
// not outlive the Credentials it was taken from.
class Secret {
 public:
  [[nodiscard]] static Secret auth(const Credentials& creds) noexcept {
    return {creds.authProtocol,           PrivProtocol::None,
            isAuthenticated(creds.level), creds.authProtocol != AuthProtocol::None,
            creds.authMasterKey,          creds.authPassword};
  }
  [[nodiscard]] static Secret priv(const Credentials& creds) noexcept {
    return {creds.authProtocol,       creds.privProtocol,
            isEncrypted(creds.level), creds.privProtocol != PrivProtocol::None,
            creds.privMasterKey,      creds.privPassword};
  }
  // A view of a temporary would dangle as soon as the expression ended.
  static Secret auth(const Credentials&&) = delete;
  static Secret priv(const Credentials&&) = delete;

  [[nodiscard]] AuthProtocol authProtocol() const noexcept { return m_authProtocol; }
  [[nodiscard]] PrivProtocol privProtocol() const noexcept { return m_privProtocol; }
  // The Master Key the caller supplied, or nullptr when the password has to be derived.
  [[nodiscard]] const SecretOctets* suppliedMasterKey() const noexcept {
    return m_masterKey->has_value() ? &**m_masterKey : nullptr;
  }
  [[nodiscard]] std::string_view password() const noexcept { return m_password->view(); }

  // The Security Level calls for this secret, but the Credentials name no protocol to use it with:
  // refused for the missing protocol, which is the mistake, before anything is sent.
  [[nodiscard]] bool protocolMissing() const noexcept { return m_levelNeedsIt && !m_protocolNamed; }

  // A supplied Master Key is the width of the hash, and stands in place of the password rather
  // than beside it. A secret with no Master Key has nothing to check.
  [[nodiscard]] bool inRange() const noexcept {
    const SecretOctets* key = suppliedMasterKey();
    return key == nullptr || (key->size() == keySize(m_authProtocol) && m_password->empty());
  }

  // RFC 3414 section 11.2's minimumPasswordLength, for a secret given as a password. Checked where
  // the Security Level uses it -- where empty is too short as well -- and wherever one is given at
  // all, as inRange checks a Master Key the level does not use. A level that needs a protocol the
  // Credentials do not name does not use the password, so an empty one passes here and
  // protocolMissing is the mistake reported later; a short one given anyway is refused here, as
  // any short password given is. A supplied Master Key has no password.
  [[nodiscard]] bool passwordLongEnough() const noexcept {
    if (suppliedMasterKey() != nullptr) return true;
    if (m_password->empty()) return !(m_levelNeedsIt && m_protocolNamed);
    return m_password->size() >= minimumPasswordLength;
  }

 private:
  Secret(AuthProtocol authProtocol, PrivProtocol privProtocol, bool levelNeedsIt,
         bool protocolNamed, const std::optional<SecretOctets>& masterKey,
         const Password& password) noexcept
      : m_authProtocol(authProtocol),
        m_privProtocol(privProtocol),
        m_levelNeedsIt(levelNeedsIt),
        m_protocolNamed(protocolNamed),
        m_masterKey(&masterKey),
        m_password(&password) {}

  AuthProtocol m_authProtocol;
  PrivProtocol m_privProtocol;
  bool m_levelNeedsIt;
  bool m_protocolNamed;
  const std::optional<SecretOctets>* m_masterKey;
  const Password* m_password;
};

// Why these Credentials will not do, before anything is sent: ArgumentOutOfRange for a Master Key
// that could never be right, then PasswordTooShort for a password RFC 3414 forbids. Both secrets
// are checked whatever the Security Level -- an unused one that is wrong is still a mistake in the
// Credentials, refused here rather than when the level is raised.
[[nodiscard]] inline std::optional<Errc> credentialsFault(const Credentials& creds) noexcept {
  const auto auth = Secret::auth(creds);
  const auto priv = Secret::priv(creds);
  if (!auth.inRange() || !priv.inRange()) return Errc::ArgumentOutOfRange;
  if (!auth.passwordLongEnough() || !priv.passwordLongEnough()) return Errc::PasswordTooShort;
  return std::nullopt;
}

// The Localized Key for one secret: localizeKey for the authentication secret, localizedPrivKey
// for the privacy one, from the Master Key handed in.
[[nodiscard]] SecretOctets localizedKeyFor(const Secret& secret,
                                           std::span<const std::byte> masterKey,
                                           std::span<const std::byte> engineId, net::ErrorCode& ec);

// Key material for passwordDigest from OpenSSL's CSPRNG (ADR-0001). CryptoFailure if it has none
// to give.
[[nodiscard]] SecretOctets randomDigestKey(net::ErrorCode& ec);

// HMAC-SHA-256 of a password under a key, at the hash's full 32 Octets: what a cache may hold in
// place of the password itself (threat model S4).
[[nodiscard]] SecretOctets passwordDigest(std::span<const std::byte> key, std::string_view password,
                                          net::ErrorCode& ec);

}  // namespace snmpio::detail

#endif  // SNMPIO_SRC_SECRET_HPP
