#ifndef SNMPIO_SRC_SECRET_HPP
#define SNMPIO_SRC_SECRET_HPP

#include <cstddef>
#include <optional>
#include <span>
#include <string_view>

#include <snmpio/Usm.hpp>

// Internal to the library, and not installed: what Client.cpp and Usm.cpp share about the
// Credentials' two secrets.
namespace snmpio::detail {

// One of the Credentials' two secrets, as the three things that always travel together: the hash
// it is derived under -- the authentication protocol's for both, since USM names no second one --
// the Master Key the Credentials carry for it, if any, and its password. A view: it must not
// outlive the Credentials it was taken from.
class Secret {
 public:
  [[nodiscard]] static Secret auth(const Credentials& creds) noexcept {
    return {creds.authProtocol, creds.authMasterKey, creds.authPassword};
  }
  [[nodiscard]] static Secret priv(const Credentials& creds) noexcept {
    return {creds.authProtocol, creds.privMasterKey, creds.privPassword};
  }
  // A view of a temporary would dangle as soon as the expression ended.
  static Secret auth(const Credentials&&) = delete;
  static Secret priv(const Credentials&&) = delete;

  [[nodiscard]] AuthProtocol authProtocol() const noexcept { return m_authProtocol; }
  // The Master Key the caller supplied, or nullptr when the password has to be derived.
  [[nodiscard]] const Octets* suppliedMasterKey() const noexcept {
    return m_masterKey->has_value() ? &**m_masterKey : nullptr;
  }
  [[nodiscard]] std::string_view password() const noexcept { return m_password; }

  // A supplied Master Key is the width of the hash, and stands in place of the password rather
  // than beside it. A secret with no Master Key has nothing to check.
  [[nodiscard]] bool inRange() const noexcept {
    const Octets* key = suppliedMasterKey();
    return key == nullptr || (key->size() == keySize(m_authProtocol) && m_password.empty());
  }

 private:
  Secret(AuthProtocol authProtocol, const std::optional<Octets>& masterKey,
         std::string_view password) noexcept
      : m_authProtocol(authProtocol), m_masterKey(&masterKey), m_password(password) {}

  AuthProtocol m_authProtocol;
  const std::optional<Octets>* m_masterKey;
  std::string_view m_password;
};

// Key material for passwordDigest from OpenSSL's CSPRNG (ADR-0001). CryptoFailure if it has none
// to give.
[[nodiscard]] Octets randomDigestKey(net::ErrorCode& ec);

// HMAC-SHA-256 of a password under a key, at the hash's full 32 Octets: what a cache may hold in
// place of the password itself (threat model S4).
[[nodiscard]] Octets passwordDigest(std::span<const std::byte> key, std::string_view password,
                                    net::ErrorCode& ec);

}  // namespace snmpio::detail

#endif  // SNMPIO_SRC_SECRET_HPP
