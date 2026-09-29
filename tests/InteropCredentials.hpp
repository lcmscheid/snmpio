#ifndef SNMPIO_TESTS_INTEROPCREDENTIALS_HPP
#define SNMPIO_TESTS_INTEROPCREDENTIALS_HPP

#include <array>
#include <string>
#include <string_view>

#include <snmpio/Usm.hpp>

#include "InteropSummary.hpp"

// The v3 half of the interop suite's vocabulary: which auth and privacy protocols it names, what
// the pairs are called, and the Credentials a pair adds up to. Said once here, so that every v3
// interop test -- the GET matrix, and each operation run over it -- addresses the same users by the
// same names and records them under the same labels.
namespace snmpio::test {

// The users tests/interop/snmpd-conf.sh creates, named after what they carry: `noauth`, `authX`
// per auth protocol, and `privXY` per (auth, privacy) pair. Naming them here is only possible
// because they are ours to create -- so an Agent running someone else's configuration is
// addressed the other way in, by a NamedUser below.
struct AuthRow {
  AuthProtocol protocol;
  const char* name;
};
inline constexpr std::array<AuthRow, 6> authProtocols{{{AuthProtocol::Md5, "md5"},
                                                       {AuthProtocol::Sha1, "sha1"},
                                                       {AuthProtocol::Sha224, "sha224"},
                                                       {AuthProtocol::Sha256, "sha256"},
                                                       {AuthProtocol::Sha384, "sha384"},
                                                       {AuthProtocol::Sha512, "sha512"}}};

// The privacy protocols the matrix crosses with every auth protocol. AES-192/256 are not in it:
// they need a Key Extension, and they have their own rows below.
struct PrivRow {
  PrivProtocol protocol;
  const char* name;
};
inline constexpr std::array<PrivRow, 2> privProtocols{
    {{PrivProtocol::Des, "des"}, {PrivProtocol::Aes128, "aes"}}};

// AES-192/256 under both Key Extensions, which both `snmpd` and the Simulator serve (ADR-0006).
inline constexpr std::array<PrivRow, 4> keyExtensionProtocols{{{PrivProtocol::Aes192, "aes192"},
                                                               {PrivProtocol::Aes256, "aes256"},
                                                               {PrivProtocol::Aes192C, "aes192c"},
                                                               {PrivProtocol::Aes256C, "aes256c"}}};

// Carrying neither, which is a row of the matrix like any other: the unauthenticated user.
inline constexpr AuthRow noAuthRow{AuthProtocol::None, "none"};
inline constexpr PrivRow noPrivRow{PrivProtocol::None, "none"};

// What the tests that want one pair rather than the whole matrix reach for. Named rather than
// indexed off the tables above, so that reordering those cannot silently retarget a test.
inline constexpr AuthRow sha1Row{AuthProtocol::Sha1, "sha1"};
inline constexpr AuthRow sha256Row{AuthProtocol::Sha256, "sha256"};
inline constexpr PrivRow aes128Row{PrivProtocol::Aes128, "aes"};

// SHA-1 is the Key Extension rows' auth protocol, for the reason TestInteropV3.cpp's
// CoversBothKeyExtensions states; the users tests/interop/snmpd-conf.sh creates for them follow.
inline constexpr const AuthRow& keyExtensionAuthRow = sha1Row;

// One (auth, privacy) pair.
struct Pair {
  AuthRow auth;
  PrivRow priv;
};

// One pair per Security Level, on the representative pair (SHA-256, then AES-128): what an
// operation runs over when it is to be proven at every level without crossing the whole matrix.
inline constexpr std::array<Pair, 3> securityLevelPairs{
    {{noAuthRow, noPrivRow}, {sha256Row, noPrivRow}, {sha256Row, aes128Row}}};

// The Security Level a pair adds up to. Said once, because the label, the user name and the
// Credentials all ask the same question of the same pair and must not answer it three ways.
[[nodiscard]] inline SecurityLevel securityLevel(const AuthRow& auth, const PrivRow& priv) {
  if (auth.protocol == AuthProtocol::None) return SecurityLevel::NoAuthNoPriv;
  if (priv.protocol == PrivProtocol::None) return SecurityLevel::AuthNoPriv;
  return SecurityLevel::AuthPriv;
}

// The pair, said the way a failure message wants to read it.
[[nodiscard]] inline std::string pairLabel(const AuthRow& auth, const PrivRow& priv) {
  if (auth.protocol == AuthProtocol::None) return "noAuthNoPriv";
  if (priv.protocol == PrivProtocol::None) return std::string("authNoPriv/") + auth.name;
  return std::string("authPriv/") + auth.name + "/" + priv.name;
}

// The user our own configuration creates for a pair, which is the pair spelled out.
[[nodiscard]] inline std::string conventionalUser(const AuthRow& auth, const PrivRow& priv) {
  if (auth.protocol == AuthProtocol::None) return "noauth";
  if (priv.protocol == PrivProtocol::None) return std::string("auth") + auth.name;
  return std::string("priv") + auth.name + priv.name;
}

[[nodiscard]] inline const AuthRow* findAuth(std::string_view name) {
  if (name == noAuthRow.name) return &noAuthRow;
  for (const auto& row : authProtocols) {
    if (name == row.name) return &row;
  }
  return nullptr;
}

[[nodiscard]] inline const PrivRow* findPriv(std::string_view name) {
  if (name == noPrivRow.name) return &noPrivRow;
  for (const auto& row : privProtocols) {
    if (name == row.name) return &row;
  }
  for (const auto& row : keyExtensionProtocols) {
    if (name == row.name) return &row;
  }
  return nullptr;
}

// A v3 user this suite did not create. A switch on the bench carries whatever user someone set up
// on it years ago, so the run says what that user is called and what it carries, and the tests
// address it instead of the convention. One is enough to be useful -- a Target typically has
// exactly one -- and every test then covers the single pair it can serve and says which pairs it
// could not.
struct NamedUser {
  std::string name;
  AuthRow auth;
  PrivRow priv;
};

// The Credentials to send for one pair: the named user's when there is one, or the conventional
// user that says what it carries. Callers filter first -- a named user serves its own pair and no
// other. Every interop user has the one password, used for both keys.
[[nodiscard]] inline Credentials credentialsFor(const AuthRow& auth, const PrivRow& priv,
                                                const std::string& password,
                                                const NamedUser* named = nullptr) {
  return Credentials{named != nullptr ? named->name : conventionalUser(auth, priv),
                     securityLevel(auth, priv),
                     auth.protocol,
                     auth.protocol == AuthProtocol::None ? std::string() : password,
                     priv.protocol,
                     priv.protocol == PrivProtocol::None ? std::string() : password};
}

// Record that every row of the GET matrix was skipped for the same reason.
inline void recordAuthAndPrivacyMatrixSkipped(const std::string& reason) {
  recordSkip("noAuthNoPriv", reason);
  for (const auto& auth : authProtocols) {
    recordSkip(pairLabel(auth, noPrivRow), reason);
    for (const auto& priv : privProtocols) {
      recordSkip(pairLabel(auth, priv), reason);
    }
  }
}

// Why the Key Extension rows skip when the run does not say the Agent serves them.
inline const std::string keyExtensionsUnset =
    "needs SNMPIO_INTEROP_V3_KEY_EXTENSIONS and an Agent serving AES-192/256";

// Record that all four Key Extension rows were skipped for the same reason.
inline void recordKeyExtensionsSkipped(const std::string& reason, const std::string& prefix = {}) {
  for (const auto& priv : keyExtensionProtocols) {
    recordSkip(prefix + pairLabel(keyExtensionAuthRow, priv), reason);
  }
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_INTEROPCREDENTIALS_HPP
