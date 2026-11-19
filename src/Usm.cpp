#include <snmpio/Usm.hpp>

#include "Algorithms.hpp"
#include "OpenSsl.hpp"
#include "Secret.hpp"

#include <snmpio/SecretOctets.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

namespace snmpio {
namespace {

// RFC 3414 appendix A.2.1: the password is repeated into exactly one megabyte, which is then
// hashed once. The RFC's listing feeds it 64 Octets at a time; the digest is of the whole
// megabyte, so how much goes in per call is otherwise free, and 16,384 calls into EVP cost about
// 3.6 times what the hash itself does (research note section 5.4). Each call here is fed the same
// buffer of the password repeated a whole number of times, so every one begins where the password
// does. Written from the RFC, not ported from anyone -- hence no NOTICE entry (ADR-0007).
constexpr std::size_t expandedPasswordSize = 1048576;
constexpr std::size_t targetRepeatedSize = 16384;

// Everything snmpio knows about one authentication protocol, in one row: OpenSSL's name for its
// hash, where its fetched algorithms are held (authAlgorithms), the hash's width -- a Master or
// Localized Key's -- and the width its HMAC is truncated to in msgAuthenticationParameters.
struct AuthSpec {
  const char* digestName = nullptr;
  std::size_t slot = 0;
  std::size_t keySize = 0;
  std::size_t paramsSize = 0;
};

constexpr AuthSpec authSpec(AuthProtocol p) noexcept {
  switch (p) {
    case AuthProtocol::None:
      return {};
    // RFC 3414 sections 6.3.1 and 7.3.1: both of the original protocols truncate to 96 bits.
    case AuthProtocol::Md5:
      return {.digestName = "MD5", .slot = 0, .keySize = 16, .paramsSize = 12};
    case AuthProtocol::Sha1:
      return {.digestName = "SHA1", .slot = 1, .keySize = 20, .paramsSize = 12};
    // RFC 7860 section 4.2 picks a width per hash, and they are not the hashes' own widths --
    // the protocol names carry the number of bits: HMAC-128-SHA-224, HMAC-192-SHA-256, and so on.
    case AuthProtocol::Sha224:
      return {.digestName = "SHA2-224", .slot = 2, .keySize = 28, .paramsSize = 16};
    case AuthProtocol::Sha256:
      return {.digestName = "SHA2-256", .slot = 3, .keySize = 32, .paramsSize = 24};
    case AuthProtocol::Sha384:
      return {.digestName = "SHA2-384", .slot = 4, .keySize = 48, .paramsSize = 32};
    case AuthProtocol::Sha512:
      return {.digestName = "SHA2-512", .slot = 5, .keySize = 64, .paramsSize = 48};
  }
  return {};
}

// The same for a privacy protocol: OpenSSL's name for its cipher, where the fetched cipher is held
// (cipherFor), the key it asks for, and whether the cipher lives in OpenSSL's legacy provider.
// Blumenthal and Reeder share a row's cipher, held once, and differ only in how its key is
// extended.
struct PrivSpec {
  const char* cipherName = nullptr;
  std::size_t slot = 0;
  std::size_t keySize = 0;
  bool legacy = false;
};

constexpr PrivSpec privSpec(PrivProtocol p) noexcept {
  switch (p) {
    case PrivProtocol::None:
      return {};
    // RFC 3414 section 8.1.1.1: 8 Octets of DES key and 8 more of pre-IV, both cut from the same
    // 16 -- which is why DES asks for twice the key its cipher takes.
    case PrivProtocol::Des:
      return {.cipherName = "DES-CBC", .slot = 0, .keySize = 16, .legacy = true};
    // "AES-128-CFB" is CFB-128 in OpenSSL's spelling -- the feedback width RFC 3826 section 3.1.1
    // requires, and the one the -CFB1 and -CFB8 names exist to distinguish themselves from.
    case PrivProtocol::Aes128:
      return {.cipherName = "AES-128-CFB", .slot = 0, .keySize = 16};
    case PrivProtocol::Aes192:
    case PrivProtocol::Aes192C:
      return {.cipherName = "AES-192-CFB", .slot = 1, .keySize = 24};
    case PrivProtocol::Aes256:
    case PrivProtocol::Aes256C:
      return {.cipherName = "AES-256-CFB", .slot = 2, .keySize = 32};
  }
  return {};
}

constexpr std::size_t authSlots = 6;
constexpr std::size_t aesSlots = 3;

// What a cipher that will not fetch is reported as: DES that will not come out of the legacy
// provider, loaded or not, names the provider, as ADR-0005 asks of its absence; any other cipher
// is OpenSSL refusing.
constexpr Errc unfetchedCipherError(const PrivSpec& spec) noexcept {
  return spec.legacy ? Errc::LegacyProviderUnavailable : Errc::CryptoFailure;
}

using detail::CipherPtr;
using detail::DigestPtr;
using MacContextPtr = detail::OpenSslPtr<EVP_MAC_CTX, EVP_MAC_CTX_free>;
using ProviderPtr = detail::OpenSslPtr<OSSL_PROVIDER, OSSL_PROVIDER_unload>;
// Each is one HMAC's, hash's or cipher pass's own, and freeing it wipes the key schedule it holds.
using DigestContext = detail::OpenSslPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
using CipherContext = detail::OpenSslPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;

// HMAC under one digest, keyless: a template each HMAC duplicates and keys. Setting the digest is
// what fetches it, and HMAC() fetched it again on every call, so it is set here once; a duplicate
// shares the fetched digest, and keying it fetches nothing. Many threads duplicate one template at
// once, which only reads it -- EVP_MAC_CTX_dup takes it const, and HMAC's dupctx copies it and
// takes atomic references -- and "Objects are thread-safe as long as the API's being invoked don't
// modify the object" (openssl-threads(7)).
MacContextPtr hmacTemplate(const char* digestName) noexcept {
  const detail::OpenSslPtr<EVP_MAC, EVP_MAC_free> mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
  MacContextPtr ctx(mac ? EVP_MAC_CTX_new(mac.get()) : nullptr);  // keeps its own reference
  // OSSL_PARAM's constructors take char* for every string, though one being set is only read; a
  // copy gives it one without casting the constness off the name. The names are AuthSpec's, the
  // longest eight characters.
  std::array<char, 16> name{};
  const std::string_view given(digestName);
  if (!ctx || given.size() >= name.size()) return nullptr;
  std::ranges::copy(given, name.begin());
  std::array<OSSL_PARAM, 2> params = {
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, name.data(), 0),
      OSSL_PARAM_construct_end()};
  if (EVP_MAC_CTX_set_params(ctx.get(), params.data()) != 1) return nullptr;
  return ctx;
}

// What one authentication protocol needs from OpenSSL: its hash, and HMAC under it.
struct AuthAlgorithms {
  DigestPtr digest;
  MacContextPtr hmac;

  explicit operator bool() const noexcept { return digest && hmac; }
};

// Each protocol's, fetched the first time it is asked for and held once that succeeds; nullptr
// for None, and while its fetch fails.
const AuthAlgorithms* authAlgorithms(AuthProtocol p) noexcept {
  const AuthSpec spec = authSpec(p);
  const char* name = spec.digestName;
  if (name == nullptr) return nullptr;
  static std::array<detail::FetchOnce<AuthAlgorithms>, authSlots> held;
  return held.at(spec.slot).get([name] {
    return AuthAlgorithms{.digest = DigestPtr(EVP_MD_fetch(nullptr, name, nullptr)),
                          .hmac = hmacTemplate(name)};
  });
}

// p's hash, or nullptr with ec set to UnsupportedAuthProtocol, which Error.hpp gives both to no
// protocol at all and to one the local OpenSSL will not provide -- a FIPS build has no MD5.
const EVP_MD* digestFor(AuthProtocol p, net::ErrorCode& ec) noexcept {
  const auto* algorithms = authAlgorithms(p);
  if (algorithms == nullptr) {
    ec = make_error_code(Errc::UnsupportedAuthProtocol);
    return nullptr;
  }
  return algorithms->digest.get();
}

// DES-CBC and the providers it comes from, which come and go together. DES lives in OpenSSL 3.x's
// legacy provider, which is not loaded by default (ADR-0005). Loading any provider explicitly stops
// the default one from being activated implicitly, so both are loaded or the very next SHA-256
// would fail. Never loaded by a build or a Client that only speaks AES; a Client loads it as a DES
// request is initiated, on the caller's thread (detail::fetchAlgorithms), not on its strand
// mid-request. The members go in reverse, so the cipher is freed before either provider is
// unloaded, and they are unloaded rather than left to the process: a provider left loaded is a
// leak every sanitizer reports, and refusing to tidy up after ourselves in a library is not a
// decision a library gets to make.
struct LegacyDes {
  ProviderPtr legacy;
  ProviderPtr defaultProvider;
  CipherPtr cipher;

  explicit operator bool() const noexcept { return legacy && defaultProvider && cipher; }
};

// Each protocol's cipher, fetched the first time it is asked for and held once that succeeds;
// nullptr for None, and while its fetch fails -- for DES, while the legacy provider will not load
// or will not give DES-CBC.
const EVP_CIPHER* cipherFor(PrivProtocol p) noexcept {
  const PrivSpec spec = privSpec(p);
  if (spec.cipherName == nullptr) return nullptr;
  if (spec.legacy) {
    static detail::FetchOnce<LegacyDes> des;
    const LegacyDes* held = des.get([name = spec.cipherName] {
      // Activates the default provider as OpenSSL's fallback first, if nothing has yet. Otherwise
      // the legacy load would be the process's first activation, which turns the fallback off for
      // good, and an attempt that then failed and unloaded what it loaded would leave the process
      // with no provider at all. With it, unloading puts things back as they were. That
      // OSSL_PROVIDER_available activates the fallback first is OpenSSL's code rather than its
      // manual; Algorithms.AFetchThatFailsIsTriedAgainNotHeld fails without it.
      std::ignore = OSSL_PROVIDER_available(nullptr, "default");
      LegacyDes loaded{.legacy = ProviderPtr(OSSL_PROVIDER_load(nullptr, "legacy")),
                       .defaultProvider = ProviderPtr(OSSL_PROVIDER_load(nullptr, "default")),
                       .cipher = nullptr};
      if (loaded.legacy && loaded.defaultProvider) {
        loaded.cipher.reset(EVP_CIPHER_fetch(nullptr, name, nullptr));
      }
      return loaded;  // a failure unloads whatever did load on its way out
    });
    return held == nullptr ? nullptr : held->cipher.get();
  }
  static std::array<detail::FetchOnce<CipherPtr>, aesSlots> aes;
  return detail::rawOrNull(aes.at(spec.slot).get(
      [name = spec.cipherName] { return CipherPtr(EVP_CIPHER_fetch(nullptr, name, nullptr)); }));
}

bool begin(const DigestContext& ctx, const EVP_MD* md, net::ErrorCode& ec) {
  if (ctx.get() == nullptr || EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
    ec = make_error_code(Errc::CryptoFailure);
    return false;
  }
  return true;
}

// A stack array of key material for OpenSSL to write into, wiped however its scope is left -- an
// error return included -- as SecretOctets is wherever it goes.
template <std::size_t N>
class WipedStackArray {
 public:
  WipedStackArray() noexcept = default;
  ~WipedStackArray() { detail::cleanse(m_bytes.data(), m_bytes.size()); }

  WipedStackArray(const WipedStackArray&) = delete;
  WipedStackArray& operator=(const WipedStackArray&) = delete;
  WipedStackArray(WipedStackArray&&) = delete;
  WipedStackArray& operator=(WipedStackArray&&) = delete;

  [[nodiscard]] unsigned char* data() noexcept { return m_bytes.data(); }
  [[nodiscard]] constexpr std::size_t size() const noexcept { return N; }
  // The first n bytes, copied out into storage that wipes itself in turn.
  [[nodiscard]] SecretOctets first(std::size_t n) const {
    const auto* begin = reinterpret_cast<const std::byte*>(m_bytes.data());
    return {begin, begin + n};
  }

 private:
  std::array<unsigned char, N> m_bytes{};
};

// Every digest finished here is key material -- a Master Key, a Localized Key, or a Key Extension
// round -- so the stack array it lands in is wiped.
SecretOctets finish(const DigestContext& ctx, net::ErrorCode& ec) {
  WipedStackArray<EVP_MAX_MD_SIZE> out;
  unsigned int len = 0;
  if (EVP_DigestFinal_ex(ctx.get(), out.data(), &len) != 1) {
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  ec = {};
  return out.first(len);
}

// An HMAC under p's hash at its full width; callers truncate where the protocol says to. Held as
// a secret, and its stack array wiped, because one caller's is: passwordDigest's stands in for a
// password.
SecretOctets hmacOf(AuthProtocol p, std::span<const std::byte> key,
                    std::span<const std::byte> message, net::ErrorCode& ec) {
  const auto* algorithms = authAlgorithms(p);
  if (algorithms == nullptr) {  // as digestFor reports it
    ec = make_error_code(Errc::UnsupportedAuthProtocol);
    return {};
  }
  const MacContextPtr ctx(EVP_MAC_CTX_dup(algorithms->hmac.get()));
  WipedStackArray<EVP_MAX_MD_SIZE> mac;
  std::size_t len = 0;
  // A null key means "keep the last one" to EVP_MAC_init, and a duplicate of the template has none,
  // so an empty key -- whose data() may be null -- is pointed somewhere, as HMAC() used to.
  static constexpr unsigned char emptyKey = 0;
  const auto* keyBytes =
      key.empty() ? &emptyKey : reinterpret_cast<const unsigned char*>(key.data());
  if (ctx.get() == nullptr || EVP_MAC_init(ctx.get(), keyBytes, key.size(), nullptr) != 1 ||
      EVP_MAC_update(ctx.get(), reinterpret_cast<const unsigned char*>(message.data()),
                     message.size()) != 1 ||
      EVP_MAC_final(ctx.get(), mac.data(), &len, mac.size()) != 1) {
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  ec = {};
  return mac.first(len);
}

// The protocol's own hash over one buffer. Blumenthal's extension is the only caller: every other
// hash in USM is either an HMAC or the three-part localization.
SecretOctets hashOf(AuthProtocol p, std::span<const std::byte> in, net::ErrorCode& ec) {
  const auto* md = digestFor(p, ec);
  if (md == nullptr) return {};
  const DigestContext ctx(EVP_MD_CTX_new());
  if (!begin(ctx, md, ec)) return {};
  if (EVP_DigestUpdate(ctx.get(), in.data(), in.size()) != 1) {
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  return finish(ctx, ec);
}

// RFC 3826 section 3.1.2.1: the salt has only to be unique for the lifetime of one key. A counter
// started somewhere unpredictable is the cheapest thing that is, and being shared between Clients
// only means it is skipped forward, never repeated.
std::uint64_t nextSalt() noexcept {
  static std::atomic<std::uint64_t> counter{[] {
    std::random_device rd;
    return (static_cast<std::uint64_t>(rd()) << 32U) ^ rd();
  }()};
  return counter.fetch_add(1, std::memory_order_relaxed);
}

void putBigEndian32(std::span<std::byte> out, std::uint32_t v) noexcept {
  for (std::size_t i = 0; i < 4; ++i) {
    out[i] = static_cast<std::byte>((v >> (8U * (3U - i))) & 0xFFU);
  }
}

// DES needs 8 Octets of key and 8 of pre-IV; every AES protocol needs its whole key and no pre-IV.
constexpr std::size_t desKeySize = 8;
constexpr std::size_t desBlockSize = 8;
constexpr std::size_t saltSize = 8;
constexpr std::size_t aesIvSize = 16;

// RFC 3414 section 8.1.1.1 for DES, RFC 3826 section 3.1.2.1 for AES: the IV either side derives
// from what the message carries, so this is the same function on both. DES's is the key's pre-IV
// under a salt the message carries, and as secret as the key it is cut from. AES's is not secret --
// boots, time and salt all travel in the clear -- but one return type for both costs only a wipe.
SecretOctets makeIv(PrivProtocol p, std::span<const std::byte> privKey, std::int32_t boots,
                    std::int32_t time, std::span<const std::byte> privParams) {
  if (p == PrivProtocol::Des) {
    SecretOctets iv(desBlockSize);
    for (std::size_t i = 0; i < desBlockSize; ++i) {
      iv[i] = privKey[desKeySize + i] ^ privParams[i];
    }
    return iv;
  }
  SecretOctets iv(aesIvSize);
  putBigEndian32(iv, static_cast<std::uint32_t>(boots));
  putBigEndian32(std::span(iv).subspan(4), static_cast<std::uint32_t>(time));
  std::ranges::copy(privParams, iv.begin() + 8);
  return iv;
}

// One EVP pass, whichever direction. CFB is a stream mode and DES-CBC is fed whole blocks, so
// there is never a partial block for the final call to flush -- and OpenSSL's own padding is off,
// because RFC 3414 section 8.1.1.2's pad is not PKCS#7 and must not be stripped on the way back.
Octets crypt(PrivProtocol p, std::span<const std::byte> privKey, std::span<const std::byte> iv,
             std::span<const std::byte> in, bool encrypt, net::ErrorCode& ec) {
  const EVP_CIPHER* cipher = cipherFor(p);
  if (cipher == nullptr) {
    ec = make_error_code(unfetchedCipherError(privSpec(p)));
    return {};
  }
  const CipherContext ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr ||
      EVP_CipherInit_ex(ctx.get(), cipher, nullptr,
                        reinterpret_cast<const unsigned char*>(privKey.data()),
                        reinterpret_cast<const unsigned char*>(iv.data()), encrypt ? 1 : 0) != 1 ||
      EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) {
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  Octets out(in.size());
  int written = 0;
  if (!in.empty() && EVP_CipherUpdate(ctx.get(), reinterpret_cast<unsigned char*>(out.data()),
                                      &written, reinterpret_cast<const unsigned char*>(in.data()),
                                      static_cast<int>(in.size())) != 1) {
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  int tail = 0;
  if (EVP_CipherFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(out.data()) + written,
                         &tail) != 1) {
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  out.resize(static_cast<std::size_t>(written) + static_cast<std::size_t>(tail));
  ec = {};
  return out;
}

}  // namespace

std::size_t keySize(AuthProtocol p) noexcept {
  return authSpec(p).keySize;
}

std::size_t privKeySize(PrivProtocol p) noexcept {
  return privSpec(p).keySize;
}

std::size_t authParamsSize(AuthProtocol p) noexcept {
  return authSpec(p).paramsSize;
}

SecretOctets passwordToKey(AuthProtocol p, std::string_view password, net::ErrorCode& ec) {
  const auto* md = digestFor(p, ec);
  if (md == nullptr) return {};
  // RFC 3414 section 11.2. It also keeps the expansion below, which indexes the password modulo
  // its length, away from an empty one.
  if (password.size() < minimumPasswordLength) {
    ec = make_error_code(Errc::PasswordTooShort);
    return {};
  }

  // A password longer than the target is repeated once. Reserved whole, so the buffer full of the
  // password is one allocation, which the allocator wipes on its way out.
  const std::size_t repeatedSize =
      std::max<std::size_t>(1, targetRepeatedSize / password.size()) * password.size();
  const auto passwordBytes = std::as_bytes(std::span(password));
  SecretOctets repeated;
  repeated.reserve(repeatedSize);
  while (repeated.size() < repeatedSize)
    repeated.insert(repeated.end(), passwordBytes.begin(), passwordBytes.end());

  const DigestContext ctx(EVP_MD_CTX_new());
  bool hashed = begin(ctx, md, ec);
  for (std::size_t done = 0; hashed && done < expandedPasswordSize; done += repeatedSize) {
    hashed = EVP_DigestUpdate(ctx.get(), repeated.data(),
                              std::min(repeatedSize, expandedPasswordSize - done)) == 1;
  }
  if (!hashed) {
    if (!ec) ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  return finish(ctx, ec);
}

SecretOctets localizeKey(AuthProtocol p, std::span<const std::byte> masterKey,
                         std::span<const std::byte> engineId, net::ErrorCode& ec) {
  const auto* md = digestFor(p, ec);
  if (md == nullptr) return {};

  const DigestContext ctx(EVP_MD_CTX_new());
  if (!begin(ctx, md, ec)) return {};

  // RFC 3414 section 2.6: the key surrounds the engineID rather than merely preceding it, so
  // that knowing a localized key reveals nothing about the master key on either side.
  const std::array<std::span<const std::byte>, 3> parts = {masterKey, engineId, masterKey};
  for (const auto& part : parts) {
    if (EVP_DigestUpdate(ctx.get(), part.data(), part.size()) != 1) {
      ec = make_error_code(Errc::CryptoFailure);
      return {};
    }
  }
  return finish(ctx, ec);
}

SecretOctets localizedPrivKey(AuthProtocol auth, PrivProtocol priv,
                              std::span<const std::byte> masterKey,
                              std::span<const std::byte> engineId, net::ErrorCode& ec) {
  const auto want = privKeySize(priv);
  if (want == 0) {
    ec = make_error_code(Errc::UnsupportedPrivProtocol);
    return {};
  }
  // The privacy key is derived under the *authentication* protocol's hash -- USM has no second
  // hash to name (RFC 3414 section 2.6).
  auto key = localizeKey(auth, masterKey, engineId, ec);
  if (ec) return {};

  const bool reeder = priv == PrivProtocol::Aes192C || priv == PrivProtocol::Aes256C;
  // Neither extension is standardised and the two are mutually incompatible (ADR-0005), so which
  // one runs is read off the protocol the caller named and never inferred from anything else.
  while (key.size() < want) {
    SecretOctets more;
    if (reeder) {
      // draft-reeder-snmpv3-usm-3desede: the key so far is fed back in as a *password*, so each
      // round costs another megabyte expansion. Nothing here caches; Client does.
      const std::string_view asPassword(reinterpret_cast<const char*>(key.data()), key.size());
      const auto next = passwordToKey(auth, asPassword, ec);
      if (ec) return {};
      more = localizeKey(auth, next, engineId, ec);
    } else {
      // draft-blumenthal-aes-usm-04 section 3.1.2.1: Kul = Kul || H(Kul), until it is long enough.
      more = hashOf(auth, key, ec);
    }
    if (ec) return {};
    if (more.empty()) {  // unreachable: every protocol with a key size has a hash behind it
      ec = make_error_code(Errc::CryptoFailure);
      return {};
    }
    key.insert(key.end(), more.begin(), more.end());
  }
  key.resize(want);
  ec = {};
  return key;
}

SecretOctets detail::localizedKeyFor(const detail::Secret& secret,
                                     std::span<const std::byte> masterKey,
                                     std::span<const std::byte> engineId, net::ErrorCode& ec) {
  if (secret.privProtocol() == PrivProtocol::None) {
    return localizeKey(secret.authProtocol(), masterKey, engineId, ec);
  }
  return localizedPrivKey(secret.authProtocol(), secret.privProtocol(), masterKey, engineId, ec);
}

namespace {

// The Localized Key for one secret of Credentials, from the Master Key they carry or the one its
// password derives to, uncached. Client::Impl::masterKey and localizedKey take the same two steps
// with a cache in between; they share localizedKeyFor, but not this, because the cache is the
// difference (Usm.hpp says why it is the Client's and not this file's).
SecretOctets localizedFromCredentials(const detail::Secret& secret,
                                      std::span<const std::byte> engineId, net::ErrorCode& ec) {
  if (const SecretOctets* supplied = secret.suppliedMasterKey()) {
    return detail::localizedKeyFor(secret, *supplied, engineId, ec);
  }
  const auto master = passwordToKey(secret.authProtocol(), secret.password(), ec);
  if (ec) return {};
  return detail::localizedKeyFor(secret, master, engineId, ec);
}

}  // namespace

SecretOctets localizedAuthKey(const Credentials& creds, std::span<const std::byte> engineId,
                              net::ErrorCode& ec) {
  return localizedFromCredentials(detail::Secret::auth(creds), engineId, ec);
}

SecretOctets localizedPrivKey(const Credentials& creds, std::span<const std::byte> engineId,
                              net::ErrorCode& ec) {
  // The span overload asks this too, but only after the Master Key it is handed: asked here
  // first, no privacy protocol fails at once rather than after a megabyte hash of the password.
  if (privKeySize(creds.privProtocol) == 0) {
    ec = make_error_code(Errc::UnsupportedPrivProtocol);
    return {};
  }
  return localizedFromCredentials(detail::Secret::priv(creds), engineId, ec);
}

void detail::cleanse(void* p, std::size_t n) noexcept {
  OPENSSL_cleanse(p, n);
}

SecretOctets detail::randomDigestKey(net::ErrorCode& ec) {
  constexpr std::size_t keyOctets = 32;  // SHA-256's block is 64; its output width is plenty
  WipedStackArray<keyOctets> key;
  detail::primeRandom();
  if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  ec = {};
  return key.first(key.size());
}

SecretOctets detail::passwordDigest(std::span<const std::byte> key, std::string_view password,
                                    net::ErrorCode& ec) {
  return hmacOf(AuthProtocol::Sha256, key, std::as_bytes(std::span(password)), ec);
}

std::optional<Errc> detail::fetchAlgorithms(const Credentials& creds) noexcept {
  // A protocol of None where the Security Level needs one is authFault's to refuse, before this.
  if (!isAuthenticated(creds.level)) return std::nullopt;
  // An auth algorithm that will not fetch is UnsupportedAuthProtocol, as Error.hpp defines it.
  if (authSpec(creds.authProtocol).digestName != nullptr &&
      authAlgorithms(creds.authProtocol) == nullptr) {
    return Errc::UnsupportedAuthProtocol;
  }
  const bool encrypted = isEncrypted(creds.level);
  // A password's Master Key is cached under its passwordDigest, which is HMAC-SHA-256 whatever
  // the protocol; Credentials carrying only Master Keys never take it.
  const bool carriesPassword = !creds.authMasterKey || (encrypted && !creds.privMasterKey);
  if (carriesPassword && authAlgorithms(AuthProtocol::Sha256) == nullptr) {
    return Errc::UnsupportedAuthProtocol;
  }
  const PrivSpec priv = privSpec(creds.privProtocol);
  if (encrypted && priv.cipherName != nullptr && cipherFor(creds.privProtocol) == nullptr) {
    return unfetchedCipherError(priv);
  }
  return std::nullopt;
}

Octets privEncrypt(PrivProtocol p, std::span<const std::byte> privKey, std::int32_t boots,
                   std::int32_t time, std::span<const std::byte> plaintext, Octets& privParams,
                   net::ErrorCode& ec) {
  if (privKeySize(p) == 0 || privKey.size() < privKeySize(p)) {
    ec = make_error_code(Errc::UnsupportedPrivProtocol);
    return {};
  }
  const auto salt = nextSalt();
  privParams.assign(saltSize, std::byte{0});
  if (p == PrivProtocol::Des) {
    // RFC 3414 section 8.1.1.1: the salt is the boots count and a local counter, so that two
    // Engines' salts cannot collide even if the counters do.
    putBigEndian32(privParams, static_cast<std::uint32_t>(boots));
    putBigEndian32(std::span(privParams).subspan(4), static_cast<std::uint32_t>(salt));
  } else {
    putBigEndian32(privParams, static_cast<std::uint32_t>(salt >> 32U));
    putBigEndian32(std::span(privParams).subspan(4), static_cast<std::uint32_t>(salt));
  }

  const auto iv = makeIv(p, privKey, boots, time, privParams);
  if (p != PrivProtocol::Des) return crypt(p, privKey, iv, plaintext, true, ec);

  // RFC 3414 section 8.1.1.2: CBC needs whole blocks and the pad is not read back, so what it is
  // filled with is unspecified. Zeroes leak nothing that the length has not already leaked.
  Octets padded(plaintext.begin(), plaintext.end());
  padded.resize(padded.size() + ((desBlockSize - (padded.size() % desBlockSize)) % desBlockSize),
                std::byte{0});
  return crypt(p, privKey, iv, padded, true, ec);
}

Octets privDecrypt(PrivProtocol p, std::span<const std::byte> privKey, std::int32_t boots,
                   std::int32_t time, std::span<const std::byte> privParams,
                   std::span<const std::byte> ciphertext, net::ErrorCode& ec) {
  if (privKey.size() < privKeySize(p) || privKeySize(p) == 0) {
    ec = make_error_code(Errc::UnsupportedPrivProtocol);
    return {};
  }
  // Both protocols fix msgPrivacyParameters at 8 Octets, and both derive the IV by indexing it.
  // A short one is a message we cannot open, not a buffer to read off the end of.
  if (privParams.size() != saltSize) {
    ec = make_error_code(Errc::DecryptionFailed);
    return {};
  }
  if (p == PrivProtocol::Des && (ciphertext.empty() || ciphertext.size() % desBlockSize != 0)) {
    ec = make_error_code(Errc::DecryptionFailed);
    return {};
  }
  const auto iv = makeIv(p, privKey, boots, time, privParams);
  return crypt(p, privKey, iv, ciphertext, false, ec);
}

Octets authDigest(AuthProtocol p, std::span<const std::byte> localizedKey,
                  std::span<const std::byte> message, net::ErrorCode& ec) {
  if (authSpec(p).digestName == nullptr) {
    ec = make_error_code(Errc::UnsupportedAuthProtocol);
    return {};
  }

  const auto mac = hmacOf(p, localizedKey, message, ec);
  if (ec) return {};

  const auto width = authParamsSize(p);
  if (width > mac.size()) {  // unreachable unless the tables above disagree with the hash
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  return {mac.begin(), mac.begin() + static_cast<std::ptrdiff_t>(width)};
}

}  // namespace snmpio
