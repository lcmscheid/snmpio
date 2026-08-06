#include <snmpio/Usm.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <random>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/provider.h>

namespace snmpio {
namespace {

// RFC 3414 appendix A.2.1: the password is repeated into exactly one megabyte, which is then
// hashed once. Fed 64 Octets at a time to stay line-for-line comparable with the C listing in
// appendix A.2.1 itself; the digest is of the whole megabyte, so the chunk size is otherwise
// free. Written from the RFC, not ported from anyone -- hence no NOTICE entry (ADR-0007).
constexpr std::size_t expandedPasswordSize = 1048576;
constexpr std::size_t chunkSize = 64;

const EVP_MD* digestFor(AuthProtocol p) noexcept {
  switch (p) {
    case AuthProtocol::None:
      return nullptr;
    case AuthProtocol::Md5:
      return EVP_md5();
    case AuthProtocol::Sha1:
      return EVP_sha1();
    case AuthProtocol::Sha224:
      return EVP_sha224();
    case AuthProtocol::Sha256:
      return EVP_sha256();
    case AuthProtocol::Sha384:
      return EVP_sha384();
    case AuthProtocol::Sha512:
      return EVP_sha512();
  }
  return nullptr;
}

// EVP_MD_CTX is a C handle with a free function; this is the whole reason to own it.
class DigestContext {
 public:
  DigestContext() noexcept : m_ctx(EVP_MD_CTX_new()) {}
  ~DigestContext() { EVP_MD_CTX_free(m_ctx); }

  DigestContext(const DigestContext&) = delete;
  DigestContext& operator=(const DigestContext&) = delete;
  DigestContext(DigestContext&&) = delete;
  DigestContext& operator=(DigestContext&&) = delete;

  [[nodiscard]] EVP_MD_CTX* get() const noexcept { return m_ctx; }

 private:
  EVP_MD_CTX* m_ctx;
};

bool begin(const DigestContext& ctx, const EVP_MD* md, net::ErrorCode& ec) {
  if (ctx.get() == nullptr || EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
    ec = make_error_code(Errc::CryptoFailure);
    return false;
  }
  return true;
}

Octets finish(const DigestContext& ctx, net::ErrorCode& ec) {
  std::array<unsigned char, EVP_MAX_MD_SIZE> out{};
  unsigned int len = 0;
  if (EVP_DigestFinal_ex(ctx.get(), out.data(), &len) != 1) {
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  ec = {};
  return Octets(reinterpret_cast<const std::byte*>(out.data()),
                reinterpret_cast<const std::byte*>(out.data()) + len);
}

// The protocol's own hash over one buffer. Blumenthal's extension is the only caller: every other
// hash in USM is either an HMAC or the three-part localization.
Octets hashOf(AuthProtocol p, std::span<const std::byte> in, net::ErrorCode& ec) {
  const auto* md = digestFor(p);
  if (md == nullptr) {
    ec = make_error_code(Errc::UnsupportedAuthProtocol);
    return {};
  }
  const DigestContext ctx;
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

// DES lives in OpenSSL 3.x's legacy provider, which is not loaded by default (ADR-0005). Loading
// any provider explicitly stops the default one from being activated implicitly, so both are
// loaded here or the very next SHA-256 would fail. Lazy, and never on the path of a build or a
// Client that only ever speaks AES.
class LegacyProvider {
 public:
  LegacyProvider() noexcept
      : m_legacy(OSSL_PROVIDER_load(nullptr, "legacy")),
        m_default(OSSL_PROVIDER_load(nullptr, "default")) {}
  // Unloaded rather than left to the process: this balances exactly the two loads above and
  // nothing outlives it, since every EVP handle is fetched and freed inside one call. A provider
  // left loaded is a leak every sanitizer reports, and refusing to tidy up after ourselves in a
  // library is not a decision a library gets to make.
  ~LegacyProvider() {
    if (m_default != nullptr) OSSL_PROVIDER_unload(m_default);
    if (m_legacy != nullptr) OSSL_PROVIDER_unload(m_legacy);
  }

  LegacyProvider(const LegacyProvider&) = delete;
  LegacyProvider& operator=(const LegacyProvider&) = delete;
  LegacyProvider(LegacyProvider&&) = delete;
  LegacyProvider& operator=(LegacyProvider&&) = delete;

  [[nodiscard]] bool loaded() const noexcept { return m_legacy != nullptr && m_default != nullptr; }

 private:
  OSSL_PROVIDER* m_legacy;
  OSSL_PROVIDER* m_default;
};

bool ensureLegacyProvider() {
  static const LegacyProvider provider;
  return provider.loaded();
}

// The OpenSSL name of the cipher, or nullptr for a protocol that has none.
const char* cipherName(PrivProtocol p) noexcept {
  switch (p) {
    case PrivProtocol::None:
      return nullptr;
    case PrivProtocol::Des:
      return "DES-CBC";
    case PrivProtocol::Aes128:
      return "AES-128-CFB";
    case PrivProtocol::Aes192:
    case PrivProtocol::Aes192C:
      return "AES-192-CFB";
    case PrivProtocol::Aes256:
    case PrivProtocol::Aes256C:
      return "AES-256-CFB";
  }
  return nullptr;
}

// "AES-128-CFB" is CFB-128 in OpenSSL's spelling -- the feedback width RFC 3826 section 3.1.1
// requires, and the one the -CFB1 and -CFB8 names exist to distinguish themselves from.
class Cipher {
 public:
  explicit Cipher(PrivProtocol p) : m_cipher(EVP_CIPHER_fetch(nullptr, cipherName(p), nullptr)) {}
  ~Cipher() { EVP_CIPHER_free(m_cipher); }

  Cipher(const Cipher&) = delete;
  Cipher& operator=(const Cipher&) = delete;
  Cipher(Cipher&&) = delete;
  Cipher& operator=(Cipher&&) = delete;

  [[nodiscard]] const EVP_CIPHER* get() const noexcept { return m_cipher; }

 private:
  EVP_CIPHER* m_cipher;
};

class CipherContext {
 public:
  CipherContext() noexcept : m_ctx(EVP_CIPHER_CTX_new()) {}
  ~CipherContext() { EVP_CIPHER_CTX_free(m_ctx); }

  CipherContext(const CipherContext&) = delete;
  CipherContext& operator=(const CipherContext&) = delete;
  CipherContext(CipherContext&&) = delete;
  CipherContext& operator=(CipherContext&&) = delete;

  [[nodiscard]] EVP_CIPHER_CTX* get() const noexcept { return m_ctx; }

 private:
  EVP_CIPHER_CTX* m_ctx;
};

// DES needs 8 Octets of key and 8 of pre-IV; every AES protocol needs its whole key and no pre-IV.
constexpr std::size_t desKeySize = 8;
constexpr std::size_t desBlockSize = 8;
constexpr std::size_t saltSize = 8;
constexpr std::size_t aesIvSize = 16;

// RFC 3414 section 8.1.1.1 for DES, RFC 3826 section 3.1.2.1 for AES: the IV either side derives
// from what the message carries, so this is the same function on both.
Octets makeIv(PrivProtocol p, std::span<const std::byte> privKey, std::int32_t boots,
              std::int32_t time, std::span<const std::byte> privParams) {
  if (p == PrivProtocol::Des) {
    Octets iv(desBlockSize);
    for (std::size_t i = 0; i < desBlockSize; ++i) {
      iv[i] = privKey[desKeySize + i] ^ privParams[i];
    }
    return iv;
  }
  Octets iv(aesIvSize);
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
  if (p == PrivProtocol::Des && !ensureLegacyProvider()) {
    ec = make_error_code(Errc::LegacyProviderUnavailable);
    return {};
  }
  const Cipher cipher(p);
  if (cipher.get() == nullptr) {
    ec = make_error_code(p == PrivProtocol::Des ? Errc::LegacyProviderUnavailable
                                                : Errc::CryptoFailure);
    return {};
  }
  const CipherContext ctx;
  if (ctx.get() == nullptr ||
      EVP_CipherInit_ex(ctx.get(), cipher.get(), nullptr,
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
  const auto* md = digestFor(p);
  return md == nullptr ? 0U : static_cast<std::size_t>(EVP_MD_get_size(md));
}

std::size_t privKeySize(PrivProtocol p) noexcept {
  switch (p) {
    case PrivProtocol::None:
      return 0;
    // RFC 3414 section 8.1.1.1: 8 Octets of DES key and 8 more of pre-IV, both cut from the same
    // 16 -- which is why DES asks for twice the key its cipher takes.
    case PrivProtocol::Des:
    case PrivProtocol::Aes128:
      return 16;
    case PrivProtocol::Aes192:
    case PrivProtocol::Aes192C:
      return 24;
    case PrivProtocol::Aes256:
    case PrivProtocol::Aes256C:
      return 32;
  }
  return 0;
}

std::size_t authParamsSize(AuthProtocol p) noexcept {
  switch (p) {
    case AuthProtocol::None:
      return 0;
    // RFC 3414 sections 6.3.1 and 7.3.1: both of the original protocols truncate to 96 bits.
    case AuthProtocol::Md5:
    case AuthProtocol::Sha1:
      return 12;
    // RFC 7860 section 4.2 picks a width per hash, and they are not the hashes' own widths --
    // the protocol names carry the number of bits: HMAC-128-SHA-224, HMAC-192-SHA-256, and so on.
    case AuthProtocol::Sha224:
      return 16;
    case AuthProtocol::Sha256:
      return 24;
    case AuthProtocol::Sha384:
      return 32;
    case AuthProtocol::Sha512:
      return 48;
  }
  return 0;
}

Octets passwordToKey(AuthProtocol p, std::string_view password, net::ErrorCode& ec) {
  const auto* md = digestFor(p);
  if (md == nullptr) {
    ec = make_error_code(Errc::UnsupportedAuthProtocol);
    return {};
  }
  // Not a policy choice about password strength -- the expansion below indexes the password
  // modulo its length, and an empty one has no length to work with.
  if (password.empty()) {
    ec = make_error_code(Errc::EmptyPassword);
    return {};
  }

  const DigestContext ctx;
  if (!begin(ctx, md, ec)) return {};

  std::array<unsigned char, chunkSize> chunk{};
  std::size_t index = 0;
  for (std::size_t done = 0; done < expandedPasswordSize; done += chunkSize) {
    for (auto& octet : chunk) {
      octet = static_cast<unsigned char>(password[index % password.size()]);
      ++index;
    }
    if (EVP_DigestUpdate(ctx.get(), chunk.data(), chunk.size()) != 1) {
      ec = make_error_code(Errc::CryptoFailure);
      return {};
    }
  }
  return finish(ctx, ec);
}

Octets localizeKey(AuthProtocol p, std::span<const std::byte> masterKey,
                   std::span<const std::byte> engineId, net::ErrorCode& ec) {
  const auto* md = digestFor(p);
  if (md == nullptr) {
    ec = make_error_code(Errc::UnsupportedAuthProtocol);
    return {};
  }

  const DigestContext ctx;
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

Octets localizedAuthKey(const Credentials& creds, std::span<const std::byte> engineId,
                        net::ErrorCode& ec) {
  const auto master = passwordToKey(creds.authProtocol, creds.authPassword, ec);
  if (ec) return {};
  return localizeKey(creds.authProtocol, master, engineId, ec);
}

Octets localizedPrivKey(const Credentials& creds, std::span<const std::byte> engineId,
                        net::ErrorCode& ec) {
  const auto want = privKeySize(creds.privProtocol);
  if (want == 0) {
    ec = make_error_code(Errc::UnsupportedPrivProtocol);
    return {};
  }
  // The privacy key is derived under the *authentication* protocol's hash -- USM has no second
  // hash to name (RFC 3414 section 2.6).
  const auto master = passwordToKey(creds.authProtocol, creds.privPassword, ec);
  if (ec) return {};
  auto key = localizeKey(creds.authProtocol, master, engineId, ec);
  if (ec) return {};

  const bool reeder =
      creds.privProtocol == PrivProtocol::Aes192C || creds.privProtocol == PrivProtocol::Aes256C;
  // Neither extension is standardised and the two are mutually incompatible (ADR-0005), so which
  // one runs is read off the protocol the caller named and never inferred from anything else.
  while (key.size() < want) {
    Octets more;
    if (reeder) {
      // draft-reeder-snmpv3-usm-3desede: the key so far is fed back in as a *password*, so each
      // round costs another megabyte expansion. Nothing here caches; Client does.
      const std::string_view asPassword(reinterpret_cast<const char*>(key.data()), key.size());
      const auto next = passwordToKey(creds.authProtocol, asPassword, ec);
      if (ec) return {};
      more = localizeKey(creds.authProtocol, next, engineId, ec);
    } else {
      // draft-blumenthal-aes-usm-04 section 3.1.2.1: Kul = Kul || H(Kul), until it is long enough.
      more = hashOf(creds.authProtocol, key, ec);
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
  const auto* md = digestFor(p);
  if (md == nullptr) {
    ec = make_error_code(Errc::UnsupportedAuthProtocol);
    return {};
  }

  std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
  unsigned int len = 0;
  if (HMAC(md, localizedKey.data(), static_cast<int>(localizedKey.size()),
           reinterpret_cast<const unsigned char*>(message.data()), message.size(), mac.data(),
           &len) == nullptr) {
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }

  const auto width = authParamsSize(p);
  if (width > len) {  // unreachable unless the tables above disagree with the hash
    ec = make_error_code(Errc::CryptoFailure);
    return {};
  }
  ec = {};
  const auto* first = reinterpret_cast<const std::byte*>(mac.data());
  return Octets(first, first + width);
}

}  // namespace snmpio
