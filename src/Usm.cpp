#include <snmpio/Usm.hpp>

#include <array>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>

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

}  // namespace

std::size_t keySize(AuthProtocol p) noexcept {
  const auto* md = digestFor(p);
  return md == nullptr ? 0U : static_cast<std::size_t>(EVP_MD_get_size(md));
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
