#ifndef SNMPIO_SRC_ALGORITHMS_HPP
#define SNMPIO_SRC_ALGORITHMS_HPP

#include <optional>

#include <snmpio/Error.hpp>
#include <snmpio/Usm.hpp>

namespace snmpio::detail {

// Fetches every OpenSSL algorithm a request under these Credentials will use, each held once it
// has fetched (FetchOnce), and loads the legacy provider if they encrypt with DES (#47). A Client
// calls it as a request is initiated, on the caller's thread, so that neither a fetch nor the
// provider's load from disk happens on its strand mid-request -- and refuses the request with what
// it returns, before anything is sent: LegacyProviderUnavailable for DES that will not load
// (ADR-0005), UnsupportedAuthProtocol for a hash or HMAC, as Error.hpp defines it,
// and CryptoFailure for any other cipher.
[[nodiscard]] std::optional<Errc> fetchAlgorithms(const Credentials& creds) noexcept;

}  // namespace snmpio::detail

#endif  // SNMPIO_SRC_ALGORITHMS_HPP
