#ifndef SNMPIO_DETAIL_HELDCREDENTIALS_HPP
#define SNMPIO_DETAIL_HELDCREDENTIALS_HPP

#include <utility>

#include <snmpio/Usm.hpp>
#include <snmpio/detail/SecretOctets.hpp>

// Not part of the API. Installed only because Client.hpp's private members name it.
namespace snmpio::detail {

// Overwrites a string's or vector's buffer with zeros and leaves it empty. Grown to its capacity
// first, which never reallocates and zeroes the tail, so that what a longer value once held there
// is wiped too -- and, for a short string, the characters a move left behind.
template <typename Buffer>
void wipeBuffer(Buffer& buffer) noexcept {
  // A moved-from buffer is the case this exists for, not a use after move.
  buffer.resize(buffer.capacity());  // NOLINT(clang-analyzer-cplusplus.Move)
  cleanse(buffer.data(), buffer.size() * sizeof(*buffer.data()));
  buffer.clear();
}

// The Credentials' passwords and Master Keys, by wipeBuffer, the keys then reset. Best effort, as
// the threat model says: it reaches this object's storage and nothing it was ever copied from.
inline void wipe(Credentials& creds) noexcept {
  wipeBuffer(creds.authPassword);
  wipeBuffer(creds.privPassword);
  for (auto* key : {&creds.authMasterKey, &creds.privMasterKey}) {
    if (key->has_value()) wipeBuffer(**key);
    key->reset();
  }
}

// A copy of the caller's Credentials that snmpio holds: what a request carries from the call that
// started it down to the coroutines that derive its keys, each of which keeps one in its frame.
// Credentials is the caller's type and its passwords are std::strings, which no allocator of ours
// reaches, so the holder wipes them itself -- when it is destroyed, and when it is moved from,
// since a short string's move copies it and leaves the characters behind in the source.
class HeldCredentials {
 public:
  // Takes the caller's copy, and wipes what the move left in it.
  explicit HeldCredentials(Credentials&& creds) noexcept : m_creds(std::move(creds)) {
    wipe(creds);
  }
  HeldCredentials(const HeldCredentials&) = default;
  HeldCredentials(HeldCredentials&& other) noexcept : m_creds(std::move(other.m_creds)) {
    wipe(other.m_creds);
  }
  HeldCredentials& operator=(const HeldCredentials& other) {
    if (this != &other) {
      wipe(m_creds);
      m_creds = other.m_creds;
    }
    return *this;
  }
  HeldCredentials& operator=(HeldCredentials&& other) noexcept {
    if (this != &other) {
      wipe(m_creds);
      m_creds = std::move(other.m_creds);
      wipe(other.m_creds);
    }
    return *this;
  }
  ~HeldCredentials() { wipe(m_creds); }

  [[nodiscard]] const Credentials& operator*() const noexcept { return m_creds; }
  [[nodiscard]] const Credentials* operator->() const noexcept { return &m_creds; }

 private:
  Credentials m_creds;
};

}  // namespace snmpio::detail

#endif  // SNMPIO_DETAIL_HELDCREDENTIALS_HPP
