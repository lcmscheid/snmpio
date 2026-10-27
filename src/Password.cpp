#include <snmpio/Password.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace snmpio {

Password::Password(const std::string& value) : m_value(value) {}

// noexcept although wipeBuffer resizes: it grows the string only to its own capacity, which never
// allocates, so it cannot throw.
Password::Password(std::string&& value) noexcept : m_value(std::move(value)) {
  detail::wipeBuffer(value);  // NOLINT(bugprone-use-after-move): what the move left behind
}

Password::Password(const char* value) : m_value(value) {}

Password::Password(std::string_view value) : m_value(value) {}

Password::Password(const Password& other) = default;

Password::Password(Password&& other) noexcept : m_value(std::move(other.m_value)) {
  detail::wipeBuffer(other.m_value);
}

// Through a temporary, which a self-assignment survives too: the copy is made before anything
// is wiped.
Password& Password::operator=(const Password& other) {
  *this = Password(other);
  return *this;
}

Password& Password::operator=(Password&& other) noexcept {
  if (this != &other) {
    detail::wipeBuffer(m_value);
    m_value = std::move(other.m_value);
    detail::wipeBuffer(other.m_value);
  }
  return *this;
}

Password::~Password() {
  detail::wipeBuffer(m_value);
}

void Password::clear() noexcept {
  detail::wipeBuffer(m_value);
}

}  // namespace snmpio
