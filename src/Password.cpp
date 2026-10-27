#include <snmpio/Password.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace snmpio {

Password::Password(const std::string& value) : m_value(value) {}

Password::Password(std::string&& value) noexcept : m_value(std::move(value)) {
  detail::wipeBuffer(value);  // NOLINT(bugprone-use-after-move): what the move left behind
}

Password::Password(const char* value) : m_value(value) {}

Password::Password(std::string_view value) : m_value(value) {}

Password::Password(const Password& other) = default;

Password::Password(Password&& other) noexcept : m_value(std::move(other.m_value)) {
  detail::wipeBuffer(other.m_value);
}

Password& Password::operator=(const Password& other) {
  if (this != &other) *this = Password(other);
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
