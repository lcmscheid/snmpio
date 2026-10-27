#ifndef SNMPIO_PASSWORD_HPP
#define SNMPIO_PASSWORD_HPP

#include <cstddef>
#include <string>
#include <string_view>

#include <snmpio/SecretOctets.hpp>

namespace snmpio {

namespace detail {

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

}  // namespace detail

// A USM password that wipes itself when it is done with: destroyed, cleared, assigned over, or
// moved from. Not SecretOctets, because a password is text and a short one lives inside the string
// object rather than in anything an allocator hands out -- and a move copies that one, leaving the
// characters in the source. So the wiping is this class's own, over the string's whole capacity.
//
// Implicit from std::string and from a string literal, so that a Credentials initialiser names a
// password as it always could. Read it through view(); nothing converts it back to a std::string
// implicitly, which would be an unwiped copy.
class Password {
 public:
  Password() noexcept = default;
  // NOLINTBEGIN(cppcoreguidelines-explicit-constructor,misc-explicit-constructor): see above
  Password(const std::string& value);
  // Takes the caller's string, and wipes what the move left in it.
  Password(std::string&& value) noexcept;
  Password(const char* value);
  // NOLINTEND(cppcoreguidelines-explicit-constructor,misc-explicit-constructor)
  explicit Password(std::string_view value);

  // Out of line, as the wiping is: one copy of it in the library rather than one in every
  // coroutine frame that holds Credentials.
  Password(const Password& other);
  Password(Password&& other) noexcept;
  // By way of a copy, so that a copy that throws leaves this password as it was.
  Password& operator=(const Password& other);
  Password& operator=(Password&& other) noexcept;
  ~Password();

  [[nodiscard]] std::string_view view() const noexcept { return m_value; }
  [[nodiscard]] std::size_t size() const noexcept { return m_value.size(); }
  [[nodiscard]] bool empty() const noexcept { return m_value.empty(); }
  void clear() noexcept;

 private:
  std::string m_value;
};

}  // namespace snmpio

#endif  // SNMPIO_PASSWORD_HPP
