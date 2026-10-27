#ifndef SNMPIO_EXAMPLES_ENVIRONMENT_HPP
#define SNMPIO_EXAMPLES_ENVIRONMENT_HPP

#include <cstdlib>

#include <snmpio/Password.hpp>

// Passwords come from the environment, never the command line, where every user on the host can
// read them in ps or /proc and the shell keeps them in its history. Read once, before the
// io_context runs a thread that could race the environment. Unset is empty, which a Client refuses
// with Errc::PasswordTooShort wherever the Security Level needs the password.
inline snmpio::Password passwordFrom(const char* variable) {
  const char* value = std::getenv(variable);
  return value != nullptr ? snmpio::Password(value) : snmpio::Password();
}

#endif  // SNMPIO_EXAMPLES_ENVIRONMENT_HPP
