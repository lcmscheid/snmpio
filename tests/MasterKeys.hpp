#ifndef SNMPIO_TESTS_MASTERKEYS_HPP
#define SNMPIO_TESTS_MASTERKEYS_HPP

#include <gtest/gtest.h>

#include <snmpio/Usm.hpp>

namespace snmpio::test {

// What an integrator hands every Client, as the README's v3 section does: the Credentials with each
// password replaced by the Master Key derived from it, once, on the test's own thread rather than
// on any I/O thread. An Agent given the original Credentials derives its keys independently.
inline Credentials withMasterKeys(Credentials creds) {
  net::ErrorCode ec;
  creds.authMasterKey = passwordToKey(creds.authProtocol, creds.authPassword, ec);
  EXPECT_FALSE(ec) << ec.message();
  creds.authPassword.clear();
  if (creds.privProtocol != PrivProtocol::None) {
    creds.privMasterKey = passwordToKey(creds.authProtocol, creds.privPassword, ec);
    EXPECT_FALSE(ec) << ec.message();
    creds.privPassword.clear();
  }
  return creds;
}

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_MASTERKEYS_HPP
