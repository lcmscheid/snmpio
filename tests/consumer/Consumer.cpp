// Run by CI against both a static and a shared install; CMakeLists.txt says what it checks and
// why. Prints each failed check and exits non-zero if there was one.
#include <cstdlib>
#include <iostream>

#include <snmpio/Error.hpp>
#include <snmpio/Pdu.hpp>
#include <snmpio/Usm.hpp>

namespace {

int failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::cerr << "failed: " << what << '\n';
    ++failures;
  }
}

}  // namespace

int main() {
  namespace net = snmpio::net;

  // Made in the library, compared here.
  net::ErrorCode ec;
  {
    // Destroyed here, so its allocator's call to detail::cleanse is compiled in this program.
    const snmpio::SecretOctets key = snmpio::passwordToKey(snmpio::AuthProtocol::Sha1, "short", ec);
    check(key.empty(), "a refused password yields no key");
  }
  check(ec == snmpio::Errc::PasswordTooShort, "the library's Errc equals the consumer's");
  check(&ec.category() == &snmpio::errorCategory(), "Errc has one category");
  check(snmpio::classify(ec) == snmpio::ErrorClass::Configuration,
        "the library classifies its own code");

  // Made here, classified in the library.
  const net::ErrorCode status = snmpio::ErrorStatus::CommitFailed;
  check(&status.category() == &snmpio::agentErrorCategory(), "ErrorStatus has one category");
  check(snmpio::classify(status) == snmpio::ErrorClass::Fatal,
        "the library classifies the consumer's ErrorStatus");
  const net::ErrorCode timeout = snmpio::Errc::Timeout;
  check(snmpio::classify(timeout) == snmpio::ErrorClass::Retriable,
        "the library classifies the consumer's Errc");

  // And a key that is kept and then destroyed here, as a caller caching a Master Key would.
  net::ErrorCode keyEc;
  {
    const snmpio::SecretOctets key =
        snmpio::passwordToKey(snmpio::AuthProtocol::Sha1, "maplesyrup", keyEc);
    check(!keyEc && key.size() == snmpio::keySize(snmpio::AuthProtocol::Sha1),
          "a valid password yields a key");
  }

  if (failures == 0) std::cout << "snmpio-consumer: every check passed\n";
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
