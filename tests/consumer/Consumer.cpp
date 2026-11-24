// Run by CI against both a static and a shared install; CMakeLists.txt says what it checks and
// why. Prints each failed check and exits non-zero if there was one.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <span>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/Error.hpp>
#include <snmpio/Pdu.hpp>
#include <snmpio/Usm.hpp>

namespace {

int run() {
  namespace net = snmpio::net;

  int failures = 0;
  const auto check = [&failures](bool ok, const char* what) {
    if (!ok) {
      std::cerr << "failed: " << what << '\n';
      ++failures;
    }
  };

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

  // An ErrorStatus the library makes: an Agent on loopback refuses the one request it gets with
  // commitFailed, and the Client turns that error-status into the completion's ErrorCode.
  net::IoContext io;
  net::UdpSocket agent(io, net::UdpEndpoint(net::asio::ip::make_address("127.0.0.1"), 0));
  std::array<std::byte, 1500> datagram{};
  net::UdpEndpoint peer;
  std::vector<std::byte> reply;
  agent.async_receive_from(
      net::asio::buffer(datagram), peer, [&](const net::ErrorCode& received, std::size_t size) {
        net::ErrorCode codec;
        auto request = received ? std::nullopt
                                : snmpio::decodeV2cMessage(std::span(datagram.data(), size), codec);
        if (!request) return;
        snmpio::Pdu refusal = request->pdu;
        refusal.type = snmpio::PduType::Response;
        refusal.errorStatus = static_cast<std::int32_t>(snmpio::ErrorStatus::CommitFailed);
        refusal.errorIndex = 1;
        reply = snmpio::encodeV2cMessage(request->community, refusal, codec);
        agent.async_send_to(net::asio::buffer(reply), peer,
                            [](const net::ErrorCode&, std::size_t) {});
      });

  snmpio::Client client(io.get_executor());
  snmpio::Target target;
  target.endpoint = agent.local_endpoint();
  net::ErrorCode refused;
  std::int32_t errorIndex = 0;
  client.asyncGet(target, snmpio::Community{"public"}, {snmpio::Oid{1, 3, 6, 1, 2, 1, 1, 1, 0}},
                  [&](const net::ErrorCode& completion, const snmpio::Response& response) {
                    refused = completion;
                    errorIndex = response.errorIndex;
                    client.stop();
                  });
  io.run();
  check(refused == snmpio::ErrorStatus::CommitFailed,
        "the library's ErrorStatus equals the consumer's");
  check(&refused.category() == &snmpio::agentErrorCategory(), "the Agent's code has one category");
  check(errorIndex == 1, "the Response carries the error-index");

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

}  // namespace

// An exception -- Asio's, opening the Agent's socket, or the Client's -- is a failure like any
// other, reported rather than left to std::terminate.
int main() {
  try {
    return run();
  } catch (const std::exception& e) {
    std::cerr << "failed: " << e.what() << '\n';
    return EXIT_FAILURE;
  }
}
