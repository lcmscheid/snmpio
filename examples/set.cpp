// SNMPv3 authPriv SET, in the callback form: writes sysContact.0 under SHA-256 and AES-128.
//
//   ./example-set 127.0.0.1 16161 writer-privsha256aes snmpio-interop "ops@example.net"
//
// Against the interop snmpd, a user that may only read -- privsha256aes, with the same protocols
// -- is refused, and the refusal is printed as the Agent sent it.
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <string>

#include <snmpio/Client.hpp>

int main(int argc, char** argv) {
  if (argc != 6) {
    std::cerr << "usage: " << argv[0] << " <address> <port> <user> <password> <sysContact>\n";
    return 2;
  }

  namespace net = snmpio::net;
  net::IoContext io;
  snmpio::Client client(io.get_executor());

  snmpio::Target target;
  target.endpoint = {net::asio::ip::make_address(argv[1]),
                     static_cast<std::uint16_t>(std::atoi(argv[2]))};

  // Usm.hpp lists the other authentication and privacy protocols. One password drives both keys
  // here, which is a convenience of this example and not of the protocol.
  snmpio::Credentials credentials;
  credentials.userName = argv[3];
  credentials.level = snmpio::SecurityLevel::AuthPriv;
  credentials.authProtocol = snmpio::AuthProtocol::Sha256;
  credentials.authPassword = argv[4];
  credentials.privProtocol = snmpio::PrivProtocol::Aes128;
  credentials.privPassword = argv[4];

  // A SET carries Values, not just names. sysContact is a DisplayString, which is an OCTET STRING
  // on the wire -- Octets, not std::string, since nothing obliges one to be text.
  const std::string contact = argv[5];
  snmpio::Octets octets;
  for (const char c : contact) octets.push_back(static_cast<std::byte>(c));
  const snmpio::Varbind sysContact{snmpio::Oid{1, 3, 6, 1, 2, 1, 1, 4, 0}, octets};

  int status = 0;
  client.asyncSet(
      target, credentials, {sysContact},
      [&client, &status](const net::ErrorCode& ec, const snmpio::Response& response) {
        client.stop();
        if (!ec) {
          std::cout << "sysContact.0 = " << snmpio::toString(response.varbinds.front().val) << "\n";
          return;
        }
        status = 1;
        // A refusal is the Agent answering: its error-status arrives in its own category, and
        // errorIndex names the Varbind it objected to, counting from 1. Anything else -- a
        // timeout, a socket fault, wrong Credentials -- means no answer about the SET at all, and
        // errorIndex is zero.
        if (ec.category() == snmpio::agentErrorCategory()) {
          std::cerr << "SET refused: " << ec.message() << " (error-status " << ec.value()
                    << "), error-index " << response.errorIndex << "\n";
          return;
        }
        std::cerr << "SET failed: " << ec.message() << "\n";
      });

  io.run();
  return status;
}
