// SNMPv2c GET, in the callback form. Build instructions are in examples/CMakeLists.txt.
//
//   ./example-get 127.0.0.1 161 public
#include <cstdlib>
#include <iostream>
#include <string>

#include <snmpio/Client.hpp>

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "usage: " << argv[0] << " <address> <port> <community>\n";
    return 2;
  }

  namespace net = snmpio::net;
  net::IoContext io;
  snmpio::Client client(io.get_executor());

  // A Target is an address and a port -- no identity, no credentials (CONTEXT.md). An address
  // rather than a hostname: choosing a resolver stays the caller's business.
  snmpio::Target target;
  target.endpoint = {net::asio::ip::make_address(argv[1]),
                     static_cast<std::uint16_t>(std::atoi(argv[2]))};

  const snmpio::Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};
  client.asyncGet(target, snmpio::Community{argv[3]}, {sysDescr},
                  [&client](const net::ErrorCode& ec, const snmpio::Response& response) {
                    // Three categories arrive here: the system's for socket faults, snmpio's for
                    // timeouts and malformed Responses, and snmp-agent's for an error-status the
                    // Agent itself returned. message() reads correctly for all three.
                    // The Client's receive loop is outstanding work, so io.run() returns only
                    // once stop() has closed it. A program with more to do would call stop() when
                    // it is finished with the Client, not after one request.
                    client.stop();
                    if (ec) {
                      std::cerr << "GET failed: " << ec.message() << "\n";
                      return;
                    }
                    // toString needs qualifying: Value is a std::variant, so ADL looks in std.
                    std::cout << snmpio::toString(response.varbinds.front().val) << "\n";
                  });

  io.run();
}
