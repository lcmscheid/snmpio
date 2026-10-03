// SNMPv3 authNoPriv GETBULK, in the coroutine form: authenticated under SHA-512, not encrypted.
//
//   ./example-getbulk 127.0.0.1 16161 authsha512 snmpio-interop
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>

namespace net = snmpio::net;

net::Awaitable<void> run(snmpio::Client& client, snmpio::Target target,
                         snmpio::Credentials credentials) {
  // GETBULK splits its OIDs in two. The first nonRepeaters each get one successor, as a GETNEXT
  // would; every OID after them gets up to maxRepetitions successors, which is how a table is read
  // a few rows at a time. Here that is sysUpTime once, then four successors each of ifDescr
  // and ifType.
  const std::int32_t nonRepeaters = 1;
  const std::int32_t maxRepetitions = 4;
  std::vector<snmpio::Oid> oids{
      snmpio::Oid{1, 3, 6, 1, 2, 1, 1, 3},        // sysUpTime
      snmpio::Oid{1, 3, 6, 1, 2, 1, 2, 2, 1, 2},  // ifDescr
      snmpio::Oid{1, 3, 6, 1, 2, 1, 2, 2, 1, 3},  // ifType
  };

  net::ErrorCode ec;
  auto response = co_await client.asyncGetBulk(
      std::move(target), std::move(credentials), std::move(oids), nonRepeaters, maxRepetitions,
      net::asio::redirect_error(net::asio::use_awaitable, ec));
  client.stop();

  if (ec) {
    std::cerr << "GETBULK failed: " << ec.message() << "\n";
    co_return;
  }
  // The non-repeaters come first, then the repetitions interleaved row by row: ifDescr.1,
  // ifType.1, ifDescr.2, ifType.2, and so on. Each repetition is a GETNEXT, so it knows nothing of
  // columns: from an Agent with fewer than four interfaces, the later rows run on into ifType and
  // ifMtu. Stopping at the column is the caller's job, and the Walk's (walk.cpp). The Agent may
  // also send fewer rows than asked, to stay under its message size, and past the end of the MIB
  // view each one is EndOfMibView.
  for (const auto& vb : response.varbinds) {
    std::cout << vb.name.toString() << " = " << snmpio::toString(vb.val) << "\n";
  }
}

int main(int argc, char** argv) {
  if (argc != 5) {
    std::cerr << "usage: " << argv[0] << " <address> <port> <user> <password>\n";
    return 2;
  }

  snmpio::Target target;
  target.endpoint = {net::asio::ip::make_address(argv[1]),
                     static_cast<std::uint16_t>(std::atoi(argv[2]))};

  // authNoPriv: the message is signed but travels in the clear, so there is no privacy protocol
  // or password to name. Usm.hpp lists the other authentication protocols.
  snmpio::Credentials credentials;
  credentials.userName = argv[3];
  credentials.level = snmpio::SecurityLevel::AuthNoPriv;
  credentials.authProtocol = snmpio::AuthProtocol::Sha512;
  credentials.authPassword = argv[4];

  net::IoContext io;
  snmpio::Client client(io.get_executor());
  net::asio::co_spawn(io, run(client, target, credentials), net::asio::detached);
  io.run();
}
