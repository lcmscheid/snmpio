// SNMPv3 authPriv Walk, in the coroutine form. Engine Discovery and time synchronisation happen
// underneath and are never surfaced -- there is no session to open and nothing to call first.
//
//   ./example-walk-collect 127.0.0.1 16161 privsha1aes 1.3.6.1.2.1.1
//
// with SNMPIO_AUTH_PASSWORD and SNMPIO_PRIV_PASSWORD set in the environment.
#include <cstdlib>
#include <iostream>

#include <snmpio/Client.hpp>

#include "Environment.hpp"

namespace net = snmpio::net;

net::Awaitable<void> run(snmpio::Client& client, snmpio::Target target,
                         snmpio::Credentials credentials, snmpio::Oid base) {
  net::ErrorCode ec;
  // asyncWalkCollect buffers; asyncWalk streams each batch to a handler instead, which is the
  // core and this the convenience (ADR-0004) -- a Walk has no bounded size.
  auto varbinds =
      co_await client.asyncWalkCollect(std::move(target), std::move(credentials), std::move(base),
                                       {}, net::asio::redirect_error(net::asio::use_awaitable, ec));

  // An incomplete Walk still hands back what it collected, alongside Errc::WalkIncomplete.
  if (ec) std::cerr << "walk ended: " << ec.message() << "\n";
  for (const auto& vb : varbinds) {
    std::cout << vb.name.toString() << " = " << snmpio::toString(vb.val) << "\n";
  }

  // The Client's receive loop is outstanding work, so io.run() returns only once stop() has
  // closed it -- not once this coroutine has.
  client.stop();
}

int main(int argc, char** argv) {
  if (argc != 5) {
    std::cerr << "usage: SNMPIO_AUTH_PASSWORD=... SNMPIO_PRIV_PASSWORD=... " << argv[0]
              << " <address> <port> <user> <base-oid>\n";
    return 2;
  }

  snmpio::Target target;
  target.endpoint = {net::asio::ip::make_address(argv[1]),
                     static_cast<std::uint16_t>(std::atoi(argv[2]))};

  // The level is required rather than inferred: a Client that silently downgraded authPriv would
  // be a security hole. Two passwords, one per key, from the environment: USM keeps the secrets
  // separate, and so does this example.
  snmpio::Credentials credentials;
  credentials.userName = argv[3];
  credentials.level = snmpio::SecurityLevel::AuthPriv;
  credentials.authProtocol = snmpio::AuthProtocol::Sha1;
  credentials.authPassword = passwordFrom("SNMPIO_AUTH_PASSWORD");
  credentials.privProtocol = snmpio::PrivProtocol::Aes128;
  credentials.privPassword = passwordFrom("SNMPIO_PRIV_PASSWORD");

  const auto base = snmpio::Oid::parse(argv[4]);
  if (!base) {
    std::cerr << "bad base OID: " << argv[4] << "\n";
    return 2;
  }

  net::IoContext io;
  snmpio::Client client(io.get_executor());
  net::asio::co_spawn(io, run(client, target, credentials, *base), net::asio::detached);
  io.run();
}
