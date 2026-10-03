// SNMPv3 authPriv Walk, streamed, in the coroutine form: SHA-1, and AES-256 under the Reeder Key
// Extension. Each batch is printed as it arrives and nothing is buffered -- the core form of a
// Walk (ADR-0004), where walk-collect.cpp shows the convenience over it.
//
//   ./example-walk 127.0.0.1 16161 privsha1aes256c snmpio-interop 1.3.6.1.2.1.1 [limit]
//
// With a limit, the Walk is cancelled once that many rows have been printed, and ends in
// Errc::WalkIncomplete -- a Walk stopped early never reports itself as a whole one.
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <span>
#include <string>

#include <snmpio/Client.hpp>

namespace net = snmpio::net;

net::Awaitable<void> run(snmpio::Client& client, snmpio::Target target,
                         snmpio::Credentials credentials, snmpio::Oid base,
                         std::optional<std::size_t> limit) {
  // The default is GETBULK, ten rows a round trip. Zero walks with GETNEXT instead, one row a
  // round trip: slower, and what a Target that mishandles GETBULK needs.
  snmpio::WalkOptions options;
  options.maxRepetitions = 10;

  // A `total` cancellation lets the batch in hand finish and then stops the Walk cleanly, where a
  // `terminal` one would drop it at once. Returning false from the handler is the other way to
  // stop; the signal is the one that also reaches a Walk from outside it, a deadline say.
  net::asio::cancellation_signal stop;
  std::size_t rows = 0;
  auto onBatch = [&](std::span<const snmpio::Varbind> batch) {
    for (const auto& vb : batch) {
      if (limit && rows == *limit) break;
      std::cout << vb.name.toString() << " = " << snmpio::toString(vb.val) << "\n";
      ++rows;
    }
    // The handler runs on the Client's strand, which is where the Walk observes its cancellation
    // state, so emitting from here needs no hop.
    if (limit && rows == *limit) stop.emit(net::asio::cancellation_type::total);
    return true;
  };

  net::ErrorCode ec;
  co_await client.asyncWalk(
      std::move(target), std::move(credentials), std::move(base), options, onBatch,
      net::asio::bind_cancellation_slot(stop.slot(),
                                        net::asio::redirect_error(net::asio::use_awaitable, ec)));

  if (ec) std::cerr << "walk ended after " << rows << " rows: " << ec.message() << "\n";
  client.stop();
}

int main(int argc, char** argv) {
  if (argc != 6 && argc != 7) {
    std::cerr << "usage: " << argv[0] << " <address> <port> <user> <password> <base-oid> [limit]\n";
    return 2;
  }

  snmpio::Target target;
  target.endpoint = {net::asio::ip::make_address(argv[1]),
                     static_cast<std::uint16_t>(std::atoi(argv[2]))};

  // AES-256 needs more key material than SHA-1 produces, and the two Key Extensions make it in
  // mutually incompatible ways. Aes256C is Reeder's, Aes256 Blumenthal's: the Agent's user
  // decides which, and nothing on the wire says. Usm.hpp lists the rest.
  snmpio::Credentials credentials;
  credentials.userName = argv[3];
  credentials.level = snmpio::SecurityLevel::AuthPriv;
  credentials.authProtocol = snmpio::AuthProtocol::Sha1;
  credentials.authPassword = argv[4];
  credentials.privProtocol = snmpio::PrivProtocol::Aes256C;
  credentials.privPassword = argv[4];

  const auto base = snmpio::Oid::parse(argv[5]);
  if (!base) {
    std::cerr << "bad base OID: " << argv[5] << "\n";
    return 2;
  }
  std::optional<std::size_t> limit;
  if (argc == 7) limit = std::strtoul(argv[6], nullptr, 10);

  net::IoContext io;
  snmpio::Client client(io.get_executor());
  net::asio::co_spawn(io, run(client, target, credentials, *base, limit), net::asio::detached);
  io.run();
}
