// SNMPv3 noAuthNoPriv GETNEXT, in the blocking form: the io_context runs on a thread of its own
// and the caller waits on a std::future. Several OIDs travel in one request, and each comes back
// as its own lexicographic successor, in the order asked.
//
//   ./example-getnext 127.0.0.1 16161 noauth 1.3.6.1.2.1.1.1 1.3.6.1.2.1.1.3 1.3.6.1.2.1.1.5
#include <cstdlib>
#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <snmpio/Client.hpp>

// use_future is the one piece of Asio this example needs that snmpio's own headers do not pull
// in, so it names whichever Asio the installed package was built against (ADR-0002).
#if defined(SNMPIO_USE_BOOST_ASIO)
#include <boost/asio/use_future.hpp>
#else
#include <asio/use_future.hpp>
#endif

int main(int argc, char** argv) {
  if (argc < 5) {
    std::cerr << "usage: " << argv[0] << " <address> <port> <user> <oid>...\n";
    return 2;
  }

  namespace net = snmpio::net;
  net::IoContext io;
  snmpio::Client client(io.get_executor());

  snmpio::Target target;
  target.endpoint = {net::asio::ip::make_address(argv[1]),
                     static_cast<std::uint16_t>(std::atoi(argv[2]))};

  // noAuthNoPriv is a user name and nothing else. It is still SNMPv3: Engine Discovery happens
  // first, underneath, but there is no clock to synchronise because nothing is authenticated.
  snmpio::Credentials credentials;
  credentials.userName = argv[3];
  credentials.level = snmpio::SecurityLevel::NoAuthNoPriv;

  std::vector<snmpio::Oid> oids;
  for (int i = 4; i < argc; ++i) {
    const auto oid = snmpio::Oid::parse(argv[i]);
    if (!oid) {
      std::cerr << "bad OID: " << argv[i] << "\n";
      return 2;
    }
    oids.push_back(*oid);
  }

  // The Client's receive loop is outstanding work, so this thread runs until stop() below.
  std::thread runner([&io] { io.run(); });

  // use_future folds the ErrorCode into the future: get() throws it as a system_error, and hands
  // back the Response alone otherwise.
  auto response = client.asyncGetNext(target, credentials, oids, net::asio::use_future);
  int status = 0;
  try {
    for (const auto& vb : response.get().varbinds) {
      // A successor past the end of the MIB view is EndOfMibView, a Value rather than an error --
      // toString renders it like any other.
      std::cout << vb.name.toString() << " = " << snmpio::toString(vb.val) << "\n";
    }
  } catch (const net::SystemError& e) {
    std::cerr << "GETNEXT failed: " << e.code().message() << "\n";
    status = 1;
  }

  client.stop();
  runner.join();
  return status;
}
