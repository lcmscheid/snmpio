#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>

#include "InteropTarget.hpp"

namespace snmpio {
namespace {

using test::envVar;
using test::makeInteropTarget;

const Oid sysDescr{1, 3, 6, 1, 2, 1, 1, 1, 0};

// The users tests/interop/snmpd-conf.sh creates, named after what they carry: `noauth`, `authX`
// per auth protocol, and `privXY` per (auth, privacy) pair. Naming them here is only possible
// because they are ours to create -- which is why an Agent not running that configuration must
// leave SNMPIO_INTEROP_V3_PASSWORD unset, and these tests skip.
struct AuthRow {
  AuthProtocol protocol;
  const char* name;
};
constexpr std::array<AuthRow, 6> authProtocols{{{AuthProtocol::Md5, "md5"},
                                                {AuthProtocol::Sha1, "sha1"},
                                                {AuthProtocol::Sha224, "sha224"},
                                                {AuthProtocol::Sha256, "sha256"},
                                                {AuthProtocol::Sha384, "sha384"},
                                                {AuthProtocol::Sha512, "sha512"}}};

// What `snmpd` speaks. AES-192/256 under either Key Extension are not in it -- net-snmp needs a
// build flag for them and Debian's does not carry it -- so they are the Simulator's job
// (ADR-0006).
struct PrivRow {
  PrivProtocol protocol;
  const char* name;
};
constexpr std::array<PrivRow, 2> privProtocols{
    {{PrivProtocol::Des, "des"}, {PrivProtocol::Aes128, "aes"}}};

// What the tests that want one pair rather than the whole matrix reach for. Named rather than
// indexed off the tables above, so that reordering those cannot silently retarget a test.
constexpr AuthRow sha256Row{AuthProtocol::Sha256, "sha256"};
constexpr PrivRow aes128Row{PrivProtocol::Aes128, "aes"};

Credentials authCredentials(const AuthRow& auth, const std::string& password) {
  return Credentials{std::string("auth") + auth.name,
                     SecurityLevel::AuthNoPriv,
                     auth.protocol,
                     password,
                     PrivProtocol::None,
                     ""};
}

Credentials privCredentials(const AuthRow& auth, const PrivRow& priv, const std::string& password) {
  return Credentials{std::string("priv") + auth.name + priv.name,
                     SecurityLevel::AuthPriv,
                     auth.protocol,
                     password,
                     priv.protocol,
                     password};
}

// Runs one GET to completion on its own io_context and Client, and hands back what the completion
// saw. A Client per call on purpose: the caches are the Client's (ADR-0003), so a fresh one is the
// only way to ask what an Engine costs the first time.
struct GetResult {
  net::ErrorCode ec;
  Response response;
};

GetResult get(const Target& target, const Credentials& credentials) {
  net::IoContext io;
  Client client(io.get_executor());
  GetResult result;

  client.asyncGet(target, credentials, {sysDescr}, [&](net::ErrorCode ec, Response response) {
    result.ec = ec;
    result.response = std::move(response);
    client.stop();
  });
  io.run();
  return result;
}

void expectSysDescr(const GetResult& result, const std::string& what) {
  ASSERT_FALSE(result.ec) << what << ": " << result.ec.category().name() << ": "
                          << result.ec.message();
  ASSERT_EQ(result.response.varbinds.size(), 1U) << what;
  EXPECT_EQ(result.response.varbinds[0].name, sysDescr) << what;
}

// The Target and the password every test here needs, or a skip. Both come from the environment,
// and either one missing means this Agent is not running our configuration.
class InteropV3 : public ::testing::Test {
 protected:
  void SetUp() override {
    const auto spec = envVar("SNMPIO_INTEROP_TARGET");
    const auto password = envVar("SNMPIO_INTEROP_V3_PASSWORD");
    if (!spec || !password) {
      GTEST_SKIP() << "needs SNMPIO_INTEROP_TARGET and SNMPIO_INTEROP_V3_PASSWORD";
    }
    const auto target = makeInteropTarget(*spec);
    ASSERT_TRUE(target.has_value()) << "SNMPIO_INTEROP_TARGET is not address[:port]: " << *spec;
    m_target = *target;
    m_password = *password;
  }

  Target m_target;
  std::string m_password;
};

// One case per pair, which is what an interop matrix is: the unauthenticated user, six protocols
// authenticating, and each of them encrypting under both of `snmpd`'s ciphers -- which is every
// Security Level, in the same pass.
TEST_F(InteropV3, CoversTheAuthAndPrivacyMatrix) {
  expectSysDescr(get(m_target, Credentials{"noauth", SecurityLevel::NoAuthNoPriv,
                                           AuthProtocol::None, "", PrivProtocol::None, ""}),
                 "noAuthNoPriv");
  for (const auto& auth : authProtocols) {
    expectSysDescr(get(m_target, authCredentials(auth, m_password)),
                   std::string("authNoPriv/") + auth.name);
    for (const auto& priv : privProtocols) {
      expectSysDescr(get(m_target, privCredentials(auth, priv, m_password)),
                     std::string("authPriv/") + auth.name + "/" + priv.name);
    }
  }
}

// Sits between the Client and the Agent and counts the datagrams the Client sends.
//
// Discovery is deliberately invisible from the API -- stage 3 put it underneath every operation
// precisely so that no caller has to think about it -- so counting what actually went over the
// wire is the only honest way to ask what the first request against an unknown Engine cost.
class CountingRelay {
 public:
  CountingRelay(net::IoContext& io, net::UdpEndpoint target)
      : m_target(std::move(target)),
        // Both sockets in the Target's own family, because makeInteropTarget takes a v6 literal
        // and a relay that only ever binds v4 would turn "[::1]" into a timeout. The client-side
        // one binds loopback rather than the wildcard: its address is what the Client is handed to
        // send to, and nothing can send to 0.0.0.0.
        m_clientSide(
            io,
            net::UdpEndpoint(
                net::asio::ip::make_address(m_target.address().is_v6() ? "::1" : "127.0.0.1"), 0)),
        m_targetSide(io, net::UdpEndpoint(m_target.protocol(), 0)) {
    receiveFromClient();
    receiveFromTarget();
  }

  [[nodiscard]] net::UdpEndpoint endpoint() const { return m_clientSide.local_endpoint(); }
  [[nodiscard]] int datagramsFromClient() const noexcept { return m_fromClient; }

  void close() {
    // Boost.Asio hands the error_code back as the return value as well, standalone Asio returns
    // void, and the ec overload is the only form both spell the same way (ADR-0002). There is
    // nothing to do with it on a socket being discarded either way.
    //
    // NOLINTBEGIN(bugprone-unused-return-value,cert-err33-c)
    net::ErrorCode ignored;
    m_clientSide.close(ignored);
    m_targetSide.close(ignored);
    // NOLINTEND(bugprone-unused-return-value,cert-err33-c)
  }

 private:
  void receiveFromClient() {
    m_clientSide.async_receive_from(
        net::asio::buffer(m_clientBuf), m_client, [this](net::ErrorCode ec, std::size_t n) {
          if (ec) return;
          ++m_fromClient;
          net::ErrorCode ignored;
          m_targetSide.send_to(net::asio::buffer(m_clientBuf, n), m_target, 0, ignored);
          receiveFromClient();
        });
  }

  void receiveFromTarget() {
    m_targetSide.async_receive_from(
        net::asio::buffer(m_targetBuf), m_targetFrom, [this](net::ErrorCode ec, std::size_t n) {
          if (ec) return;
          net::ErrorCode ignored;
          m_clientSide.send_to(net::asio::buffer(m_targetBuf, n), m_client, 0, ignored);
          receiveFromTarget();
        });
  }

  net::UdpEndpoint m_target;
  net::UdpSocket m_clientSide;
  net::UdpSocket m_targetSide;
  net::UdpEndpoint m_client;
  net::UdpEndpoint m_targetFrom;
  std::array<std::byte, 4096> m_clientBuf{};
  std::array<std::byte, 4096> m_targetBuf{};
  int m_fromClient = 0;
};

// The Engine Discovery criterion, stated the way it is observable: the first request against an
// Engine we have never spoken to pays for the extra round trips, and the second pays for none.
TEST_F(InteropV3, DiscoveryCostsExtraRoundTripsOnlyOnce) {
  net::IoContext io;
  CountingRelay relay(io, m_target.endpoint);
  Target target = m_target;
  target.endpoint = relay.endpoint();

  Client client(io.get_executor());
  const auto credentials = privCredentials(sha256Row, aes128Row, m_password);
  int first = 0;
  int second = 0;
  net::ErrorCode firstEc;
  net::ErrorCode secondEc;

  // The relay keeps a receive outstanding for as long as it is open, so every path out of here
  // has to close it -- including the one where the first request failed and there is no second.
  const auto finish = [&] {
    client.stop();
    relay.close();
  };

  client.asyncGet(target, credentials, {sysDescr}, [&](net::ErrorCode ec, const Response&) {
    firstEc = ec;
    first = relay.datagramsFromClient();
    if (ec) {
      finish();
      return;
    }
    // The second request runs on the same Client, so it meets the caches the first one filled --
    // which is the whole of what there is to observe.
    client.asyncGet(target, credentials, {sysDescr}, [&](net::ErrorCode ec2, const Response&) {
      secondEc = ec2;
      second = relay.datagramsFromClient() - first;
      finish();
    });
  });
  io.run();

  ASSERT_FALSE(firstEc) << firstEc.message();
  ASSERT_FALSE(secondEc) << secondEc.message();
  // Three on a healthy run -- the engineID probe, the boots/time probe, then the request -- but
  // what the criterion asks is only that discovery is paid once, and a retransmitted datagram on
  // a loaded runner would make an exact count red for a reason that is not this library's.
  EXPECT_GT(first, second);
  EXPECT_EQ(second, 1);
}

// A wrong password must arrive as the Report the Engine sends -- usmStatsWrongDigests, which this
// library spells AuthFailed because that is what it means. A timeout here would mean the Report
// was dropped, and "wrong password" would be indistinguishable from "unplugged".
TEST_F(InteropV3, SurfacesAWrongPasswordAsAReport) {
  const auto wrong = get(m_target, authCredentials(sha256Row, m_password + "-and-then-some"));
  EXPECT_EQ(wrong.ec, make_error_code(Errc::AuthFailed))
      << "got " << wrong.ec.category().name() << ": " << wrong.ec.message();

  const Credentials nobody{"nobody-by-that-name", SecurityLevel::AuthNoPriv,
                           AuthProtocol::Sha256,  m_password,
                           PrivProtocol::None,    ""};
  const auto unknown = get(m_target, nobody);
  EXPECT_EQ(unknown.ec, make_error_code(Errc::UnknownUserName))
      << "got " << unknown.ec.category().name() << ": " << unknown.ec.message();
}

}  // namespace
}  // namespace snmpio
