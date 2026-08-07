#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>

#include "InteropRelay.hpp"
#include "InteropTarget.hpp"

namespace snmpio {
namespace {

using test::CountingRelay;
using test::envPort;
using test::envVar;
using test::get;
using test::GetResult;
using test::makeInteropTarget;
using test::sysDescr;

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

// What the Simulator adds, and the reason it is in CI at all (ADR-0006).
constexpr std::array<PrivRow, 4> keyExtensionProtocols{{{PrivProtocol::Aes192, "aes192"},
                                                        {PrivProtocol::Aes256, "aes256"},
                                                        {PrivProtocol::Aes192C, "aes192c"},
                                                        {PrivProtocol::Aes256C, "aes256c"}}};

// What the tests that want one pair rather than the whole matrix reach for. Named rather than
// indexed off the tables above, so that reordering those cannot silently retarget a test.
constexpr AuthRow sha1Row{AuthProtocol::Sha1, "sha1"};
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
    const auto address = envVar("SNMPIO_INTEROP_TARGET");
    const auto password = envVar("SNMPIO_INTEROP_V3_PASSWORD");
    if (!address || !password) {
      GTEST_SKIP() << "needs SNMPIO_INTEROP_TARGET and SNMPIO_INTEROP_V3_PASSWORD";
    }
    const auto target = makeInteropTarget(*address, envPort("SNMPIO_INTEROP_PORT"));
    ASSERT_TRUE(target.has_value())
        << "SNMPIO_INTEROP_TARGET/_PORT is not an address and a port: " << *address;
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

// Both Key Extension schemes, against the one Agent in CI that speaks either. Blumenthal and
// Reeder are mutually incompatible, so a Client that guessed instead of choosing fails half of
// these -- which is the whole point of running them on every commit rather than at pre-release
// against a borrowed switch (ADR-0006).
//
// SHA-1 for all four, and not arbitrarily: both schemes derive `localizedKey || extension` and
// truncate to the cipher's key length, so an auth hash already as long as the key discards the
// extension and the two schemes come out byte-identical. SHA-1's 20 bytes are shorter than both 24
// and 32, so the extension is actually reached; pairing with SHA-256 would pass without either
// scheme being implemented at all.
TEST_F(InteropV3, CoversBothKeyExtensions) {
  if (!envVar("SNMPIO_INTEROP_V3_KEY_EXTENSIONS")) {
    GTEST_SKIP() << "needs SNMPIO_INTEROP_V3_KEY_EXTENSIONS and an Agent serving AES-192/256";
  }
  for (const auto& priv : keyExtensionProtocols) {
    expectSysDescr(get(m_target, privCredentials(sha1Row, priv, m_password)),
                   std::string("authPriv/sha1/") + priv.name);
  }
}

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
//
// Gated, because an Agent that answers a bad digest with silence is not thereby broken: RFC 3414
// §3.2 (5) lets it choose, and the Simulator does -- the library GoSNMPServer it is built on sends
// no usmStats Report at all, so against it this asserts on an Agent's choice rather than on this
// Client.
TEST_F(InteropV3, SurfacesAWrongPasswordAsAReport) {
  if (!envVar("SNMPIO_INTEROP_V3_USM_REPORTS")) {
    GTEST_SKIP() << "needs SNMPIO_INTEROP_V3_USM_REPORTS and an Agent that sends usmStats Reports";
  }
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
