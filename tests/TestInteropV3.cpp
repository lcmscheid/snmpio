#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
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
// because they are ours to create -- so an Agent running someone else's configuration is
// addressed the other way in, by SNMPIO_INTEROP_V3_USER below.
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

// Carrying neither, which is a row of the matrix like any other: the unauthenticated user.
constexpr AuthRow noAuthRow{AuthProtocol::None, "none"};
constexpr PrivRow noPrivRow{PrivProtocol::None, "none"};

// What the tests that want one pair rather than the whole matrix reach for. Named rather than
// indexed off the tables above, so that reordering those cannot silently retarget a test.
constexpr AuthRow sha1Row{AuthProtocol::Sha1, "sha1"};
constexpr AuthRow sha256Row{AuthProtocol::Sha256, "sha256"};
constexpr PrivRow aes128Row{PrivProtocol::Aes128, "aes"};

// The Security Level a pair adds up to, said the way a failure message wants to read it.
std::string pairLabel(const AuthRow& auth, const PrivRow& priv) {
  if (auth.protocol == AuthProtocol::None) return "noAuthNoPriv";
  if (priv.protocol == PrivProtocol::None) return std::string("authNoPriv/") + auth.name;
  return std::string("authPriv/") + auth.name + "/" + priv.name;
}

// The user our own configuration creates for a pair, which is the pair spelled out.
std::string conventionalUser(const AuthRow& auth, const PrivRow& priv) {
  if (auth.protocol == AuthProtocol::None) return "noauth";
  if (priv.protocol == PrivProtocol::None) return std::string("auth") + auth.name;
  return std::string("priv") + auth.name + priv.name;
}

[[nodiscard]] const AuthRow* findAuth(std::string_view name) {
  if (name == noAuthRow.name) return &noAuthRow;
  for (const auto& row : authProtocols) {
    if (name == row.name) return &row;
  }
  return nullptr;
}

[[nodiscard]] const PrivRow* findPriv(std::string_view name) {
  if (name == noPrivRow.name) return &noPrivRow;
  for (const auto& row : privProtocols) {
    if (name == row.name) return &row;
  }
  for (const auto& row : keyExtensionProtocols) {
    if (name == row.name) return &row;
  }
  return nullptr;
}

// A v3 user this suite did not create. A switch on the bench carries whatever user someone set up
// on it years ago, so the run says what that user is called and what it carries, and the tests
// address it instead of the convention. One is enough to be useful -- a Target typically has
// exactly one -- and the matrix then covers the single pair it can serve and says which pairs it
// could not.
struct NamedUser {
  std::string name;
  AuthRow auth;
  PrivRow priv;
};

// Every pair of the matrix but the one a named user carries, for the message that says what
// naming it cost this run.
std::string matrixPairsExcept(const std::string& covered) {
  std::string out;
  const auto add = [&](const std::string& label) {
    if (label == covered) return;
    if (!out.empty()) out += ", ";
    out += label;
  };
  add(pairLabel(noAuthRow, noPrivRow));
  for (const auto& auth : authProtocols) {
    add(pairLabel(auth, noPrivRow));
    for (const auto& priv : privProtocols) add(pairLabel(auth, priv));
  }
  return out;
}

void expectSysDescr(const GetResult& result, const std::string& what) {
  ASSERT_FALSE(result.ec) << what << ": " << result.ec.category().name() << ": "
                          << result.ec.message();
  ASSERT_EQ(result.response.varbinds.size(), 1U) << what;
  EXPECT_EQ(result.response.varbinds[0].name, sysDescr) << what;
}

// The Target and the password every test here needs, or a skip -- plus, optionally, the one user
// the Agent actually has. Both ways in come from the environment, and only whoever starts the run
// knows which applies.
class InteropV3 : public ::testing::Test {
 protected:
  void SetUp() override {
    const auto address = envVar("SNMPIO_INTEROP_TARGET");
    const auto user = envVar("SNMPIO_INTEROP_V3_USER");
    const auto authName = envVar("SNMPIO_INTEROP_V3_AUTH");
    const auto privName = envVar("SNMPIO_INTEROP_V3_PRIV");
    const auto password = envVar("SNMPIO_INTEROP_V3_PASSWORD");
    // Neither way in named: no Target, or no user of any kind. Only unset variables skip; from
    // here on every one of them is set, and a set one that cannot be used fails instead.
    if (!address || (!user && !password)) {
      GTEST_SKIP() << "needs SNMPIO_INTEROP_TARGET, and either SNMPIO_INTEROP_V3_PASSWORD for the "
                      "users our own configuration creates or SNMPIO_INTEROP_V3_USER for one the "
                      "Agent already had";
    }
    const auto target = makeInteropTarget(*address, envPort("SNMPIO_INTEROP_PORT"));
    ASSERT_TRUE(target.has_value())
        << "SNMPIO_INTEROP_TARGET/_PORT is not an address and a port: " << *address;
    m_target = *target;
    m_password = password.value_or("");

    if (!user) {
      // The protocols say what one named user carries, so without the name they are addressed at
      // nobody -- and silently running the convention path instead would report green for a user
      // this run believed it had asked for.
      ASSERT_TRUE(!authName && !privName)
          << "SNMPIO_INTEROP_V3_AUTH/_PRIV say what SNMPIO_INTEROP_V3_USER carries, and no user "
             "was named";
      return;
    }
    // Set but unspellable fails the run, like every other interop variable: a protocol name that
    // fell back to a default would send the wrong digest and blame the Agent for refusing it.
    const auto* const auth = findAuth(authName.value_or("none"));
    const auto* const priv = findPriv(privName.value_or("none"));
    ASSERT_NE(auth, nullptr) << "SNMPIO_INTEROP_V3_AUTH is not one of none, md5, sha1, sha224, "
                                "sha256, sha384, sha512";
    ASSERT_NE(priv, nullptr) << "SNMPIO_INTEROP_V3_PRIV is not one of none, des, aes, aes192, "
                                "aes256, aes192c, aes256c";
    ASSERT_TRUE(auth->protocol != AuthProtocol::None || priv->protocol == PrivProtocol::None)
        << "SNMPIO_INTEROP_V3_PRIV needs an SNMPIO_INTEROP_V3_AUTH: USM derives the privacy key "
           "with the authentication protocol's hash, so there is no privacy without it";
    // A user that authenticates has a secret, and this is the only place it can come from. Only a
    // user carrying neither protocol can do without one.
    ASSERT_TRUE(auth->protocol == AuthProtocol::None || password.has_value())
        << "SNMPIO_INTEROP_V3_USER=" << *user << " carries " << auth->name
        << ", so it needs SNMPIO_INTEROP_V3_PASSWORD to authenticate with";
    m_named = NamedUser{*user, *auth, *priv};
  }

  // The user to send for one pair: the one this run named, or the conventional one that says what
  // it carries. Callers filter first -- a named user serves its own pair and no other.
  [[nodiscard]] Credentials credentials(const AuthRow& auth, const PrivRow& priv) const {
    auto level = SecurityLevel::AuthPriv;
    if (auth.protocol == AuthProtocol::None) {
      level = SecurityLevel::NoAuthNoPriv;
    } else if (priv.protocol == PrivProtocol::None) {
      level = SecurityLevel::AuthNoPriv;
    }
    return Credentials{m_named ? m_named->name : conventionalUser(auth, priv),
                       level,
                       auth.protocol,
                       auth.protocol == AuthProtocol::None ? std::string() : m_password,
                       priv.protocol,
                       priv.protocol == PrivProtocol::None ? std::string() : m_password};
  }

  // The pair the tests that want one reach for: the named user's, or SHA-256 over AES-128.
  [[nodiscard]] Credentials defaultCredentials() const {
    return m_named ? credentials(m_named->auth, m_named->priv) : credentials(sha256Row, aes128Row);
  }

  Target m_target;
  std::string m_password;
  std::optional<NamedUser> m_named;
};

// One case per pair, which is what an interop matrix is: the unauthenticated user, six protocols
// authenticating, and each of them encrypting under both of `snmpd`'s ciphers -- which is every
// Security Level, in the same pass.
//
// A named user is one user and so one pair, and the rest of the matrix is not its to answer: the
// run covers what that user carries and says what it did not reach, rather than failing the
// Target for users nobody claimed it had.
TEST_F(InteropV3, CoversTheAuthAndPrivacyMatrix) {
  if (m_named) {
    const auto label = pairLabel(m_named->auth, m_named->priv);
    expectSysDescr(get(m_target, defaultCredentials()), label);
    GTEST_LOG_(INFO) << "SNMPIO_INTEROP_V3_USER=" << m_named->name << " carries " << label
                     << " and nothing else, so this run skipped: " << matrixPairsExcept(label);
    return;
  }
  expectSysDescr(get(m_target, credentials(noAuthRow, noPrivRow)), "noAuthNoPriv");
  for (const auto& auth : authProtocols) {
    expectSysDescr(get(m_target, credentials(auth, noPrivRow)), pairLabel(auth, noPrivRow));
    for (const auto& priv : privProtocols) {
      expectSysDescr(get(m_target, credentials(auth, priv)), pairLabel(auth, priv));
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
  if (m_named) {
    GTEST_SKIP() << "needs the four privsha1aes192/256(c) users, and this run named one user: "
                 << m_named->name << " carrying " << pairLabel(m_named->auth, m_named->priv);
  }
  if (!envVar("SNMPIO_INTEROP_V3_KEY_EXTENSIONS")) {
    GTEST_SKIP() << "needs SNMPIO_INTEROP_V3_KEY_EXTENSIONS and an Agent serving AES-192/256";
  }
  for (const auto& priv : keyExtensionProtocols) {
    expectSysDescr(get(m_target, credentials(sha1Row, priv)), pairLabel(sha1Row, priv));
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
  const auto credentials = defaultCredentials();
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
  if (m_named && m_named->auth.protocol == AuthProtocol::None) {
    GTEST_SKIP() << "needs an authenticating user, and SNMPIO_INTEROP_V3_USER=" << m_named->name
                 << " carries no authentication";
  }
  // The named user at its own Security Level, since a Target that requires privacy of it would
  // refuse the request before ever checking the digest; the conventional path keeps the
  // authNoPriv user it has always used.
  Credentials wrong = m_named ? defaultCredentials() : credentials(sha256Row, noPrivRow);
  wrong.authPassword += "-and-then-some";
  const auto wrongResult = get(m_target, wrong);
  EXPECT_EQ(wrongResult.ec, make_error_code(Errc::AuthFailed))
      << "got " << wrongResult.ec.category().name() << ": " << wrongResult.ec.message();

  Credentials nobody = m_named ? defaultCredentials() : credentials(sha256Row, noPrivRow);
  nobody.userName = "nobody-by-that-name";
  const auto unknown = get(m_target, nobody);
  EXPECT_EQ(unknown.ec, make_error_code(Errc::UnknownUserName))
      << "got " << unknown.ec.category().name() << ": " << unknown.ec.message();
}

}  // namespace
}  // namespace snmpio
