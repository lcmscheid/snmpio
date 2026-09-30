#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>

#include "InteropCredentials.hpp"
#include "InteropOperations.hpp"
#include "InteropRelay.hpp"
#include "InteropSet.hpp"
#include "InteropSummary.hpp"
#include "InteropTarget.hpp"
#include "InteropWalk.hpp"

namespace snmpio {
namespace {

using test::aes128Row;
using test::authProtocols;
using test::AuthRow;
using test::CountingRelay;
using test::credentialsFor;
using test::envPort;
using test::envVar;
using test::expectedRefusal;
using test::findAuth;
using test::findPriv;
using test::get;
using test::getAndRecord;
using test::getBulkAndRecord;
using test::getNextAndGetBulkAndRecord;
using test::keyExtensionAuthRow;
using test::keyExtensionProtocols;
using test::keyExtensionsUnset;
using test::makeInteropTarget;
using test::NamedUser;
using test::noAuthRow;
using test::noPrivRow;
using test::Operation;
using test::operationLabel;
using test::pairLabel;
using test::privProtocols;
using test::PrivRow;
using test::recordAuthAndPrivacyMatrixSkipped;
using test::recordKeyExtensionsSkipped;
using test::recordOutcome;
using test::recordSkip;
using test::refusedSetAndRecord;
using test::securityLevel;
using test::securityLevelPairs;
using test::sha256Row;
using test::sysDescr;
using test::walkBothModesAndRecord;
using test::walkModes;
using test::writeReadAndRestoreAndRecord;
using test::writerUnset;
using test::writerVariable;

// The operations run at every Security Level besides GET and test::walkModes. GETBULK and the
// Walks run again under every privacy protocol, since their Responses cross many cipher blocks.
constexpr std::array getNextAndGetBulk{Operation::GetNext, Operation::GetBulk};
constexpr std::array getBulkAlone{Operation::GetBulk};
// The two SETs, which run at every Security Level and under no other privacy protocol.
constexpr std::array refusedSetAlone{Operation::RefusedSet};
constexpr std::array bothSets{Operation::RefusedSet, Operation::Set};

// Record that the rows of `operations` at every Security Level were skipped for the same reason.
void recordSecurityLevelsSkipped(std::span<const Operation> operations, const std::string& reason) {
  for (const auto operation : operations) {
    for (const auto& [auth, priv] : securityLevelPairs) {
      recordSkip(operationLabel(operation, pairLabel(auth, priv)), reason);
    }
  }
}

// Record that the rows of `operations` under every privacy protocol were skipped for the same
// reason.
void recordPrivacySkipped(std::span<const Operation> operations, const std::string& reason) {
  for (const auto operation : operations) {
    for (const auto& priv : privProtocols) {
      recordSkip(operationLabel(operation, pairLabel(sha256Row, priv)), reason);
    }
    recordKeyExtensionsSkipped(operation, reason);
  }
}

// Record that every v3 row was skipped for the same reason. Called from SetUp when the Target is
// configured but the run did not name any v3 way in, so the summary still lists every row.
void recordEveryRowSkipped(const std::string& reason) {
  recordAuthAndPrivacyMatrixSkipped(reason);
  recordKeyExtensionsSkipped(Operation::Get, reason);
  recordSecurityLevelsSkipped(getNextAndGetBulk, reason);
  recordSecurityLevelsSkipped(walkModes, reason);
  recordSecurityLevelsSkipped(bothSets, reason);
  recordPrivacySkipped(getBulkAlone, reason);
  recordPrivacySkipped(walkModes, reason);
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
    // No Target at all is the bare checkout, where nothing here is addressed at anything and a
    // stray variable left over from some other run is not this suite's to complain about.
    if (!address) GTEST_SKIP() << "needs SNMPIO_INTEROP_TARGET";
    // A Target, though, means a run that meant to reach it. The protocols say what one named user
    // carries, so without the name they are addressed at nobody -- and this is checked ahead of
    // the skip below because the run that forgot SNMPIO_INTEROP_V3_USER is exactly the run that
    // has no password either, and would otherwise skip green believing it had named a user.
    ASSERT_TRUE(user || (!authName && !privName))
        << "SNMPIO_INTEROP_V3_AUTH/_PRIV say what SNMPIO_INTEROP_V3_USER carries, and no user "
           "was named";
    // Neither way in named. Only unset variables skip; from here on every one of them is set, and
    // a set one that cannot be used fails instead. When the Target is configured but v3 is not,
    // record the whole v3 matrix as skipped so the summary still lists every pair.
    if (!user && !password) {
      const std::string reason =
          "needs either SNMPIO_INTEROP_V3_PASSWORD for the conventional users or "
          "SNMPIO_INTEROP_V3_USER for a named user";
      recordEveryRowSkipped(reason);
      GTEST_SKIP() << "needs either SNMPIO_INTEROP_V3_PASSWORD for the users our own configuration "
                      "creates or SNMPIO_INTEROP_V3_USER for one the Agent already had";
    }
    const auto target = makeInteropTarget(*address, envPort("SNMPIO_INTEROP_PORT"));
    ASSERT_TRUE(target.has_value())
        << "SNMPIO_INTEROP_TARGET/_PORT is not an address and a port: " << *address;
    m_target = *target;
    m_password = password.value_or("");

    if (!user) return;
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
    return credentialsFor(auth, priv, m_password, m_named ? &*m_named : nullptr);
  }

  // The pair the tests that want one reach for: the named user's, or SHA-256 over AES-128.
  [[nodiscard]] Credentials singlePairCredentials() const {
    return m_named ? credentials(m_named->auth, m_named->priv) : credentials(sha256Row, aes128Row);
  }

  // Why a row the named user does not serve is skipped: the run said which one pair it had.
  [[nodiscard]] std::string namedUserOnly() const {
    return "run named one user: " + m_named->name + " carrying " +
           pairLabel(m_named->auth, m_named->priv);
  }

  // The pairs the privacy-protocol tests cover: every privacy protocol on SHA-256, then the Key
  // Extension rows on SHA-1 when the run says the Agent serves them. `send(credentials, label)`
  // runs once per pair, and the rows of `operations` it does not reach are recorded as skipped --
  // all of them for a named user, which is one user and so one cipher. That skip marks the test
  // skipped but returns only from here, so each test ends with this call.
  template <typename Send>
  void underEveryPrivacyProtocol(std::span<const Operation> operations, Send send) {
    if (m_named) {
      const auto reason = namedUserOnly();
      recordPrivacySkipped(operations, reason);
      GTEST_SKIP() << reason;
    }
    for (const auto& priv : privProtocols) {
      send(credentials(sha256Row, priv), pairLabel(sha256Row, priv));
    }
    if (!envVar("SNMPIO_INTEROP_V3_KEY_EXTENSIONS")) {
      for (const auto operation : operations) {
        recordKeyExtensionsSkipped(operation, keyExtensionsUnset);
      }
      return;
    }
    for (const auto& priv : keyExtensionProtocols) {
      send(credentials(keyExtensionAuthRow, priv), pairLabel(keyExtensionAuthRow, priv));
    }
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
// run covers what that user carries, rather than failing the Target for users nobody claimed it
// had.
TEST_F(InteropV3, CoversTheAuthAndPrivacyMatrix) {
  if (m_named) {
    getAndRecord(m_target, singlePairCredentials(), pairLabel(m_named->auth, m_named->priv));
    recordAuthAndPrivacyMatrixSkipped(namedUserOnly());
    return;
  }
  getAndRecord(m_target, credentials(noAuthRow, noPrivRow), pairLabel(noAuthRow, noPrivRow));
  for (const auto& auth : authProtocols) {
    getAndRecord(m_target, credentials(auth, noPrivRow), pairLabel(auth, noPrivRow));
    for (const auto& priv : privProtocols) {
      getAndRecord(m_target, credentials(auth, priv), pairLabel(auth, priv));
    }
  }
}

// Both Key Extension schemes, against every Agent in CI -- `snmpd`, whose reading of each is not
// ours, and the Simulator, whose is. Blumenthal and Reeder are mutually incompatible, so a Client
// that guessed instead of choosing fails half of these -- which is the whole point of running them
// on every commit rather than at pre-release against a borrowed switch (ADR-0006).
//
// SHA-1 for all four, and not arbitrarily: both schemes derive `localizedKey || extension` and
// truncate to the cipher's key length, so an auth hash already as long as the key discards the
// extension and the two schemes come out byte-identical. SHA-1's 20 bytes are shorter than both 24
// and 32, so the extension is actually reached; pairing with SHA-256 would pass without either
// scheme being implemented at all.
TEST_F(InteropV3, CoversBothKeyExtensions) {
  if (m_named) {
    const std::string reason = "needs the four privsha1aes192/256(c) users; " + namedUserOnly();
    recordKeyExtensionsSkipped(Operation::Get, reason);
    GTEST_SKIP() << reason;
  }
  if (!envVar("SNMPIO_INTEROP_V3_KEY_EXTENSIONS")) {
    recordKeyExtensionsSkipped(Operation::Get, keyExtensionsUnset);
    GTEST_SKIP() << keyExtensionsUnset;
  }
  for (const auto& priv : keyExtensionProtocols) {
    getAndRecord(m_target, credentials(keyExtensionAuthRow, priv),
                 pairLabel(keyExtensionAuthRow, priv));
  }
}

// GETNEXT and GETBULK at every Security Level, on the representative pair: an operation-specific
// bug in how a Scoped PDU is built or read would hide behind a GET that works. A named user is one
// pair, and the operations run as that pair instead.
TEST_F(InteropV3, GetNextAndGetBulkAtEverySecurityLevel) {
  if (m_named) {
    getNextAndGetBulkAndRecord(m_target, singlePairCredentials(),
                               pairLabel(m_named->auth, m_named->priv));
    recordSecurityLevelsSkipped(getNextAndGetBulk, namedUserOnly());
    return;
  }
  for (const auto& [auth, priv] : securityLevelPairs) {
    getNextAndGetBulkAndRecord(m_target, credentials(auth, priv), pairLabel(auth, priv));
  }
}

// GETBULK under every privacy protocol the Agent speaks, at the size test::bulkRepetitions picks
// for it, on data an Agent nobody here wrote encrypted. The AES-128 row is the Security Level
// test's authPriv row again, and test::replaces says which of the two the summary keeps. The Key
// Extension rows are gated as the GET ones are, and on SHA-1 for the same reason.
TEST_F(InteropV3, GetBulkUnderEveryPrivacyProtocol) {
  underEveryPrivacyProtocol(getBulkAlone,
                            [&](const Credentials& credentials, const std::string& label) {
                              getBulkAndRecord(m_target, credentials, label);
                            });
}

// A Walk that needs several batches, in both modes, each streaming and collecting, at every
// Security Level on the representative pair -- or as the named user's pair, which is the one it
// serves.
TEST_F(InteropV3, WalksSeveralBatchesAtEverySecurityLevel) {
  if (m_named) {
    walkBothModesAndRecord(m_target, singlePairCredentials(),
                           pairLabel(m_named->auth, m_named->priv));
    recordSecurityLevelsSkipped(walkModes, namedUserOnly());
    return;
  }
  for (const auto& [auth, priv] : securityLevelPairs) {
    walkBothModesAndRecord(m_target, credentials(auth, priv), pairLabel(auth, priv));
  }
}

// The same Walks under every privacy protocol the Agent speaks: a Subtree several batches long is
// many encrypted Responses, each running to many cipher blocks, where
// GetBulkUnderEveryPrivacyProtocol is one. The same pairs as that test, gated the same way.
TEST_F(InteropV3, WalksSeveralBatchesUnderEveryPrivacyProtocol) {
  underEveryPrivacyProtocol(walkModes,
                            [&](const Credentials& credentials, const std::string& label) {
                              walkBothModesAndRecord(m_target, credentials, label);
                            });
}

// The promise that a rejected SET surfaces the Agent's own error-status, at every Security Level on
// the representative pair -- or as the named user's pair, the one it serves. The same SET as the
// v2c one: sysDescr.0's own value, sent as a user that only reads, so it changes nothing.
TEST_F(InteropV3, SurfacesTheAgentsRefusalOfASetAtEverySecurityLevel) {
  std::optional<ErrorStatus> expected;
  ASSERT_NO_FATAL_FAILURE(expectedRefusal(expected));
  if (m_named) {
    refusedSetAndRecord(m_target, singlePairCredentials(), pairLabel(m_named->auth, m_named->priv),
                        expected);
    recordSecurityLevelsSkipped(refusedSetAlone, namedUserOnly());
    return;
  }
  for (const auto& [auth, priv] : securityLevelPairs) {
    refusedSetAndRecord(m_target, credentials(auth, priv), pairLabel(auth, priv), expected);
  }
}

// A write that lands, read back and restored, at every Security Level the run names a writer for.
// A writer is a user of its own, never the named user or a conventional one, which all stay
// read-only; it carries its level's representative pair. With none named the test skips, and every
// level it did not reach says so in the summary.
TEST_F(InteropV3, WritesReadsBackAndRestoresSysContactAtEverySecurityLevel) {
  bool anyWriterNamed = false;
  for (const auto& [auth, priv] : securityLevelPairs) {
    const char* const variable = writerVariable(securityLevel(auth, priv));
    const auto writer = envVar(variable);
    if (!writer) {
      recordSkip(operationLabel(Operation::Set, pairLabel(auth, priv)), writerUnset(variable));
      continue;
    }
    // Set but unusable fails, as everywhere -- as a failed row rather than an assertion, so the
    // levels after it still reach the summary.
    if (auth.protocol != AuthProtocol::None && m_password.empty()) {
      recordOutcome(operationLabel(Operation::Set, pairLabel(auth, priv)),
                    std::string(variable) + "=" + *writer + " carries " + auth.name +
                        ", so it needs SNMPIO_INTEROP_V3_PASSWORD to authenticate with",
                    {});
      anyWriterNamed = true;
      continue;
    }
    const NamedUser user{*writer, auth, priv};
    writeReadAndRestoreAndRecord(m_target, credentialsFor(auth, priv, m_password, &user),
                                 pairLabel(auth, priv));
    anyWriterNamed = true;
  }
  if (!anyWriterNamed) {
    GTEST_SKIP() << "names no writer: SNMPIO_INTEROP_WRITER_NOAUTHNOPRIV, _AUTHNOPRIV and "
                    "_AUTHPRIV are all unset";
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
  const auto credentials = singlePairCredentials();
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

  ASSERT_FALSE(firstEc) << test::errorText(firstEc);
  ASSERT_FALSE(secondEc) << test::errorText(secondEc);
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
// §3.2 (5) lets it choose, and against an Agent that stays silent this would assert on its choice
// rather than on this Client. tests/interop/start-agent.sh says which Agents send the Report.
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
  Credentials wrong = m_named ? singlePairCredentials() : credentials(sha256Row, noPrivRow);
  wrong.authPassword += "-and-then-some";
  const auto wrongResult = get(m_target, wrong);
  EXPECT_EQ(wrongResult.ec, make_error_code(Errc::AuthFailed))
      << "got " << test::errorText(wrongResult.ec);

  Credentials nobody = wrong;  // the password is irrelevant to a user the Agent has not got
  nobody.userName = "nobody-by-that-name";
  const auto unknown = get(m_target, nobody);
  EXPECT_EQ(unknown.ec, make_error_code(Errc::UnknownUserName))
      << "got " << test::errorText(unknown.ec);
}

}  // namespace
}  // namespace snmpio
