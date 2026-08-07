#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>

#include "InteropRelay.hpp"
#include "InteropTarget.hpp"
#include "SimulatorFaults.hpp"

// The half of this Client that only ever runs when the Agent has already gone wrong, driven by an
// Agent that goes wrong on purpose (ADR-0006).
//
// Every case here has a counterpart in TestClient.cpp or TestClientV3.cpp against the Scripted
// Agent, and that is not duplication: the Scripted Agent shares our own reading of the protocol,
// so a misreading would satisfy both sides of it at once. The Simulator is a separate
// implementation in another language, and only agreeing with it is evidence.
namespace snmpio {
namespace {

using test::CountingRelay;
using test::envPort;
using test::envVar;
using test::get;
using test::makeInteropTarget;
using test::SimulatorFaults;
using test::sysDescr;

const Oid systemTree{1, 3, 6, 1, 2, 1, 1};

// The Target and the Simulator's fault control endpoint, or a skip. The control endpoint is what
// separates this file from TestInteropV3.cpp: `snmpd` and a switch on the bench answer the interop
// matrix, and neither of them can be told to misbehave.
class InteropFaults : public ::testing::Test {
 protected:
  void SetUp() override {
    const auto address = envVar("SNMPIO_INTEROP_TARGET");
    if (!address || !envVar("SNMPIO_INTEROP_FAULTS")) {
      GTEST_SKIP() << "needs SNMPIO_INTEROP_TARGET and SNMPIO_INTEROP_FAULTS, and an Agent that "
                      "misbehaves on request";
    }
    const auto target = makeInteropTarget(*address, envPort("SNMPIO_INTEROP_PORT"));
    ASSERT_TRUE(target.has_value())
        << "SNMPIO_INTEROP_TARGET/_PORT is not an address and a port: " << *address;
    // No default: the control channel is a web UI, and 161 is not where any of them are -- so a
    // port that did not parse fails here rather than aiming HTTP somewhere and reading the
    // silence as "no Simulator".
    m_controlPort = envPort("SNMPIO_INTEROP_FAULTS", 0);
    ASSERT_NE(m_controlPort, 0) << "SNMPIO_INTEROP_FAULTS is not a port";

    m_target = *target;
    m_password = envVar("SNMPIO_INTEROP_V3_PASSWORD").value_or("");
  }

  // The engine faults are v3's alone, and the two Walk cases below are v2c -- so the password
  // gates only the tests that spend it. Written out at each call site because GTEST_SKIP in a
  // helper skips the helper and lets the test carry on.
  [[nodiscard]] Credentials credentials() const {
    return Credentials{"privsha256aes", SecurityLevel::AuthPriv, AuthProtocol::Sha256,
                       m_password,      PrivProtocol::Aes128,    m_password};
  }

  Target m_target;
  std::uint16_t m_controlPort = 0;
  std::string m_password;
};

// GETs in sequence on one Client, with `between[i]` run after the i-th has completed. The engine
// faults all have this shape: talk once so the Client caches the Engine's state, move the Engine
// under it, talk again. One Client throughout, because the cache the fault invalidates is the
// Client's -- and chained through the completion handlers rather than through separate io_context
// runs, because the Client's receive loop stays outstanding until it is stopped.
std::vector<net::ErrorCode> getSequence(const Target& target, const Credentials& credentials,
                                        const std::vector<std::function<void()>>& between) {
  net::IoContext io;
  Client client(io.get_executor());
  std::vector<net::ErrorCode> results;

  // std::function rather than a recursive lambda: the step has to name itself, and this is the
  // shortest way to let it.
  std::function<void()> step = [&] {
    client.asyncGet(target, credentials, {sysDescr}, [&](net::ErrorCode ec, const Response&) {
      results.push_back(ec);
      if (results.size() > between.size()) {
        client.stop();
        return;
      }
      between[results.size() - 1]();
      step();
    });
  };
  step();
  io.run();
  return results;
}

// Criterion: an Engine restart mid-session recovers. The Client cached a boots/time pair, the
// Engine's boots then jumped past it, and the request that meets the resulting
// usmStatsNotInTimeWindows Report has to resynchronise from it and complete -- not fail, and not
// return the Report to the caller.
//
// That a Client which simply re-discovered before every request would also pass this is not a hole
// here: InteropV3.DiscoveryCostsExtraRoundTripsOnlyOnce is where that is ruled out, off the wire.
TEST_F(InteropFaults, RecoversFromAnEngineRestart) {
  if (m_password.empty()) GTEST_SKIP() << "needs SNMPIO_INTEROP_V3_PASSWORD";
  SimulatorFaults faults(m_target.endpoint, m_controlPort);
  bool bumped = false;
  const auto results =
      getSequence(m_target, credentials(), {[&] { bumped = faults.set("engineBootsBump", "5"); }});

  ASSERT_TRUE(bumped) << "the Simulator did not accept engineBootsBump";
  ASSERT_EQ(results.size(), 2U);
  EXPECT_FALSE(results[0]) << "before the restart: " << results[0].message();
  EXPECT_FALSE(results[1]) << "after the restart: " << results[1].message();
}

// Criterion: a boots/time regression is refused rather than cached. RFC 3414 section 2.2.3 lets a
// cached boots count go up and never down, so an Engine that suddenly reports a lower one is
// either lying or has been replaced -- and a Client that believed it could be walked backwards
// into a replay window by anyone able to forge a Report.
//
// Refusing costs the session, which is the observable part: the Client keeps asking with the
// higher pair the Engine will not accept, and gives up rather than climbing down to meet it. A
// Client with no cache at all still gets in, which is what says the Agent is healthy and it was
// the comparison that refused.
TEST_F(InteropFaults, RefusesABootsRegression) {
  if (m_password.empty()) GTEST_SKIP() << "needs SNMPIO_INTEROP_V3_PASSWORD";
  SimulatorFaults faults(m_target.endpoint, m_controlPort);
  bool bumped = false;
  bool cleared = false;
  const auto results = getSequence(
      m_target, credentials(),
      {[&] { bumped = faults.set("engineBootsBump", "50"); }, [&] { cleared = faults.clear(); }});

  ASSERT_TRUE(bumped) << "the Simulator did not accept engineBootsBump";
  ASSERT_TRUE(cleared) << "the Simulator did not clear its faults";
  ASSERT_EQ(results.size(), 3U);
  EXPECT_FALSE(results[0]) << results[0].message();
  EXPECT_FALSE(results[1]) << "the boots bump did not resynchronise: " << results[1].message();
  // That it failed, rather than which code it failed with: what an Agent does with a request it
  // considers untimely is the Agent's choice, and the Simulator makes a third one -- it does not
  // run the check at all, so it answers with its real pair and there is no Report to name. The
  // pair of assertions is what pins the criterion: this Client refuses, and a Client with nothing
  // cached still gets in, so it was the comparison that refused and not the Agent that died.
  EXPECT_TRUE(results[2]) << "the regression was cached rather than refused";
  EXPECT_FALSE(get(m_target, credentials()).ec)
      << "a Client with an empty cache should still get in";
}

// The other half of the same criterion, and a separate comparison in the Client: within one boot,
// a time that has gone backwards is refused too. Boots alone would leave that path unreached --
// an Engine whose clock jumps without restarting is the ordinary case of the two, since it needs
// nothing more than NTP stepping it.
TEST_F(InteropFaults, RefusesATimeRegressionWithinOneBoot) {
  if (m_password.empty()) GTEST_SKIP() << "needs SNMPIO_INTEROP_V3_PASSWORD";
  SimulatorFaults faults(m_target.endpoint, m_controlPort);
  bool shifted = false;
  bool cleared = false;
  const auto results = getSequence(m_target, credentials(),
                                   {[&] { shifted = faults.set("engineTimeOffsetS", "3000"); },
                                    [&] { cleared = faults.clear(); }});

  ASSERT_TRUE(shifted) << "the Simulator did not accept engineTimeOffsetS";
  ASSERT_TRUE(cleared) << "the Simulator did not clear its faults";
  ASSERT_EQ(results.size(), 3U);
  EXPECT_FALSE(results[0]) << results[0].message();
  EXPECT_FALSE(results[1]) << "the clock jump did not resynchronise: " << results[1].message();
  // Failure, and a fresh Client getting in regardless -- the same pair of assertions, and for the
  // same reason, as RefusesABootsRegression states.
  EXPECT_TRUE(results[2]) << "the clock going back was cached rather than refused";
  EXPECT_FALSE(get(m_target, credentials()).ec)
      << "a Client with an empty cache should still get in";
}

// Criterion: an Engine that changes identity mid-session is re-discovered, and the keys follow it.
//
// Every key this Client holds is localized to an engineID, so an Engine that comes back under a
// different one invalidates all of them at once. What arrives is an unauthenticated
// usmStatsUnknownEngineIDs Report -- the Engine cannot sign a complaint about a key it does not
// have -- carrying the new identity, and the request has to survive that: re-discover, re-derive
// both the authentication and the privacy key against the new engineID, and complete.
//
// At authPriv, because that is what makes the re-derivation observable. A Client that re-discovered
// but reused the localized keys authenticates with a digest the Engine will not accept, which is a
// failure and not a Response.
//
// Gated on its own capability: the fault is newer than the older of the two Simulator images CI
// pins, and an Agent that does not offer it must skip rather than fail for not being asked.
TEST_F(InteropFaults, RediscoversAnEngineThatChangesItsIdentity) {
  if (m_password.empty()) GTEST_SKIP() << "needs SNMPIO_INTEROP_V3_PASSWORD";
  if (!envVar("SNMPIO_INTEROP_FAULTS_ENGINE_ID")) {
    GTEST_SKIP() << "needs SNMPIO_INTEROP_FAULTS_ENGINE_ID and an Agent offering engineIDChange";
  }
  SimulatorFaults faults(m_target.endpoint, m_controlPort);
  bool changed = false;
  const auto results =
      getSequence(m_target, credentials(), {[&] { changed = faults.set("engineIDChange", "on"); }});

  ASSERT_TRUE(changed) << "the Simulator did not accept engineIDChange";
  ASSERT_EQ(results.size(), 2U);
  EXPECT_FALSE(results[0]) << "before the change: " << results[0].message();
  EXPECT_FALSE(results[1]) << "the Engine changed identity and the request did not follow it: "
                           << results[1].message();
}

// Criterion: `tooBig` degrades max-repetitions and the Walk still finishes.
//
// Both halves need the wire. max-repetitions is a number this library picks and revises on its
// own, so the relay is the only place its degradation is visible; and the Simulator's `tooBig` is
// unconditional, so the Walk can only go on to finish if the fault is turned off partway -- which
// the relay can do at the exact request that proves the degradation, instead of after a sleep long
// enough to hope.
TEST_F(InteropFaults, DegradesMaxRepetitionsWhenTheAgentSaysTooBig) {
  SimulatorFaults faults(m_target.endpoint, m_controlPort);
  ASSERT_TRUE(faults.set("tooBig", "on"));

  net::IoContext io;
  std::vector<std::int32_t> asked;
  bool cleared = false;
  CountingRelay relay(io, m_target.endpoint, [&](std::span<const std::byte> datagram) {
    net::ErrorCode ec;
    const auto msg = decodeV2cMessage(datagram, ec);
    if (!msg || msg->pdu.type != PduType::GetBulk) return;
    asked.push_back(msg->pdu.maxRepetitions());
    // A blocking HTTP round trip from inside the receive handler, which stalls this io_context for
    // as long as loopback takes to answer -- microseconds against a Target timeout in seconds. The
    // alternative is an asynchronous clear that lands at no particular point in the exchange,
    // which is the one thing this has to be exact about.
    if (!cleared && asked.size() > 1 && asked.back() < asked.front()) cleared = faults.clear();
  });

  Target target = m_target;
  target.endpoint = relay.endpoint();
  Client client(io.get_executor());
  net::ErrorCode walkEc;
  std::vector<Varbind> rows;

  client.asyncWalkCollect(target, Community("public"), systemTree, WalkOptions{},
                          [&](net::ErrorCode ec, std::vector<Varbind> collected) {
                            walkEc = ec;
                            rows = std::move(collected);
                            client.stop();
                            relay.close();
                          });
  io.run();

  ASSERT_TRUE(cleared) << "the Walk never asked for less: max-repetitions stayed put";
  ASSERT_GE(asked.size(), 2U);
  EXPECT_LT(asked[1], asked[0]) << "tooBig did not shrink max-repetitions";
  EXPECT_FALSE(walkEc) << "the Walk did not finish once the Agent stopped saying tooBig: "
                       << walkEc.message();
  EXPECT_FALSE(rows.empty());
}

// Criterion: a non-increasing OID fails the Walk rather than looping. The Simulator echoes the
// requested OID straight back, which is the shape of the bug ADR-0004's guard exists for -- an
// unguarded Walk asks the same question for ever and never returns at all, so a Walk that returns
// an error here is the whole of the test.
TEST_F(InteropFaults, FailsAWalkOnANonIncreasingOid) {
  SimulatorFaults faults(m_target.endpoint, m_controlPort);
  ASSERT_TRUE(faults.set("nonIncreasingOID", "on"));

  net::IoContext io;
  Client client(io.get_executor());
  net::ErrorCode walkEc;

  client.asyncWalkCollect(m_target, Community("public"), systemTree, WalkOptions{},
                          [&](net::ErrorCode ec, const std::vector<Varbind>&) {
                            walkEc = ec;
                            client.stop();
                          });
  io.run();

  EXPECT_EQ(walkEc, make_error_code(Errc::NonIncreasingOid)) << walkEc.message();
}

// Criterion: malformed BER is dropped, leaving the request outstanding until it times out.
//
// Timeout rather than a decode error, and the difference is the point: a datagram that does not
// decode says nothing about whether the Response we are waiting for is still coming, so the only
// safe reading of it is that nothing arrived. Surfacing Errc::Truncated here would let anyone able
// to send this Client a single junk datagram end a request it had no part in.
//
// At v2c, and through the relay, because a Timeout on its own is no evidence at all -- an Agent
// that was never reached times out identically. v2c so the truncated datagram is the Response to
// the one request there is rather than to a Discovery exchange, and the relay so the test can say
// that a datagram did arrive and was discarded.
TEST_F(InteropFaults, DropsMalformedBerAndTimesOut) {
  SimulatorFaults faults(m_target.endpoint, m_controlPort);
  ASSERT_TRUE(faults.set("truncateBytes", "16"));

  net::IoContext io;
  CountingRelay relay(io, m_target.endpoint);
  Target target = m_target;
  target.endpoint = relay.endpoint();
  // Not the interop harness's patient 5 seconds: this exchange is meant to expire, so the wait is
  // the test's cost rather than its tolerance.
  target.timeout = std::chrono::milliseconds(750);
  target.retries = 0;

  Client client(io.get_executor());
  net::ErrorCode ec;
  client.asyncGet(target, Community("public"), {sysDescr}, [&](net::ErrorCode e, const Response&) {
    ec = e;
    client.stop();
    relay.close();
  });
  io.run();

  EXPECT_EQ(ec, make_error_code(Errc::Timeout))
      << "an undecodable Response must leave the request outstanding, not fail it: "
      << ec.message();
  EXPECT_GT(relay.datagramsFromTarget(), 0)
      << "the Agent never answered, so nothing was there to drop";
}

}  // namespace
}  // namespace snmpio
