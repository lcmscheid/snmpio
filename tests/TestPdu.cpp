#include <gtest/gtest.h>

#include <snmpio/Pdu.hpp>

#include "Bytes.hpp"

namespace snmpio {
namespace {

using test::bytes;

const Oid sysUpTime{1, 3, 6, 1, 2, 1, 1, 3, 0};

// A GET of sysUpTime.0 with community "public" and request-id 1 -- the first packet of every
// SNMP capture ever taken, byte for byte.
std::vector<std::byte> goldenGet() {
  return bytes({
      0x30, 0x26,                                                  // SEQUENCE, 38 content Octets
      0x02, 0x01, 0x01,                                            // version 1, i.e. SNMPv2c
      0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,              // "public"
      0xA0, 0x19,                                                  // GetRequest-PDU
      0x02, 0x01, 0x01,                                            // request-id 1
      0x02, 0x01, 0x00,                                            // error-status noError
      0x02, 0x01, 0x00,                                            // error-index 0
      0x30, 0x0E,                                                  // VarBindList
      0x30, 0x0C,                                                  // VarBind
      0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00,  // 1.3.6.1.2.1.1.3.0
      0x05, 0x00,                                                  // NULL
  });
}

TEST(V2cMessage, EncodesTheCanonicalGet) {
  Pdu pdu;
  pdu.type = PduType::Get;
  pdu.requestId = 1;
  pdu.varbinds = {Varbind{sysUpTime, null}};

  net::ErrorCode ec;
  EXPECT_EQ(encodeV2cMessage("public", pdu, ec), goldenGet());
  EXPECT_FALSE(ec) << ec.message();
}

TEST(V2cMessage, DecodesTheCanonicalGet) {
  net::ErrorCode ec;
  const auto msg = decodeV2cMessage(goldenGet(), ec);
  ASSERT_TRUE(msg) << ec.message();
  EXPECT_EQ(msg->community, "public");
  EXPECT_EQ(msg->pdu.type, PduType::Get);
  EXPECT_EQ(msg->pdu.requestId, 1);
  EXPECT_EQ(msg->pdu.errorStatus, 0);
  ASSERT_EQ(msg->pdu.varbinds.size(), 1U);
  EXPECT_EQ(msg->pdu.varbinds[0].name, sysUpTime);
  EXPECT_TRUE(std::holds_alternative<NullType>(msg->pdu.varbinds[0].val));
}

TEST(V2cMessage, RoundTripsEveryPduTypeAndAnAgentErrorStatus) {
  for (const auto type : {PduType::Get, PduType::GetNext, PduType::GetBulk, PduType::Set,
                          PduType::Response, PduType::Report}) {
    Pdu pdu;
    pdu.type = type;
    pdu.requestId = 0x7FFFFFFF;
    pdu.errorStatus = static_cast<std::int32_t>(ErrorStatus::TooBig);
    pdu.errorIndex = 2;
    pdu.varbinds = {Varbind{sysUpTime, TimeTicks{12345}},
                    Varbind{Oid{1, 3, 6, 1, 2, 1, 1, 5, 0}, ValueException::NoSuchInstance}};

    net::ErrorCode ec;
    const auto wire = encodeV2cMessage("private", pdu, ec);
    ASSERT_FALSE(ec) << ec.message();
    const auto back = decodeV2cMessage(wire, ec);
    ASSERT_TRUE(back) << ec.message();
    EXPECT_EQ(back->community, "private");
    EXPECT_EQ(back->pdu.type, type);
    EXPECT_EQ(back->pdu.requestId, pdu.requestId);
    EXPECT_EQ(back->pdu.errorStatus, pdu.errorStatus);
    EXPECT_EQ(back->pdu.errorIndex, pdu.errorIndex);
    EXPECT_EQ(back->pdu.varbinds, pdu.varbinds);
  }
}

TEST(Pdu, GetBulkReusesErrorStatusAndErrorIndex) {
  // RFC 3416 section 4.2.3: same two INTEGERs in the same two positions, different names. If the
  // aliasing ever stops holding, a GETBULK silently asks for the wrong repetitions.
  Pdu pdu;
  pdu.type = PduType::GetBulk;
  pdu.setBulkParams(1, 25);
  EXPECT_EQ(pdu.nonRepeaters(), 1);
  EXPECT_EQ(pdu.maxRepetitions(), 25);
  EXPECT_EQ(pdu.errorStatus, 1);
  EXPECT_EQ(pdu.errorIndex, 25);
}

TEST(V2cMessage, RejectsAVersionItDoesNotSpeak) {
  auto wire = goldenGet();
  wire[4] = std::byte{0x03};  // SNMPv3 framing is not this decoder's job
  net::ErrorCode ec;
  EXPECT_FALSE(decodeV2cMessage(wire, ec));
  EXPECT_EQ(ec, Errc::BadVersion);
}

TEST(V2cMessage, RejectsSomethingThatIsNotAPduWhereThePduBelongs) {
  auto wire = goldenGet();
  wire[13] = std::byte{0x30};  // a plain SEQUENCE, not a PDU tag
  net::ErrorCode ec;
  EXPECT_FALSE(decodeV2cMessage(wire, ec));
  EXPECT_EQ(ec, Errc::UnexpectedPduType);
}

TEST(V2cMessage, RejectsTruncationAtEveryOffset) {
  // Every prefix of a valid message is an invalid message. Datagrams get truncated in the wild.
  const auto full = goldenGet();
  for (std::size_t n = 0; n < full.size(); ++n) {
    net::ErrorCode ec;
    EXPECT_FALSE(decodeV2cMessage(std::span(full).first(n), ec)) << "prefix of length " << n;
    EXPECT_TRUE(ec) << "prefix of length " << n;
  }
}

TEST(V2cMessage, RejectsTrailingBytesAfterTheMessage) {
  auto wire = goldenGet();
  wire.push_back(std::byte{0x00});
  net::ErrorCode ec;
  EXPECT_FALSE(decodeV2cMessage(wire, ec));
  EXPECT_EQ(ec, Errc::TrailingData);
}

TEST(AgentErrorStatus, ConvertsToAnErrorCodeCarryingTheWireNumber) {
  const net::ErrorCode ec = make_error_code(ErrorStatus::InconsistentName);
  EXPECT_EQ(ec.value(), 18);
  EXPECT_EQ(ec, ErrorStatus::InconsistentName);
  EXPECT_NE(ec, ErrorStatus::TooBig);
  // Distinct categories, so the Agent's number 2 is never mistaken for one of ours.
  EXPECT_NE(ec.category(), errorCategory());
  EXPECT_FALSE(ec.message().empty());

  EXPECT_FALSE(make_error_code(ErrorStatus::NoError));
}

}  // namespace
}  // namespace snmpio
