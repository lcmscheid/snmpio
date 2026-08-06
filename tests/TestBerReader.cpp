#include <gtest/gtest.h>

#include <array>

#include <snmpio/ber/Reader.hpp>

#include "Bytes.hpp"

namespace snmpio::ber {
namespace {

using test::bytes;

// Asserts that decoding `input` with `decode` fails with exactly `expected`.
#define EXPECT_DECODE_FAILS(input, expected, decode)                        \
  do {                                                                      \
    const auto m_buf = (input);                                             \
    Reader r(m_buf);                                                        \
    decode;                                                                 \
    EXPECT_FALSE(r.ok());                                                   \
    EXPECT_EQ(r.error(), make_error_code(expected)) << r.error().message(); \
  } while (false)

TEST(ReaderHeader, ShortAndLongFormLengths) {
  {
    const auto buf = bytes({0x04, 0x03, 'a', 'b', 'c'});
    Reader r(buf);
    const auto h = r.readHeader();
    ASSERT_TRUE(h.has_value());
    EXPECT_EQ(h->tag, tag::octetString);
    EXPECT_EQ(h->length, 3U);
  }
  {
    // 0x81 0x80: long form, one length octet, Value 128.
    std::vector<std::byte> buf = bytes({0x04, 0x81, 0x80});
    buf.resize(3 + 128, std::byte{0});
    Reader r(buf);
    const auto h = r.readHeader();
    ASSERT_TRUE(h.has_value());
    EXPECT_EQ(h->length, 128U);
  }
}

TEST(ReaderHeader, AcceptsNonMinimalLongForm) {
  // 0x82 0x00 0x03 says "three" the long way. BER permits it and agents emit it; DER would not.
  const auto buf = bytes({0x04, 0x82, 0x00, 0x03, 'a', 'b', 'c'});
  Reader r(buf);
  const auto v = r.octetString();
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->size(), 3U);
  EXPECT_TRUE(r.finish());
}

TEST(ReaderHeader, RejectsIndefiniteLength) {
  EXPECT_DECODE_FAILS(bytes({0x30, 0x80, 0x05, 0x00, 0x00, 0x00}), Errc::IndefiniteLength,
                      (void)r.readHeader());
}

TEST(ReaderHeader, RejectsReservedLengthOctet) {
  EXPECT_DECODE_FAILS(bytes({0x04, 0xFF, 0x00}), Errc::ReservedLength, (void)r.readHeader());
}

TEST(ReaderHeader, RejectsHighTagNumberForm) {
  EXPECT_DECODE_FAILS(bytes({0x1F, 0x81, 0x00, 0x00}), Errc::HighTagNumber, (void)r.readHeader());
}

TEST(ReaderHeader, RejectsLengthBeyondInput) {
  EXPECT_DECODE_FAILS(bytes({0x04, 0x05, 'a', 'b'}), Errc::Truncated, (void)r.readHeader());
}

TEST(ReaderHeader, RejectsOverwideLengthField) {
  EXPECT_DECODE_FAILS(bytes({0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00}), Errc::LengthTooLarge,
                      (void)r.readHeader());
}

TEST(ReaderHeader, RejectsHeaderCutInHalf) {
  EXPECT_DECODE_FAILS(bytes({0x04}), Errc::Truncated, (void)r.readHeader());
  EXPECT_DECODE_FAILS(bytes({}), Errc::Truncated, (void)r.readHeader());
}

TEST(ReaderInteger, DecodesMinimalForms) {
  struct Case {
    std::vector<std::byte> encoding;
    std::int32_t expected;
  };
  const auto cases = std::to_array<Case>({
      {bytes({0x02, 0x01, 0x00}), 0},
      {bytes({0x02, 0x01, 0x7F}), 127},
      {bytes({0x02, 0x02, 0x00, 0x80}), 128},
      {bytes({0x02, 0x01, 0xFF}), -1},
      {bytes({0x02, 0x01, 0x80}), -128},
      {bytes({0x02, 0x02, 0xFF, 0x7F}), -129},
      {bytes({0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF}), 2147483647},
      {bytes({0x02, 0x04, 0x80, 0x00, 0x00, 0x00}), -2147483647 - 1},
  });
  for (const auto& c : cases) {
    Reader r(c.encoding);
    const auto v = r.integer();
    ASSERT_TRUE(v.has_value()) << test::hex(c.encoding) << ": " << r.error().message();
    EXPECT_EQ(*v, c.expected) << test::hex(c.encoding);
  }
}

TEST(ReaderInteger, ToleratesRedundantSignPadding) {
  // Non-minimal, and therefore not strictly legal, but real agents emit it and there is nothing
  // ambiguous about it. Being strict here would buy nothing and cost interop.
  {
    const auto buf = bytes({0x02, 0x04, 0x00, 0x00, 0x00, 0x05});
    Reader r(buf);
    EXPECT_EQ(r.integer(), 5);
  }
  {
    const auto buf = bytes({0x02, 0x03, 0xFF, 0xFF, 0xFB});
    Reader r(buf);
    EXPECT_EQ(r.integer(), -5);
  }
}

TEST(ReaderInteger, RejectsEmptyAndOversized) {
  EXPECT_DECODE_FAILS(bytes({0x02, 0x00}), Errc::EmptyContent, (void)r.integer());
  // Five significant Octets cannot be an Integer32 whichever way you read them.
  EXPECT_DECODE_FAILS(bytes({0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00}), Errc::IntegerTooLarge,
                      (void)r.integer());
  // 2^31 does not fit an Integer32, however non-negative it looks.
  EXPECT_DECODE_FAILS(bytes({0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00}), Errc::IntegerTooLarge,
                      (void)r.integer());
}

TEST(ReaderInteger, RejectsWrongTag) {
  EXPECT_DECODE_FAILS(bytes({0x41, 0x01, 0x05}), Errc::UnexpectedTag, (void)r.integer());
}

TEST(ReaderUnsigned, AcceptsBothEncodingsOfTheHighHalf) {
  // 0xFFFFFFFF is correctly encoded with a leading zero, because Counter32 is an ASN.1 INTEGER
  // constrained to be non-negative. Many agents skip the zero. Both must decode to the same Value.
  {
    const auto buf = bytes({0x41, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF});
    Reader r(buf);
    EXPECT_EQ(r.unsigned32(tag::counter32), 4294967295U);
  }
  {
    const auto buf = bytes({0x41, 0x04, 0xFF, 0xFF, 0xFF, 0xFF});
    Reader r(buf);
    EXPECT_EQ(r.unsigned32(tag::counter32), 4294967295U);
  }
}

TEST(ReaderUnsigned, DecodesGaugeAndTimeticks) {
  const auto gauge = bytes({0x42, 0x02, 0x01, 0x00});
  Reader rg(gauge);
  EXPECT_EQ(rg.unsigned32(tag::gauge32), 256U);

  const auto ticks = bytes({0x43, 0x01, 0x00});
  Reader rt(ticks);
  EXPECT_EQ(rt.unsigned32(tag::timeticks), 0U);
}

TEST(ReaderUnsigned, RejectsOversized) {
  EXPECT_DECODE_FAILS(bytes({0x41, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00}), Errc::IntegerTooLarge,
                      (void)r.unsigned32(tag::counter32));
  EXPECT_DECODE_FAILS(bytes({0x41, 0x00}), Errc::EmptyContent, (void)r.unsigned32(tag::counter32));
}

TEST(ReaderUnsigned, Counter64FullRange) {
  const auto buf = bytes({0x46, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
  Reader r(buf);
  EXPECT_EQ(r.unsigned64(tag::counter64), 18446744073709551615ULL);
}

TEST(ReaderOid, DecodesTheCanonicalExample) {
  // 1.3.6.1.2.1.1.3.0 -- sysUpTime.0, the OID this library will send more than any other.
  const auto buf = bytes({0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00});
  Reader r(buf);
  const auto o = r.objectIdentifier();
  ASSERT_TRUE(o.has_value()) << r.error().message();
  EXPECT_EQ(*o, *Oid::parse("1.3.6.1.2.1.1.3.0"));
  EXPECT_TRUE(r.finish());
}

TEST(ReaderOid, UnpacksAllThreeFirstArcRanges) {
  const auto zero = bytes({0x06, 0x01, 0x27});  // 39 -> 0.39
  Reader r0(zero);
  EXPECT_EQ(r0.objectIdentifier(), Oid::parse("0.39"));

  const auto one = bytes({0x06, 0x01, 0x4F});  // 79 -> 1.39
  Reader r1(one);
  EXPECT_EQ(r1.objectIdentifier(), Oid::parse("1.39"));

  const auto two = bytes({0x06, 0x01, 0x50});  // 80 -> 2.0
  Reader r2(two);
  EXPECT_EQ(r2.objectIdentifier(), Oid::parse("2.0"));
}

TEST(ReaderOid, DecodesMultiOctetSubidentifiers) {
  // 0x87 0xFF 0xFF 0xFF 0x7F is 4294967295, the largest sub-identifier that fits.
  const auto buf = bytes({0x06, 0x06, 0x2B, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F});
  Reader r(buf);
  const auto o = r.objectIdentifier();
  ASSERT_TRUE(o.has_value()) << r.error().message();
  EXPECT_EQ(*o, *Oid::parse("1.3.4294967295"));
}

TEST(ReaderOid, RejectsSubidentifierOverflow) {
  // One bit past 2^32-1.
  EXPECT_DECODE_FAILS(bytes({0x06, 0x06, 0x2B, 0x90, 0x80, 0x80, 0x80, 0x00}),
                      Errc::OidSubidOverflow, (void)r.objectIdentifier());
}

TEST(ReaderOid, RejectsNonMinimalSubidentifier) {
  // A leading 0x80 contributes seven zero bits and nothing else -- unambiguously malformed.
  EXPECT_DECODE_FAILS(bytes({0x06, 0x03, 0x2B, 0x80, 0x01}), Errc::OidNonMinimal,
                      (void)r.objectIdentifier());
}

TEST(ReaderOid, RejectsTruncatedSubidentifier) {
  EXPECT_DECODE_FAILS(bytes({0x06, 0x02, 0x2B, 0x81}), Errc::OidTruncatedSubid,
                      (void)r.objectIdentifier());
}

TEST(ReaderOid, RejectsEmptyContent) {
  EXPECT_DECODE_FAILS(bytes({0x06, 0x00}), Errc::OidEmpty, (void)r.objectIdentifier());
}

TEST(ReaderOid, RejectsMoreThan128Subidentifiers) {
  // 0x2B unpacks to two arcs, then 127 more single-octet arcs makes 129.
  std::vector<std::byte> content;
  content.push_back(std::byte{0x2B});
  for (int i = 0; i < 127; ++i) content.push_back(std::byte{0x01});
  ASSERT_EQ(content.size(), 128U);
  std::vector<std::byte> buf = bytes({0x06, 0x81, 0x80});  // long form: a bare 0x80 is indefinite
  buf.insert(buf.end(), content.begin(), content.end());
  Reader r(buf);
  EXPECT_FALSE(r.objectIdentifier().has_value());
  EXPECT_EQ(r.error(), make_error_code(Errc::OidTooLong));
}

TEST(ReaderNull, RejectsContentBearingNull) {
  EXPECT_DECODE_FAILS(bytes({0x05, 0x01, 0x00}), Errc::BadNull, (void)r.nullValue());
  const auto good = bytes({0x05, 0x00});
  Reader r(good);
  EXPECT_TRUE(r.nullValue());
}

TEST(ReaderValue, DecodesIpAddress) {
  const auto buf = bytes({0x40, 0x04, 0x0A, 0x00, 0x00, 0x01});
  Reader r(buf);
  const auto v = r.anyValue();
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(toString(*v), "10.0.0.1");
}

TEST(ReaderValue, RejectsMisSizedIpAddress) {
  EXPECT_DECODE_FAILS(bytes({0x40, 0x03, 0x0A, 0x00, 0x01}), Errc::BadIpAddress,
                      (void)r.anyValue());
}

TEST(ReaderValue, DecodesTheThreeExceptions) {
  struct Case {
    int tag;
    ValueException expected;
  };
  const auto cases = std::to_array<Case>({
      {0x80, ValueException::NoSuchObject},
      {0x81, ValueException::NoSuchInstance},
      {0x82, ValueException::EndOfMibView},
  });
  for (const auto& c : cases) {
    const auto buf = bytes({c.tag, 0x00});
    Reader r(buf);
    const auto v = r.anyValue();
    ASSERT_TRUE(v.has_value()) << r.error().message();
    ASSERT_TRUE(isException(*v));
    EXPECT_EQ(std::get<ValueException>(*v), c.expected);
  }
}

TEST(ReaderValue, RejectsUnknownTag) {
  EXPECT_DECODE_FAILS(bytes({0x45, 0x01, 0x00}), Errc::UnknownValueTag, (void)r.anyValue());
}

TEST(ReaderScope, ClampsReadsToTheEnclosingElement) {
  // The inner SEQUENCE claims two Octets. The INTEGER that follows it is outside, so a read
  // attempted while still inside the Scope must not reach it.
  const auto buf = bytes({0x30, 0x03, 0x02, 0x01, 0x07, 0x05, 0x00});
  Reader r(buf);
  {
    auto s = r.enter(tag::sequence);
    EXPECT_EQ(r.integer(), 7);
    EXPECT_TRUE(r.atEnd()) << "the NULL is outside this Scope";
  }
  EXPECT_TRUE(r.ok());
  EXPECT_TRUE(r.nullValue());
  EXPECT_TRUE(r.finish());
}

TEST(ReaderScope, FlagsUnconsumedContent) {
  const auto buf = bytes({0x30, 0x06, 0x02, 0x01, 0x07, 0x02, 0x01, 0x08});
  Reader r(buf);
  {
    auto s = r.enter(tag::sequence);
    EXPECT_EQ(r.integer(), 7);
    // The second INTEGER is left unread on purpose.
  }
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.error(), make_error_code(Errc::TrailingData));
}

TEST(ReaderScope, RejectsAPrimitiveWhereAConstructedWasExpected) {
  const auto buf = bytes({0x04, 0x01, 0x00});
  Reader r(buf);
  {
    auto s = r.enter(tag::sequence);
    EXPECT_FALSE(r.ok());
  }
  EXPECT_EQ(r.error(), make_error_code(Errc::UnexpectedTag));
}

TEST(ReaderError, IsStickyAndSuppressesLaterReads) {
  // The contract that lets a decoder be a straight run of reads with one check at the end.
  const auto buf = bytes({0x02, 0x00, 0x02, 0x01, 0x07});
  Reader r(buf);
  EXPECT_FALSE(r.integer().has_value());
  const auto first = r.error();
  EXPECT_EQ(first, make_error_code(Errc::EmptyContent));
  EXPECT_FALSE(r.integer().has_value()) << "a later read must not succeed past a failure";
  EXPECT_EQ(r.error(), first) << "the first error is the one that is kept";
  EXPECT_FALSE(r.finish());
}

TEST(ReaderVarbind, DecodesOneVarbind) {
  // 1.3.6.1.2.1.1.3.0 = TimeTicks 12345
  const auto buf = bytes({0x30, 0x10,                                                  //
                          0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00,  //
                          0x43, 0x04, 0x00, 0x00, 0x30, 0x39});
  Reader r(buf);
  const auto vb = r.readVarbind();
  ASSERT_TRUE(vb.has_value()) << r.error().message();
  EXPECT_EQ(vb->name, *Oid::parse("1.3.6.1.2.1.1.3.0"));
  ASSERT_TRUE(std::holds_alternative<TimeTicks>(vb->val));
  EXPECT_EQ(std::get<TimeTicks>(vb->val).value, 12345U);
  EXPECT_TRUE(r.finish());
}

TEST(ReaderVarbind, DecodesAList) {
  const auto buf = bytes({0x30, 0x0C,                                // VarBindList
                          0x30, 0x05, 0x06, 0x01, 0x2B, 0x05, 0x00,  // 1.3 = NULL
                          0x30, 0x03, 0x06, 0x01, 0x2B});            // an OID and no Value
  Reader r(buf);
  // The second Varbind holds a name but no Value. The Scope bound stops the Value read from
  // running on into whatever follows the Varbind, so this is a clean failure rather than a
  // Varbind that silently borrows the next element's bytes.
  EXPECT_FALSE(r.varbindList().has_value());
  EXPECT_FALSE(r.ok());
}

TEST(ReaderVarbind, DecodesAWellFormedList) {
  const auto buf = bytes({0x30, 0x0E,                                  //
                          0x30, 0x05, 0x06, 0x01, 0x2B, 0x05, 0x00,    // 1.3 = NULL
                          0x30, 0x05, 0x06, 0x01, 0x2C, 0x05, 0x00});  // 1.4 = NULL
  Reader r(buf);
  const auto vbs = r.varbindList();
  ASSERT_TRUE(vbs.has_value()) << r.error().message();
  ASSERT_EQ(vbs->size(), 2U);
  EXPECT_EQ((*vbs)[0].name, *Oid::parse("1.3"));
  EXPECT_EQ((*vbs)[1].name, *Oid::parse("1.4"));
  EXPECT_TRUE(r.finish());
}

TEST(ReaderVarbind, EmptyListIsValid) {
  const auto buf = bytes({0x30, 0x00});
  Reader r(buf);
  const auto vbs = r.varbindList();
  ASSERT_TRUE(vbs.has_value());
  EXPECT_TRUE(vbs->empty());
}

TEST(ReaderSkip, SkipsAnElementWhole) {
  const auto buf = bytes({0x30, 0x03, 0x02, 0x01, 0x07, 0x05, 0x00});
  Reader r(buf);
  const auto skipped = r.skipElement();
  ASSERT_TRUE(skipped.has_value());
  EXPECT_EQ(skipped->size(), 5U);
  EXPECT_TRUE(r.nullValue());
  EXPECT_TRUE(r.finish());
}

}  // namespace
}  // namespace snmpio::ber
