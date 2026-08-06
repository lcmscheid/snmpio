#include <gtest/gtest.h>

#include <array>

#include <snmpio/ber/Reader.hpp>
#include <snmpio/ber/Writer.hpp>

#include "Bytes.hpp"

namespace snmpio::ber {
namespace {

using test::bytes;

std::vector<std::byte> encoded(const Value& v) {
  Writer w;
  w.write(v);
  EXPECT_TRUE(w.ok()) << w.error().message();
  return w.take();
}

TEST(WriterInteger, EmitsMinimalTwosComplement) {
  struct Case {
    std::int32_t input;
    std::vector<std::byte> expected;
  };
  const auto cases = std::to_array<Case>({
      {0, bytes({0x02, 0x01, 0x00})},
      {127, bytes({0x02, 0x01, 0x7F})},
      {128, bytes({0x02, 0x02, 0x00, 0x80})},
      {255, bytes({0x02, 0x02, 0x00, 0xFF})},
      {256, bytes({0x02, 0x02, 0x01, 0x00})},
      {-1, bytes({0x02, 0x01, 0xFF})},
      {-128, bytes({0x02, 0x01, 0x80})},
      {-129, bytes({0x02, 0x02, 0xFF, 0x7F})},
      {2147483647, bytes({0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF})},
      {-2147483647 - 1, bytes({0x02, 0x04, 0x80, 0x00, 0x00, 0x00})},
  });
  for (const auto& c : cases) {
    Writer w;
    w.integer(c.input);
    EXPECT_EQ(w.take(), c.expected) << "input " << c.input;
  }
}

TEST(WriterUnsigned, KeepsTheLeadingZeroWhenTheHighBitIsSet) {
  // Counter32/Gauge32/TimeTicks are non-negative, so anything from 0x80000000 up needs the pad
  // octet or it would read back as a negative INTEGER.
  Writer w;
  w.unsigned32(4294967295U, tag::counter32);
  EXPECT_EQ(w.take(), bytes({0x41, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}));

  Writer w2;
  w2.unsigned32(0, tag::timeticks);
  EXPECT_EQ(w2.take(), bytes({0x43, 0x01, 0x00}));

  Writer w3;
  w3.unsigned32(128, tag::gauge32);
  EXPECT_EQ(w3.take(), bytes({0x42, 0x02, 0x00, 0x80}));
}

TEST(WriterUnsigned, Counter64) {
  Writer w;
  w.unsigned64(18446744073709551615ULL, tag::counter64);
  EXPECT_EQ(w.take(), bytes({0x46, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));
}

TEST(WriterOid, EmitsTheCanonicalExample) {
  Writer w;
  w.objectIdentifier(*Oid::parse("1.3.6.1.2.1.1.3.0"));
  EXPECT_EQ(w.take(), bytes({0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00}));
}

TEST(WriterOid, PacksTheFirstTwoArcs) {
  Writer w0;
  w0.objectIdentifier(*Oid::parse("0.39"));
  EXPECT_EQ(w0.take(), bytes({0x06, 0x01, 0x27}));

  Writer w1;
  w1.objectIdentifier(*Oid::parse("1.39"));
  EXPECT_EQ(w1.take(), bytes({0x06, 0x01, 0x4F}));

  Writer w2;
  w2.objectIdentifier(*Oid::parse("2.0"));
  EXPECT_EQ(w2.take(), bytes({0x06, 0x01, 0x50}));
}

TEST(WriterOid, EmitsBase128ForLargeSubidentifiers) {
  Writer w;
  w.objectIdentifier(*Oid::parse("1.3.4294967295"));
  EXPECT_EQ(w.take(), bytes({0x06, 0x06, 0x2B, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F}));
}

TEST(WriterOid, RefusesUnencodableOids) {
  for (const char* text : {"1", "3.1", "1.40"}) {
    Writer w;
    w.objectIdentifier(*Oid::parse(text));
    EXPECT_FALSE(w.ok()) << text;
    EXPECT_EQ(w.error(), make_error_code(Errc::OidNotEncodable)) << text;
  }
}

TEST(WriterOid, SizePredictionMatchesTheEncoding) {
  for (const char* text : {"1.3", "1.3.6.1.2.1.1.3.0", "1.3.4294967295", "2.999"}) {
    const auto o = *Oid::parse(text);
    Writer w;
    w.objectIdentifier(o);
    EXPECT_EQ(encodedOidSize(o), w.size()) << text;
  }
  EXPECT_EQ(encodedOidSize(*Oid::parse("1")), 0U) << "unencodable reports zero";
}

TEST(WriterScope, PatchesShortFormLengths) {
  Writer w;
  {
    auto s = w.beginSequence();
    w.integer(7);
  }
  EXPECT_EQ(w.take(), bytes({0x30, 0x03, 0x02, 0x01, 0x07}));
}

TEST(WriterScope, WidensThePlaceholderWhenContentExceeds127Octets) {
  // The case the patch-in-place trick exists for: the one-octet placeholder is not enough and
  // everything after it has to shift.
  Writer w;
  const std::vector<std::byte> payload(200, std::byte{0xAB});
  {
    auto s = w.beginSequence();
    w.octetString(payload);
  }
  const auto out = w.take();
  ASSERT_EQ(out.size(), 3U + 3U + 200U);
  EXPECT_EQ(out[0], std::byte{0x30});
  EXPECT_EQ(out[1], std::byte{0x81}) << "long form, one length octet";
  EXPECT_EQ(out[2], std::byte{0xCB}) << "203 = 200 payload + the inner 3-octet Header";
  EXPECT_EQ(out[3], std::byte{0x04}) << "the OCTET STRING tag survived the shift";

  Reader r(out);
  {
    auto s = r.enter(tag::sequence);
    const auto v = r.octetString();
    ASSERT_TRUE(v.has_value()) << r.error().message();
    EXPECT_EQ(v->size(), 200U);
  }
  EXPECT_TRUE(r.finish());
}

TEST(WriterScope, NestsSeveralDeep) {
  Writer w;
  {
    auto outer = w.beginSequence();
    {
      auto middle = w.beginSequence();
      {
        auto inner = w.beginSequence();
        w.integer(1);
      }
    }
  }
  EXPECT_EQ(w.take(), bytes({0x30, 0x07, 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01}));
}

TEST(WriterScope, RejectsAPrimitiveTag) {
  Writer w;
  {
    auto s = w.beginConstructed(tag::octetString);
  }
  EXPECT_FALSE(w.ok());
  EXPECT_EQ(w.error(), make_error_code(Errc::UnexpectedTag));
}

TEST(WriterValue, EncodesEveryAlternative) {
  EXPECT_EQ(encoded(Value{null}), bytes({0x05, 0x00}));
  EXPECT_EQ(encoded(Value{std::int32_t{-1}}), bytes({0x02, 0x01, 0xFF}));
  EXPECT_EQ(encoded(Value{Octets{std::byte{'h'}, std::byte{'i'}}}), bytes({0x04, 0x02, 'h', 'i'}));
  EXPECT_EQ(encoded(Value{*Oid::parse("1.3")}), bytes({0x06, 0x01, 0x2B}));
  EXPECT_EQ(encoded(Value{IpAddress{{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{1}}}}),
            bytes({0x40, 0x04, 0x0A, 0x00, 0x00, 0x01}));
  EXPECT_EQ(encoded(Value{Counter32{1}}), bytes({0x41, 0x01, 0x01}));
  EXPECT_EQ(encoded(Value{Gauge32{1}}), bytes({0x42, 0x01, 0x01}));
  EXPECT_EQ(encoded(Value{TimeTicks{1}}), bytes({0x43, 0x01, 0x01}));
  EXPECT_EQ(encoded(Value{Opaque{Octets{std::byte{0x9F}}}}), bytes({0x44, 0x01, 0x9F}));
  EXPECT_EQ(encoded(Value{Counter64{1}}), bytes({0x46, 0x01, 0x01}));
  EXPECT_EQ(encoded(Value{ValueException::NoSuchObject}), bytes({0x80, 0x00}));
  EXPECT_EQ(encoded(Value{ValueException::NoSuchInstance}), bytes({0x81, 0x00}));
  EXPECT_EQ(encoded(Value{ValueException::EndOfMibView}), bytes({0x82, 0x00}));
}

TEST(WriterVarbind, EncodesNameAndValue) {
  Writer w;
  w.write(Varbind{*Oid::parse("1.3.6.1.2.1.1.3.0"), Value{TimeTicks{12345}}});
  EXPECT_EQ(w.take(), bytes({0x30, 0x0E,                                                  //
                             0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00,  //
                             0x43, 0x02, 0x30, 0x39}));
}

TEST(WriterVarbind, EncodesAList) {
  const auto vbs = std::to_array<Varbind>({
      {*Oid::parse("1.3"), Value{null}},
      {*Oid::parse("1.4"), Value{null}},
  });
  Writer w;
  w.varbindList(vbs);
  EXPECT_EQ(w.take(), bytes({0x30, 0x0E,                                //
                             0x30, 0x05, 0x06, 0x01, 0x2B, 0x05, 0x00,  //
                             0x30, 0x05, 0x06, 0x01, 0x2C, 0x05, 0x00}));
}

TEST(WriterError, IsStickyAndSuppressesLaterWrites) {
  Writer w;
  w.objectIdentifier(Oid{});  // unencodable
  ASSERT_FALSE(w.ok());
  const auto afterFailure = w.size();
  w.integer(7);
  EXPECT_EQ(w.size(), afterFailure) << "writes after a failure must not append";
  EXPECT_EQ(w.error(), make_error_code(Errc::OidNotEncodable));
}

}  // namespace
}  // namespace snmpio::ber
