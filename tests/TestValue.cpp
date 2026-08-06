#include <gtest/gtest.h>

#include <snmpio/Value.hpp>

#include "Bytes.hpp"

namespace snmpio {
namespace {

TEST(Value, ApplicationTypesAreDistinctAlternatives) {
  // Counter32, Gauge32 and TimeTicks are all 32-bit unsigned on the wire. Keeping them as
  // separate structs is the point: holding one never satisfies a query for another.
  const Value c = Counter32{42};
  const Value g = Gauge32{42};
  const Value t = TimeTicks{42};
  EXPECT_TRUE(std::holds_alternative<Counter32>(c));
  EXPECT_FALSE(std::holds_alternative<Gauge32>(c));
  EXPECT_FALSE(std::holds_alternative<TimeTicks>(c));
  EXPECT_NE(c.index(), g.index());
  EXPECT_NE(g.index(), t.index());
}

TEST(Value, DefaultVarbindIsNull) {
  const Varbind vb;
  EXPECT_TRUE(std::holds_alternative<NullType>(vb.val));
  EXPECT_TRUE(vb.name.empty());
}

TEST(Value, ExceptionsAreValuesNotErrors) {
  const Value v = ValueException::EndOfMibView;
  EXPECT_TRUE(isException(v));
  EXPECT_FALSE(isException(Value{Counter32{0}}));
  EXPECT_EQ(toString(ValueException::NoSuchObject), "noSuchObject");
  EXPECT_EQ(toString(ValueException::NoSuchInstance), "noSuchInstance");
  EXPECT_EQ(toString(ValueException::EndOfMibView), "endOfMibView");
}

TEST(Value, ToStringRendersPrintableStringsAndHexesTheRest) {
  EXPECT_EQ(toString(Value{Octets{std::byte{'e'}, std::byte{'t'}, std::byte{'h'}}}), "\"eth\"");
  EXPECT_EQ(toString(Value{Octets{std::byte{0x00}, std::byte{0xFF}}}), "00 ff");
  EXPECT_EQ(toString(Value{Octets{}}), "\"\"");
  EXPECT_EQ(toString(Value{null}), "NULL");
  EXPECT_EQ(toString(Value{std::int32_t{-7}}), "-7");
  EXPECT_EQ(toString(Value{Counter64{18446744073709551615ULL}}), "18446744073709551615");
  EXPECT_EQ(toString(Value{*Oid::parse("1.3.6.1")}), "1.3.6.1");
  EXPECT_EQ(toString(Value{IpAddress{{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{1}}}}),
            "10.0.0.1");
}

}  // namespace
}  // namespace snmpio
