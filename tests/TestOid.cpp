#include <gtest/gtest.h>

#include <snmpio/Oid.hpp>

#include "Bytes.hpp"

namespace snmpio {
namespace {

TEST(Oid, ParsesDottedDecimal) {
  const auto o = Oid::parse("1.3.6.1.2.1.1.3.0");
  ASSERT_TRUE(o.has_value());
  EXPECT_EQ(o->size(), 9U);
  EXPECT_EQ((*o)[0], 1U);
  EXPECT_EQ((*o)[8], 0U);
  EXPECT_EQ(o->toString(), "1.3.6.1.2.1.1.3.0");
}

TEST(Oid, AcceptsLeadingDot) {
  EXPECT_EQ(Oid::parse(".1.3.6"), Oid::parse("1.3.6"));
}

TEST(Oid, ParsesFullSubidRange) {
  const auto o = Oid::parse("1.3.4294967295");
  ASSERT_TRUE(o.has_value());
  EXPECT_EQ((*o)[2], 4294967295U);
}

TEST(Oid, RejectsMalformedText) {
  EXPECT_FALSE(Oid::parse("").has_value());
  EXPECT_FALSE(Oid::parse(".").has_value());
  EXPECT_FALSE(Oid::parse("1..3").has_value());
  EXPECT_FALSE(Oid::parse("1.3.").has_value());
  EXPECT_FALSE(Oid::parse("1.3.x").has_value());
  EXPECT_FALSE(Oid::parse("1.3.-1").has_value());
  EXPECT_FALSE(Oid::parse("1.3.+4").has_value());
  EXPECT_FALSE(Oid::parse("1 3 6").has_value());
  EXPECT_FALSE(Oid::parse("1.3.4294967296").has_value()) << "one past 2^32-1";
}

TEST(Oid, RejectsMoreThan128Subids) {
  std::string text = "1";
  for (int i = 0; i < 127; ++i) text += ".1";  // 128 components exactly
  EXPECT_TRUE(Oid::parse(text).has_value());
  EXPECT_FALSE(Oid::parse(text + ".1").has_value());
}

TEST(Oid, OrdersLexicographicallyNotNumerically) {
  // The ordering that matters: it is what the walk loop's "did the Agent go backwards" check
  // rests on. A shorter OID sorts before any OID that extends it.
  EXPECT_LT(Oid::parse("1.3.6.1.2")->toString(), std::string("1.3.6.1.2.1"));
  EXPECT_TRUE(*Oid::parse("1.3.6.1.2") < *Oid::parse("1.3.6.1.2.1"));
  EXPECT_TRUE(*Oid::parse("1.3.6.1.2.1") < *Oid::parse("1.3.6.1.3"));
  EXPECT_TRUE(*Oid::parse("1.3.6.1.2.9") < *Oid::parse("1.3.6.1.2.10")) << "9 < 10, not '9' > '1'";
  EXPECT_FALSE(*Oid::parse("1.3.6") < *Oid::parse("1.3.6"));
}

TEST(Oid, PrefixIsSubtreeMembership) {
  const auto base = *Oid::parse("1.3.6.1.2.1.2.2.1");
  EXPECT_TRUE(base.isPrefixOf(base)) << "a subtree contains its own base";
  EXPECT_TRUE(base.isPrefixOf(*Oid::parse("1.3.6.1.2.1.2.2.1.2.1")));
  EXPECT_FALSE(base.isPrefixOf(*Oid::parse("1.3.6.1.2.1.2.2")));
  EXPECT_FALSE(base.isPrefixOf(*Oid::parse("1.3.6.1.2.1.2.3.1")));
  // The classic off-by-one: 1.3.6.1.2.1.2.2.10 is not inside 1.3.6.1.2.1.2.2.1.
  EXPECT_FALSE(base.isPrefixOf(*Oid::parse("1.3.6.1.2.1.2.2.10")));
}

TEST(Oid, Child) {
  EXPECT_EQ(Oid::parse("1.3.6")->child(1), *Oid::parse("1.3.6.1"));
}

TEST(Oid, Encodability) {
  EXPECT_TRUE(Oid::parse("1.3.6.1")->isEncodable());
  EXPECT_TRUE(Oid::parse("0.0")->isEncodable());
  EXPECT_TRUE(Oid::parse("2.999")->isEncodable()) << "second arc is unbounded under arc 2";
  EXPECT_FALSE(Oid().isEncodable()) << "empty";
  EXPECT_FALSE(Oid::parse("1")->isEncodable()) << "one arc cannot be packed";
  EXPECT_FALSE(Oid::parse("3.1")->isEncodable()) << "first arc above 2";
  EXPECT_FALSE(Oid::parse("1.40")->isEncodable()) << "second arc must stay below 40 under arc 0/1";
  EXPECT_FALSE(Oid::parse("2.4294967295")->isEncodable()) << "40*2 + second overflows";
}

}  // namespace
}  // namespace snmpio
