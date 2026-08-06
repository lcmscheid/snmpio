#include <gtest/gtest.h>

#include <cstdint>
#include <random>
#include <vector>

#include <snmpio/ber/Reader.hpp>
#include <snmpio/ber/Writer.hpp>

#include "Bytes.hpp"

namespace snmpio::ber {
namespace {

// encode then decode is the identity on every Value the library can represent. This is the
// property the fuzz target checks against arbitrary input; here it runs over values chosen to sit
// on the boundaries where the encoders switch form.
void expectRoundTrips(const Value& v) {
  Writer w;
  w.write(v);
  ASSERT_TRUE(w.ok()) << w.error().message();
  const auto encoding = w.take();

  Reader r(encoding);
  const auto decoded = r.anyValue();
  ASSERT_TRUE(decoded.has_value()) << test::hex(encoding) << ": " << r.error().message();
  EXPECT_TRUE(r.finish()) << test::hex(encoding);
  EXPECT_EQ(v, *decoded) << test::hex(encoding);
}

TEST(RoundTrip, IntegerBoundaries) {
  for (std::int32_t v :
       {std::int32_t{0}, std::int32_t{1}, std::int32_t{-1}, std::int32_t{127}, std::int32_t{128},
        std::int32_t{-128}, std::int32_t{-129}, std::int32_t{32767}, std::int32_t{32768},
        std::int32_t{8388607}, std::int32_t{8388608}, std::int32_t{2147483647},
        std::int32_t{-2147483647 - 1}}) {
    expectRoundTrips(Value{v});
  }
}

TEST(RoundTrip, UnsignedBoundaries) {
  for (std::uint32_t v :
       {0U, 1U, 127U, 128U, 255U, 256U, 65535U, 65536U, 2147483647U, 2147483648U, 4294967295U}) {
    expectRoundTrips(Value{Counter32{v}});
    expectRoundTrips(Value{Gauge32{v}});
    expectRoundTrips(Value{TimeTicks{v}});
  }
  for (std::uint64_t v : {0ULL, 1ULL, 255ULL, 4294967296ULL, 9223372036854775807ULL,
                          9223372036854775808ULL, 18446744073709551615ULL}) {
    expectRoundTrips(Value{Counter64{v}});
  }
}

TEST(RoundTrip, OctetStringLengthsAcrossTheLongFormBoundary) {
  for (const std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{126}, std::size_t{127},
                              std::size_t{128}, std::size_t{129}, std::size_t{255},
                              std::size_t{256}, std::size_t{65535}, std::size_t{65536}}) {
    Octets payload(n);
    for (std::size_t i = 0; i < n; ++i) payload[i] = static_cast<std::byte>(i & 0xFF);
    expectRoundTrips(Value{payload});
    expectRoundTrips(Value{Opaque{payload}});
  }
}

TEST(RoundTrip, Oids) {
  for (const char* text : {"0.0", "1.3", "2.0", "0.39", "1.39", "2.999", "1.3.6.1.2.1.1.3.0",
                           "1.3.127", "1.3.128", "1.3.16383", "1.3.16384", "1.3.2097151",
                           "1.3.2097152", "1.3.268435455", "1.3.268435456", "1.3.4294967295"}) {
    expectRoundTrips(Value{*Oid::parse(text)});
  }
}

TEST(RoundTrip, MaximumLengthOid) {
  Oid o{1, 3};
  while (o.size() < Oid::maxSubids) o.pushBack(4294967295U);
  ASSERT_TRUE(o.isEncodable());
  expectRoundTrips(Value{o});
}

TEST(RoundTrip, ScalarsAndExceptions) {
  expectRoundTrips(Value{null});
  expectRoundTrips(Value{IpAddress{{std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}}}});
  expectRoundTrips(
      Value{IpAddress{{std::byte{255}, std::byte{255}, std::byte{255}, std::byte{255}}}});
  expectRoundTrips(Value{ValueException::NoSuchObject});
  expectRoundTrips(Value{ValueException::NoSuchInstance});
  expectRoundTrips(Value{ValueException::EndOfMibView});
}

TEST(RoundTrip, VarbindListsOfEveryValueKind) {
  std::vector<Varbind> vbs;
  vbs.push_back({*Oid::parse("1.3.6.1.2.1.1.1.0"), Value{Octets(300, std::byte{'x'})}});
  vbs.push_back({*Oid::parse("1.3.6.1.2.1.1.3.0"), Value{TimeTicks{4294967295U}}});
  vbs.push_back({*Oid::parse("1.3.6.1.2.1.2.2.1.10.1"), Value{Counter64{1ULL << 63}}});
  vbs.push_back({*Oid::parse("1.3.6.1.2.1.4.20.1.1.10.0.0.1"),
                 Value{IpAddress{{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{1}}}}});
  vbs.push_back({*Oid::parse("1.3.6.1.2.1.1.2.0"), Value{*Oid::parse("1.3.6.1.4.1.9")}});
  vbs.push_back({*Oid::parse("1.3.6.1.9.9.9"), Value{ValueException::EndOfMibView}});
  vbs.push_back({*Oid::parse("1.3.6.1.9.9.10"), Value{null}});
  vbs.push_back({*Oid::parse("1.3.6.1.9.9.11"), Value{std::int32_t{-2147483647 - 1}}});

  Writer w;
  w.varbindList(vbs);
  ASSERT_TRUE(w.ok()) << w.error().message();
  const auto encoding = w.take();

  Reader r(encoding);
  const auto decoded = r.varbindList();
  ASSERT_TRUE(decoded.has_value()) << r.error().message();
  EXPECT_TRUE(r.finish());
  EXPECT_EQ(vbs, *decoded);
}

TEST(RoundTrip, RandomisedSweep) {
  // Fixed seed: a failure here has to be reproducible, and an unseeded generator would turn a
  // codec bug into an intermittent one.
  // NOLINTNEXTLINE(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
  std::mt19937 rng(20260806);
  std::uniform_int_distribution<int> kind(0, 9);
  std::uniform_int_distribution<std::uint64_t> any64(0, 18446744073709551615ULL);
  std::uniform_int_distribution<std::size_t> len(0, 400);
  std::uniform_int_distribution<std::size_t> arcs(2, Oid::maxSubids);

  for (int i = 0; i < 2000; ++i) {
    Value v;
    switch (kind(rng)) {
      case 0:
        v = static_cast<std::int32_t>(any64(rng));
        break;
      case 1:
        v = Counter32{static_cast<std::uint32_t>(any64(rng))};
        break;
      case 2:
        v = Gauge32{static_cast<std::uint32_t>(any64(rng))};
        break;
      case 3:
        v = TimeTicks{static_cast<std::uint32_t>(any64(rng))};
        break;
      case 4:
        v = Counter64{any64(rng)};
        break;
      case 5: {
        Octets b(len(rng));
        for (auto& c : b) c = static_cast<std::byte>(any64(rng) & 0xFF);
        v = std::move(b);
        break;
      }
      case 6: {
        Octets b(len(rng));
        for (auto& c : b) c = static_cast<std::byte>(any64(rng) & 0xFF);
        v = Opaque{std::move(b)};
        break;
      }
      case 7: {
        Oid o{1, 3};
        const std::size_t n = arcs(rng);
        while (o.size() < n) o.pushBack(static_cast<std::uint32_t>(any64(rng)));
        v = std::move(o);
        break;
      }
      case 8: {
        IpAddress a;
        for (auto& c : a.value) c = static_cast<std::byte>(any64(rng) & 0xFF);
        v = a;
        break;
      }
      default:
        v = null;
        break;
    }
    ASSERT_NO_FATAL_FAILURE(expectRoundTrips(v)) << "iteration " << i;
  }
}

}  // namespace
}  // namespace snmpio::ber
