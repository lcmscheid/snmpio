#ifndef SNMPIO_VALUE_HPP
#define SNMPIO_VALUE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <variant>
#include <vector>

#include <snmpio/Oid.hpp>

namespace snmpio {

using Octets = std::vector<std::byte>;

// ASN.1 NULL, the Value carried by every Varbind in a request.
struct NullType {
  friend bool operator==(NullType /*lhs*/, NullType /*rhs*/) noexcept { return true; }
};
inline constexpr NullType null{};

// The application types of RFC 2578 section 7.1. Each is a distinct struct rather than a bare
// integer so that they stay separate alternatives of the variant: Counter32, Gauge32 and TimeTicks
// are all 32-bit unsigned on the wire but mean entirely different things, and a Counter32 that
// silently compares equal to a TimeTicks is a bug waiting to be written.
struct Counter32 {
  std::uint32_t value = 0;
  friend auto operator<=>(const Counter32&, const Counter32&) = default;
};
struct Gauge32 {  // also spelled Unsigned32
  std::uint32_t value = 0;
  friend auto operator<=>(const Gauge32&, const Gauge32&) = default;
};
struct TimeTicks {
  std::uint32_t value = 0;  // hundredths of a second
  friend auto operator<=>(const TimeTicks&, const TimeTicks&) = default;
};
struct Counter64 {
  std::uint64_t value = 0;
  friend auto operator<=>(const Counter64&, const Counter64&) = default;
};
struct IpAddress {
  std::array<std::byte, 4> value{};
  friend bool operator==(const IpAddress&, const IpAddress&) = default;
};
struct Opaque {
  Octets value;
  friend bool operator==(const Opaque&, const Opaque&) = default;
};

// The three exception markers a Response may carry in place of a Value (RFC 3416 section 4.1).
// They are values, not errors: a GETNEXT that walks off the end of the MIB view returns
// EndOfMibView in a perfectly successful Response.
enum class ValueException : std::uint8_t {
  NoSuchObject,
  NoSuchInstance,
  EndOfMibView,
};

std::string_view toString(ValueException e) noexcept;

// Everything a Varbind can carry.
using Value = std::variant<NullType,      //
                           std::int32_t,  // INTEGER / Integer32
                           Octets,        // OCTET STRING
                           Oid,           // OBJECT IDENTIFIER
                           IpAddress,     //
                           Counter32,     //
                           Gauge32,       //
                           TimeTicks,     //
                           Opaque,        //
                           Counter64,     //
                           ValueException>;

// A pairing of an OID with a Value or with one of the three exception markers.
struct Varbind {
  Oid name;
  Value val{null};

  friend bool operator==(const Varbind&, const Varbind&) = default;
};

// Convenience: the exception markers never appear in a request, and callers walking a Response
// usually want to skip them before touching the Value.
inline bool isException(const Value& v) noexcept {
  return std::holds_alternative<ValueException>(v);
}

// Human-readable rendering, for logs and test failure messages. Not a display-hint implementation:
// with no MIB there is nothing to hint with, so OCTET STRINGs are rendered as hex unless they are
// entirely printable.
std::string toString(const Value& v);

}  // namespace snmpio

#endif  // SNMPIO_VALUE_HPP
