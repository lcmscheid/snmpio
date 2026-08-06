#ifndef SNMPIO_ERROR_HPP
#define SNMPIO_ERROR_HPP

#include <snmpio/detail/Asio.hpp>

namespace snmpio {

// Stage 0 error taxonomy: everything here is a codec-level fault, i.e. "these bytes are not a
// well-formed SNMP encoding". Transport, timeout and USM errors arrive in later stages.
enum class Errc {
  Ok = 0,

  // Framing.
  Truncated,         // ran off the end of the input
  IndefiniteLength,  // 0x80 length -- legal in BER at large, never legal in SNMP
  LengthTooLarge,    // length field wider than we accept, or larger than the remaining input
  HighTagNumber,     // multi-byte tag; SNMP only ever uses tags < 31
  UnexpectedTag,     // well-formed, but not the tag the caller asked for
  TrailingData,      // content decoded, but bytes were left over inside the TLV
  ReservedLength,    // 0xFF length octet, reserved by X.690

  // Primitives.
  EmptyContent,     // a primitive that requires at least one content octet had none
  IntegerTooLarge,  // INTEGER content does not fit the target width
  BadIpAddress,     // IpAddress whose content is not exactly 4 Octets
  BadNull,          // NULL with non-empty content

  // Object identifiers.
  OidEmpty,           // zero content Octets
  OidTooLong,         // more than 128 sub-identifiers (RFC 3416 limit)
  OidSubidOverflow,   // a sub-identifier that does not fit in 32 bits
  OidNonMinimal,      // a sub-identifier with a leading 0x80 continuation byte
  OidTruncatedSubid,  // content ended mid sub-identifier
  OidNotEncodable,    // fewer than two arcs, or arcs outside the ranges X.690 can pack
  OidBadSyntax,       // string form did not parse

  // Values.
  UnknownValueTag,  // tag is not one this library recognises as a Varbind Value
};

const net::ErrorCategory& errorCategory() noexcept;

// Not makeErrorCode: this is an ADL customisation point. Both std::error_code and
// boost::system::error_code call `make_error_code(e)` unqualified when converting from a
// registered enum, so the spelling is fixed by the standard, not by us.
// NOLINTNEXTLINE(readability-identifier-naming)
net::ErrorCode make_error_code(Errc e) noexcept;

}  // namespace snmpio

SNMPIO_REGISTER_ERROR_CODE_ENUM(::snmpio::Errc)

#endif  // SNMPIO_ERROR_HPP
