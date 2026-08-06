#ifndef SNMPIO_BER_TAG_HPP
#define SNMPIO_BER_TAG_HPP

#include <cstdint>

namespace snmpio::ber {

// SNMP only ever uses low-tag-number form, so an identifier octet is the whole tag and a plain
// std::uint8_t is the right representation.
using TagType = std::uint8_t;

inline constexpr TagType classUniversal = 0x00;
inline constexpr TagType classApplication = 0x40;
inline constexpr TagType classContext = 0x80;
inline constexpr TagType classPrivate = 0xC0;
inline constexpr TagType constructedBit = 0x20;
inline constexpr TagType classMask = 0xC0;
inline constexpr TagType numberMask = 0x1F;

// The tag number 31 escape means "the number continues in following Octets". SNMP never needs it.
inline constexpr TagType highTagNumberEscape = 0x1F;

namespace tag {

// X.690 universal types.
inline constexpr TagType integer = 0x02;
inline constexpr TagType octetString = 0x04;
inline constexpr TagType null = 0x05;
inline constexpr TagType objectIdentifier = 0x06;
inline constexpr TagType sequence = 0x30;  // universal 16, constructed

// RFC 2578 application types.
inline constexpr TagType ipAddress = 0x40;
inline constexpr TagType counter32 = 0x41;
inline constexpr TagType gauge32 = 0x42;  // also Unsigned32
inline constexpr TagType timeticks = 0x43;
inline constexpr TagType opaque = 0x44;
inline constexpr TagType counter64 = 0x46;

// RFC 3416 exception markers: context-specific, primitive, always zero-length.
inline constexpr TagType noSuchObject = 0x80;
inline constexpr TagType noSuchInstance = 0x81;
inline constexpr TagType endOfMibView = 0x82;

// RFC 3416 PDU tags: context-specific, constructed. Defined here because they are BER identifiers
// like any other; the PDUs themselves arrive in stage 1.
inline constexpr TagType getRequest = 0xA0;
inline constexpr TagType getNextRequest = 0xA1;
inline constexpr TagType response = 0xA2;
inline constexpr TagType setRequest = 0xA3;
inline constexpr TagType getBulkRequest = 0xA5;
inline constexpr TagType informRequest = 0xA6;
inline constexpr TagType snmpv2Trap = 0xA7;
inline constexpr TagType report = 0xA8;

}  // namespace tag

constexpr bool isConstructed(TagType t) noexcept {
  return (t & constructedBit) != 0;
}

}  // namespace snmpio::ber

#endif  // SNMPIO_BER_TAG_HPP
