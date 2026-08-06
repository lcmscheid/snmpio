#ifndef SNMPIO_PDU_HPP
#define SNMPIO_PDU_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <snmpio/Error.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/ber/Reader.hpp>
#include <snmpio/ber/Tag.hpp>
#include <snmpio/ber/Writer.hpp>

namespace snmpio {

// The PDU types of RFC 3416, valued as their BER identifier octets so that encoding is a cast.
// Trap and Inform are notification traffic, which a Command Generator neither sends nor receives.
enum class PduType : ber::TagType {
  Get = ber::tag::getRequest,
  GetNext = ber::tag::getNextRequest,
  GetBulk = ber::tag::getBulkRequest,
  Set = ber::tag::setRequest,
  Response = ber::tag::response,
  Report = ber::tag::report,
};

[[nodiscard]] bool isPduTag(ber::TagType t) noexcept;

// RFC 3416 section 4.2 error-status. Its own enumeration and its own error category rather than
// more Errc values: the numbering is the Agent's, fixed by the RFC, and folding it into ours would
// either renumber it or leave a hole. `ec.value()` on one of these is the wire number.
enum class ErrorStatus : std::int32_t {
  NoError = 0,
  TooBig = 1,
  NoSuchName = 2,
  BadValue = 3,
  ReadOnly = 4,
  GenErr = 5,
  NoAccess = 6,
  WrongType = 7,
  WrongLength = 8,
  WrongEncoding = 9,
  WrongValue = 10,
  NoCreation = 11,
  InconsistentValue = 12,
  ResourceUnavailable = 13,
  CommitFailed = 14,
  UndoFailed = 15,
  AuthorizationError = 16,
  NotWritable = 17,
  InconsistentName = 18,
};

const net::ErrorCategory& agentErrorCategory() noexcept;

// See the note on snmpio::make_error_code(Errc): the spelling is the standard's, not ours.
// NOLINTNEXTLINE(readability-identifier-naming)
net::ErrorCode make_error_code(ErrorStatus e) noexcept;

// A Protocol Data Unit.
//
// GETBULK reuses the error-status and error-index slots as non-repeaters and max-repetitions
// (RFC 3416 section 4.2.3) -- same two INTEGERs in the same two positions, different meaning. The
// accessors below name them; there is no second struct, because on the wire there is no second
// layout.
struct Pdu {
  PduType type = PduType::Get;
  std::int32_t requestId = 0;
  std::int32_t errorStatus = 0;
  std::int32_t errorIndex = 0;
  std::vector<Varbind> varbinds;

  [[nodiscard]] std::int32_t nonRepeaters() const noexcept { return errorStatus; }
  [[nodiscard]] std::int32_t maxRepetitions() const noexcept { return errorIndex; }
  void setBulkParams(std::int32_t nonRepeaters, std::int32_t maxRepetitions) noexcept {
    errorStatus = nonRepeaters;
    errorIndex = maxRepetitions;
  }
};

void encodePdu(ber::Writer& w, const Pdu& p);

// Decodes one PDU TLV, whichever of the six types it is. Failures land in the Reader's sticky
// error, as everywhere else in the codec.
std::optional<Pdu> decodePdu(ber::Reader& r);

// RFC 3416 section 3: SNMPv2c is version 1 on the wire. The off-by-one is the specification's.
inline constexpr std::int32_t versionV2c = 1;

struct V2cMessage {
  std::string community;
  Pdu pdu;
};

// SEQUENCE { version INTEGER, community OCTET STRING, PDU }.
std::vector<std::byte> encodeV2cMessage(std::string_view community, const Pdu& pdu,
                                        net::ErrorCode& ec);
std::optional<V2cMessage> decodeV2cMessage(std::span<const std::byte> datagram, net::ErrorCode& ec);

}  // namespace snmpio

SNMPIO_REGISTER_ERROR_CODE_ENUM(::snmpio::ErrorStatus)

#endif  // SNMPIO_PDU_HPP
