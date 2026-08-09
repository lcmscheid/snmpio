#ifndef SNMPIO_ERROR_HPP
#define SNMPIO_ERROR_HPP

#include <snmpio/detail/Asio.hpp>

namespace snmpio {

// The library's own faults. Stage 0 filled in the codec half -- "these bytes are not a
// well-formed SNMP encoding" -- stage 1 added the transport and protocol half, and stage 2 the
// security one. Stage 4 added privacy's.
//
// An Agent's own error-status is deliberately *not* here: it is a distinct enumeration with
// numbering fixed by RFC 3416, and it lives in its own category as snmpio::ErrorStatus.
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

  // Messages and PDUs.
  BadVersion,         // message version field is not one this library speaks
  UnexpectedPduType,  // a PDU tag where none belongs, or a request PDU arriving as a Response
  MissingVarbind,     // Response carried no Varbind where the operation required one

  // Transport and operations.
  Timeout,           // the Target said nothing at all inside its timeout, after every retry. A
                     // Target that answered but whose every reply we discarded reports why
                     // instead: AuthFailed, DecryptionFailed or NotInTimeWindow (ADR-0008).
  ClientStopped,     // the Client stopped while the request was outstanding
  NonIncreasingOid,  // a Walk Response repeated or went backwards (ADR-0004)
  WalkIncomplete,    // a Walk stopped early: cancelled, or the batch handler asked it to

  // Security (USM). A rejection the Agent reports is not here: that arrives as a Report PDU and
  // is handled internally (stage 3), not surfaced as one of our faults.
  UnsupportedAuthProtocol,    // an auth operation asked for with AuthProtocol::None, or one the
                              // local OpenSSL will not provide
  UnsupportedSecurityLevel,   // a Security Level this build cannot produce
  UnsupportedPrivProtocol,    // authPriv asked for with PrivProtocol::None
  LegacyProviderUnavailable,  // DES needs OpenSSL's legacy provider, and it would not load
  UnsupportedSecurityModel,   // msgSecurityModel names something other than USM
  BadMessageFlags,            // msgFlags was not one Octet, or claimed privacy without auth
  EmptyPassword,              // password-to-key on an empty password, which it cannot expand
  CryptoFailure,              // OpenSSL refused an operation that should not have been refusable
  AuthFailed,                 // the message's digest is not the one its key produces
  DecryptionFailed,           // an encryptedPDU this key does not open, or does not open into a
                              // ScopedPDU

  // usmStats Reports the Authoritative Engine sent back (RFC 3414 section 5). Two of the six are
  // not here on purpose: usmStatsWrongDigests arrives as AuthFailed and
  // usmStatsUnsupportedSecLevels as UnsupportedSecurityLevel, because that is what they mean and a
  // second spelling of each would only be a second thing to check for.
  UnknownUserName,   // usmStatsUnknownUserNames: no such user on that Engine
  UnknownEngineId,   // usmStatsUnknownEngineIDs, still, after re-discovering
  NotInTimeWindow,   // usmStatsNotInTimeWindows, still, after resynchronising
  DecryptionError,   // usmStatsDecryptionErrors
  UnexpectedReport,  // a Report whose usmStats counter we do not recognise
};

// What a caller can do about a failure, across all three categories a completion can carry --
// snmpio's Errc, the Agent's ErrorStatus, and the system's socket faults. Callers write retry
// policies against this rather than against forty-odd enumerators; the useful question is not how
// bad a failure was but what to do next.
//
// The borderline calls, since they are the ones worth arguing with:
//
//   * AuthFailed, DecryptionFailed, DecryptionError and UnknownUserName are Configuration, not
//     Retriable. Wrong Credentials produce them on every retry, and a retry loop that treats them
//     like a lost datagram is an infinite loop against a Target that is answering perfectly.
//   * UnknownEngineId and NotInTimeWindow are Retriable even though the Client already
//     re-discovered and resynchronised once before reporting them: they are what an Agent that
//     rebooted mid-exchange produces, and the next request discovers the new boots/time.
//   * CommitFailed and UndoFailed are Fatal rather than Retriable. The Agent is telling us it does
//     not know what state the SET left behind, and replaying a half-applied SET is the one retry
//     that can do damage.
//   * WalkIncomplete and ClientStopped are Fatal because the caller asked for them. Nothing about
//     the Target changed, so there is nothing for a retry policy to wait out.
//   * ErrorStatus::GenErr is Retriable, and it is the least comfortable call here. It is the
//     Agent's catch-all for a processing failure it has no better code for, which is usually
//     transient -- but after a SET it carries the same unknown-state risk CommitFailed does, and
//     classify() cannot see which operation produced it. A caller retrying SETs should treat this
//     one as Fatal itself.
//   * In the system category, the socket faults worth waiting out -- unreachable, reset, down,
//     refused, out of buffers, timed out, interrupted -- are Retriable; everything else, including
//     the operation_canceled a cancellation signal produces, is Fatal. connection_refused on UDP
//     is an ICMP port-unreachable, which is a Target still booting at least as often as it is a
//     Target with nothing listening, so it goes with the retriable half.
//   * An ErrorCode from a fourth category is Unclassified rather than Fatal. Naming what we cannot
//     interpret is honest; guessing would be a retry policy deciding on evidence it does not have.
//   * Malformed replies -- the framing, primitive and OID decode faults -- are Fatal. They mean
//     the Agent is producing something no correct Agent produces, and the next datagram will be
//     just as unusable. Encode-side faults on the caller's own input (OidNotEncodable,
//     OidBadSyntax) are Configuration instead: those the caller can fix.
enum class ErrorClass {
  Ok,             // not a failure
  Retriable,      // retry unchanged: the Target was silent, unreachable, or busy
  Configuration,  // change something -- Credentials, Oid, request size -- and retry
  Fatal,          // stop: retrying changes nothing, and nothing the caller can set will help
  Unclassified,   // a code from a category this library does not know. No Errc or ErrorStatus
                  // produces this -- TestError pins that -- so it means a fourth category arrived.
};

// The one entry point. Safe to call on a success code, which classifies as Ok.
[[nodiscard]] ErrorClass classify(const net::ErrorCode& ec) noexcept;

const net::ErrorCategory& errorCategory() noexcept;

// Not makeErrorCode: this is an ADL customisation point. Both std::error_code and
// boost::system::error_code call `make_error_code(e)` unqualified when converting from a
// registered enum, so the spelling is fixed by the standard, not by us.
// NOLINTNEXTLINE(readability-identifier-naming)
net::ErrorCode make_error_code(Errc e) noexcept;

}  // namespace snmpio

SNMPIO_REGISTER_ERROR_CODE_ENUM(::snmpio::Errc)

#endif  // SNMPIO_ERROR_HPP
