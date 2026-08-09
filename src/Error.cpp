#include <snmpio/Error.hpp>

#include <string>
#include <system_error>

#include <snmpio/Pdu.hpp>

namespace snmpio {
namespace {

// Boost.System's errorCategory has a protected non-virtual destructor -- deliberately, since
// categories are singletons that are never deleted through a base pointer. Deriving from it is
// the documented way to add one, so the warning is a false positive here rather than a design
// smell to fix.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#endif

class SnmpioCategory final : public net::ErrorCategory {
 public:
  const char* name() const noexcept override { return "snmpio"; }

  std::string message(int ev) const override {
    switch (static_cast<Errc>(ev)) {
      case Errc::Ok:
        return "success";
      case Errc::Truncated:
        return "input ended inside a BER element";
      case Errc::IndefiniteLength:
        return "indefinite-length encoding is not permitted in SNMP";
      case Errc::LengthTooLarge:
        return "length field is wider than supported or exceeds the remaining input";
      case Errc::HighTagNumber:
        return "high-tag-number form is not permitted in SNMP";
      case Errc::UnexpectedTag:
        return "BER tag does not match the expected type";
      case Errc::TrailingData:
        return "unconsumed bytes remain inside a BER element";
      case Errc::ReservedLength:
        return "length octet 0xFF is reserved";
      case Errc::EmptyContent:
        return "primitive has no content Octets";
      case Errc::IntegerTooLarge:
        return "integer does not fit the target width";
      case Errc::BadIpAddress:
        return "IpAddress content is not exactly four Octets";
      case Errc::BadNull:
        return "NULL has non-empty content";
      case Errc::OidEmpty:
        return "object identifier has no content Octets";
      case Errc::OidTooLong:
        return "object identifier has more than 128 sub-identifiers";
      case Errc::OidSubidOverflow:
        return "object identifier sub-identifier exceeds 32 bits";
      case Errc::OidNonMinimal:
        return "object identifier sub-identifier is not minimally encoded";
      case Errc::OidTruncatedSubid:
        return "object identifier ended inside a sub-identifier";
      case Errc::OidNotEncodable:
        return "object identifier cannot be represented in BER";
      case Errc::OidBadSyntax:
        return "object identifier string is malformed";
      case Errc::UnknownValueTag:
        return "unrecognised Varbind Value tag";
      case Errc::BadVersion:
        return "SNMP message version is not one this library speaks";
      case Errc::UnexpectedPduType:
        return "PDU is not of a type valid in this position";
      case Errc::MissingVarbind:
        return "Response carried no Varbind where one was required";
      case Errc::Timeout:
        return "no Response from the Target within the timeout";
      case Errc::ClientStopped:
        return "the Client stopped with the request outstanding";
      case Errc::NonIncreasingOid:
        return "Agent returned a non-increasing object identifier during a Walk";
      case Errc::WalkIncomplete:
        return "Walk stopped before the end of the Subtree";
      case Errc::UnsupportedAuthProtocol:
        return "authentication protocol is unavailable or unset";
      case Errc::UnsupportedSecurityLevel:
        return "security level is not one this build can produce";
      case Errc::UnsupportedPrivProtocol:
        return "privacy protocol is unset where the security level requires one";
      case Errc::LegacyProviderUnavailable:
        return "OpenSSL's legacy provider, which DES lives in, could not be loaded";
      case Errc::UnsupportedSecurityModel:
        return "message security model is not USM";
      case Errc::BadMessageFlags:
        return "message flags are not a single Octet, or claim privacy without authentication";
      case Errc::EmptyPassword:
        return "authentication password is empty";
      case Errc::CryptoFailure:
        return "cryptographic operation failed";
      case Errc::AuthFailed:
        return "message authentication digest did not match";
      case Errc::DecryptionFailed:
        return "encryptedPDU did not decrypt into a ScopedPDU with this key";
      case Errc::UnknownUserName:
        return "the Authoritative Engine does not know this user name";
      case Errc::UnknownEngineId:
        return "the Authoritative Engine rejected its own engineID after re-discovery";
      case Errc::NotInTimeWindow:
        return "the Authoritative Engine rejected the message as untimely after resynchronising";
      case Errc::DecryptionError:
        return "the Authoritative Engine could not decrypt the message";
      case Errc::UnexpectedReport:
        return "Report carried a usmStats counter this library does not recognise";
    }
    return "unknown snmpio error " + std::to_string(ev);
  }
};

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

}  // namespace

const net::ErrorCategory& errorCategory() noexcept {
  static const SnmpioCategory instance;
  return instance;
}

namespace {

ErrorClass classifyErrc(Errc e) noexcept {
  switch (e) {
    case Errc::Ok:
      return ErrorClass::Ok;

    // The Target said nothing, or said it was busy. Retransmission is the whole reason UDP
    // transport survives, and these are what it survives.
    case Errc::Timeout:
    case Errc::UnknownEngineId:
    case Errc::NotInTimeWindow:
      return ErrorClass::Retriable;

    // Something the caller set is wrong: Credentials, an Oid, or the build's crypto.
    case Errc::OidNotEncodable:
    case Errc::OidBadSyntax:
    case Errc::UnsupportedAuthProtocol:
    case Errc::UnsupportedSecurityLevel:
    case Errc::UnsupportedPrivProtocol:
    case Errc::LegacyProviderUnavailable:
    case Errc::EmptyPassword:
    case Errc::AuthFailed:
    case Errc::DecryptionFailed:
    case Errc::UnknownUserName:
    case Errc::DecryptionError:
      return ErrorClass::Configuration;

    // Malformed replies, a Target that is not speaking SNMP as this library understands it, and
    // the endings the caller asked for. None of them changes with another datagram.
    case Errc::Truncated:
    case Errc::IndefiniteLength:
    case Errc::LengthTooLarge:
    case Errc::HighTagNumber:
    case Errc::UnexpectedTag:
    case Errc::TrailingData:
    case Errc::ReservedLength:
    case Errc::EmptyContent:
    case Errc::IntegerTooLarge:
    case Errc::BadIpAddress:
    case Errc::BadNull:
    case Errc::OidEmpty:
    case Errc::OidTooLong:
    case Errc::OidSubidOverflow:
    case Errc::OidNonMinimal:
    case Errc::OidTruncatedSubid:
    case Errc::UnknownValueTag:
    case Errc::BadVersion:
    case Errc::UnexpectedPduType:
    case Errc::MissingVarbind:
    case Errc::ClientStopped:
    case Errc::NonIncreasingOid:
    case Errc::WalkIncomplete:
    case Errc::UnsupportedSecurityModel:
    case Errc::BadMessageFlags:
    case Errc::CryptoFailure:
    case Errc::UnexpectedReport:
      return ErrorClass::Fatal;
  }
  return ErrorClass::Unclassified;
}

ErrorClass classifyErrorStatus(ErrorStatus e) noexcept {
  switch (e) {
    case ErrorStatus::NoError:
      return ErrorClass::Ok;

    // The Agent is temporarily unable, not permanently unwilling.
    case ErrorStatus::GenErr:
    case ErrorStatus::ResourceUnavailable:
      return ErrorClass::Retriable;

    // Ask for something else: fewer Varbinds, a different Oid, a different value, or different
    // Credentials.
    case ErrorStatus::TooBig:
    case ErrorStatus::NoSuchName:
    case ErrorStatus::BadValue:
    case ErrorStatus::ReadOnly:
    case ErrorStatus::NoAccess:
    case ErrorStatus::WrongType:
    case ErrorStatus::WrongLength:
    case ErrorStatus::WrongEncoding:
    case ErrorStatus::WrongValue:
    case ErrorStatus::NoCreation:
    case ErrorStatus::InconsistentValue:
    case ErrorStatus::AuthorizationError:
    case ErrorStatus::NotWritable:
    case ErrorStatus::InconsistentName:
      return ErrorClass::Configuration;

    // The Agent does not know what state the SET left behind. Replaying it is the one retry that
    // can do damage.
    case ErrorStatus::CommitFailed:
    case ErrorStatus::UndoFailed:
      return ErrorClass::Fatal;
  }
  return ErrorClass::Unclassified;
}

// Socket faults, via the generic condition so the same list works under both Asio flavours.
// Anything not named here is Fatal: an unrecognised socket fault is not one we can argue is worth
// waiting out.
ErrorClass classifySystem(const net::ErrorCode& ec) noexcept {
  switch (static_cast<std::errc>(ec.default_error_condition().value())) {
    case std::errc::timed_out:
    case std::errc::interrupted:
    case std::errc::network_down:
    case std::errc::network_unreachable:
    case std::errc::network_reset:
    case std::errc::host_unreachable:
    case std::errc::connection_refused:
    case std::errc::connection_reset:
    case std::errc::no_buffer_space:
      return ErrorClass::Retriable;
    default:
      return ErrorClass::Fatal;
  }
}

}  // namespace

ErrorClass classify(const net::ErrorCode& ec) noexcept {
  if (!ec) return ErrorClass::Ok;
  if (ec.category() == errorCategory()) return classifyErrc(static_cast<Errc>(ec.value()));
  if (ec.category() == agentErrorCategory()) {
    return classifyErrorStatus(static_cast<ErrorStatus>(ec.value()));
  }
  if (ec.category() == net::systemCategory() || ec.category() == net::genericCategory()) {
    return classifySystem(ec);
  }
  // Not one of the three. Naming a category we cannot interpret is honest; guessing Fatal for it
  // would be a retry policy silently deciding on evidence it does not have.
  return ErrorClass::Unclassified;
}

net::ErrorCode make_error_code(Errc e) noexcept {
  return net::ErrorCode(static_cast<int>(e), errorCategory());
}

}  // namespace snmpio
