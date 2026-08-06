#include <snmpio/Error.hpp>

#include <string>

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

net::ErrorCode make_error_code(Errc e) noexcept {
  return net::ErrorCode(static_cast<int>(e), errorCategory());
}

}  // namespace snmpio
