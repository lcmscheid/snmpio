#include <snmpio/Pdu.hpp>

#include <string>
#include <utility>

namespace snmpio {
namespace {

// Same reason as in Error.cpp: Boost.System's category has a protected non-virtual destructor
// on purpose, and deriving from it is the documented way to add one.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#endif

class AgentCategory final : public net::ErrorCategory {
 public:
  const char* name() const noexcept override { return "snmp-agent"; }

  std::string message(int ev) const override {
    switch (static_cast<ErrorStatus>(ev)) {
      case ErrorStatus::NoError:
        return "success";
      case ErrorStatus::TooBig:
        return "tooBig: the Response would not fit in one message";
      case ErrorStatus::NoSuchName:
        return "noSuchName";
      case ErrorStatus::BadValue:
        return "badValue";
      case ErrorStatus::ReadOnly:
        return "readOnly";
      case ErrorStatus::GenErr:
        return "genErr";
      case ErrorStatus::NoAccess:
        return "noAccess";
      case ErrorStatus::WrongType:
        return "wrongType";
      case ErrorStatus::WrongLength:
        return "wrongLength";
      case ErrorStatus::WrongEncoding:
        return "wrongEncoding";
      case ErrorStatus::WrongValue:
        return "wrongValue";
      case ErrorStatus::NoCreation:
        return "noCreation";
      case ErrorStatus::InconsistentValue:
        return "inconsistentValue";
      case ErrorStatus::ResourceUnavailable:
        return "resourceUnavailable";
      case ErrorStatus::CommitFailed:
        return "commitFailed";
      case ErrorStatus::UndoFailed:
        return "undoFailed";
      case ErrorStatus::AuthorizationError:
        return "authorizationError";
      case ErrorStatus::NotWritable:
        return "notWritable";
      case ErrorStatus::InconsistentName:
        return "inconsistentName";
    }
    return "unknown SNMP error-status " + std::to_string(ev);
  }
};

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

}  // namespace

const net::ErrorCategory& agentErrorCategory() noexcept {
  static const AgentCategory instance;
  return instance;
}

net::ErrorCode make_error_code(ErrorStatus e) noexcept {
  return net::ErrorCode(static_cast<int>(e), agentErrorCategory());
}

bool isPduTag(ber::TagType t) noexcept {
  switch (t) {
    case ber::tag::getRequest:
    case ber::tag::getNextRequest:
    case ber::tag::getBulkRequest:
    case ber::tag::setRequest:
    case ber::tag::response:
    case ber::tag::report:
      return true;
    default:
      return false;
  }
}

void encodePdu(ber::Writer& w, const Pdu& p) {
  auto scope = w.beginConstructed(static_cast<ber::TagType>(p.type));
  w.integer(p.requestId);
  w.integer(p.errorStatus);
  w.integer(p.errorIndex);
  w.varbindList(p.varbinds);
}

std::optional<Pdu> decodePdu(ber::Reader& r) {
  if (!r.ok()) return std::nullopt;
  const auto t = r.peekTag();
  if (!t) {
    r.fail(Errc::Truncated);
    return std::nullopt;
  }
  if (!isPduTag(*t)) {
    r.fail(Errc::UnexpectedPduType);
    return std::nullopt;
  }

  Pdu p;
  p.type = static_cast<PduType>(*t);
  {
    auto scope = r.enter(*t);
    const auto requestId = r.integer();
    const auto errorStatus = r.integer();
    const auto errorIndex = r.integer();
    auto varbinds = r.varbindList();
    if (!requestId || !errorStatus || !errorIndex || !varbinds) return std::nullopt;
    p.requestId = *requestId;
    p.errorStatus = *errorStatus;
    p.errorIndex = *errorIndex;
    p.varbinds = std::move(*varbinds);
  }
  if (!r.ok()) return std::nullopt;  // the Scope guard may have flagged trailing data
  return p;
}

std::vector<std::byte> encodeV2cMessage(std::string_view community, const Pdu& pdu,
                                        net::ErrorCode& ec) {
  ber::Writer w(256);
  {
    auto scope = w.beginSequence();
    w.integer(versionV2c);
    w.octetString(community);
    encodePdu(w, pdu);
  }
  ec = w.error();
  if (ec) return {};
  return w.take();
}

std::optional<V2cMessage> decodeV2cMessage(std::span<const std::byte> datagram,
                                           net::ErrorCode& ec) {
  ber::Reader r(datagram);
  V2cMessage msg;
  {
    auto scope = r.enter(ber::tag::sequence);
    const auto version = r.integer();
    auto community = r.octetString();
    if (!version || !community) {
      ec = r.error();
      return std::nullopt;
    }
    if (*version != versionV2c) {
      ec = make_error_code(Errc::BadVersion);
      return std::nullopt;
    }
    msg.community.assign(reinterpret_cast<const char*>(community->data()), community->size());
    auto pdu = decodePdu(r);
    if (!pdu) {
      ec = r.error();
      return std::nullopt;
    }
    msg.pdu = std::move(*pdu);
  }
  if (!r.finish()) {
    ec = r.error();
    return std::nullopt;
  }
  ec = {};
  return msg;
}

}  // namespace snmpio
