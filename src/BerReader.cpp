#include <snmpio/ber/Reader.hpp>

#include <algorithm>
#include <limits>

namespace snmpio::ber {

void Reader::fail(Errc e) noexcept {
  if (!m_ec) m_ec = make_error_code(e);
  // Clamping the cursor makes every later read a cheap no-op and guarantees that a caller who
  // ignores the sticky flag still cannot read past the failure point.
  m_pos = m_end;
}

std::optional<TagType> Reader::peekTag() const noexcept {
  if (m_ec || m_pos >= m_end) return std::nullopt;
  return static_cast<TagType>(m_buf[m_pos]);
}

bool Reader::finish() noexcept {
  if (m_ec) return false;
  if (m_pos != m_end) {
    fail(Errc::TrailingData);
    return false;
  }
  return true;
}

std::optional<Reader::Header> Reader::readHeader() {
  if (m_ec) return std::nullopt;
  if (remaining() < 2) {
    fail(Errc::Truncated);
    return std::nullopt;
  }

  const auto t = static_cast<TagType>(m_buf[m_pos++]);
  if ((t & numberMask) == highTagNumberEscape) {
    fail(Errc::HighTagNumber);
    return std::nullopt;
  }

  const auto first = static_cast<unsigned>(m_buf[m_pos++]);
  std::size_t length = 0;
  if (first < 0x80) {
    length = first;
  } else if (first == 0x80) {
    fail(Errc::IndefiniteLength);
    return std::nullopt;
  } else if (first == 0xFF) {
    fail(Errc::ReservedLength);
    return std::nullopt;
  } else {
    const unsigned count = first & 0x7F;
    // Four Octets covers 4 GiB; an SNMP message that needs more is not one we will ever hold.
    if (count > 4) {
      fail(Errc::LengthTooLarge);
      return std::nullopt;
    }
    if (remaining() < count) {
      fail(Errc::Truncated);
      return std::nullopt;
    }
    for (unsigned i = 0; i < count; ++i) {
      length = (length << 8) | static_cast<unsigned>(m_buf[m_pos++]);
    }
  }

  if (length > remaining()) {
    fail(Errc::Truncated);
    return std::nullopt;
  }
  return Header{.tag = t, .length = length};
}

Reader::Scope::~Scope() {
  if (m_reader == nullptr) return;
  if (!m_reader->m_ec && m_reader->m_pos != m_contentEnd) {
    m_reader->fail(Errc::TrailingData);
  }
  m_reader->m_end = m_savedEnd;
  m_reader->m_pos = m_contentEnd;
}

Reader::Scope Reader::enter(TagType expected) {
  const std::size_t savedEnd = m_end;
  if (m_ec) return Scope(this, savedEnd, m_pos);

  if (!isConstructed(expected)) {
    fail(Errc::UnexpectedTag);
    return Scope(this, savedEnd, m_pos);
  }
  const auto tagHere = peekTag();
  if (!tagHere || *tagHere != expected) {
    fail(Errc::UnexpectedTag);
    return Scope(this, savedEnd, m_pos);
  }
  const auto h = readHeader();
  if (!h) return Scope(this, savedEnd, m_pos);

  const std::size_t contentEnd = m_pos + h->length;
  m_end = contentEnd;
  return Scope(this, savedEnd, contentEnd);
}

std::optional<std::span<const std::byte>> Reader::primitiveContent(TagType expected) {
  if (m_ec) return std::nullopt;
  const auto tagHere = peekTag();
  if (!tagHere) {
    fail(Errc::Truncated);
    return std::nullopt;
  }
  if (*tagHere != expected) {
    fail(Errc::UnexpectedTag);
    return std::nullopt;
  }
  if (isConstructed(expected)) {
    // Constructed OCTET STRING is legal BER but never appears in SNMP; treating it as an error
    // here keeps the decoders from having to reassemble fragments.
    fail(Errc::UnexpectedTag);
    return std::nullopt;
  }
  const auto h = readHeader();
  if (!h) return std::nullopt;
  const auto content = m_buf.subspan(m_pos, h->length);
  m_pos += h->length;
  return content;
}

std::optional<std::span<const std::byte>> Reader::skipElement() {
  if (m_ec) return std::nullopt;
  const std::size_t start = m_pos;
  const auto h = readHeader();
  if (!h) return std::nullopt;
  m_pos += h->length;
  return m_buf.subspan(start, m_pos - start);
}

std::optional<std::int32_t> Reader::integer(TagType expected) {
  const auto content = primitiveContent(expected);
  if (!content) return std::nullopt;
  if (content->empty()) {
    fail(Errc::EmptyContent);
    return std::nullopt;
  }

  // Be liberal about redundant sign padding: it is technically non-minimal, but agents emit it
  // and rejecting it would break interop for no gain. Drop the padding, then insist that what is
  // left fits an Integer32.
  std::size_t i = 0;
  const std::size_t n = content->size();
  const bool negative = (static_cast<unsigned>((*content)[0]) & 0x80) != 0;
  const auto pad = static_cast<unsigned>(negative ? 0xFF : 0x00);
  while (i + 1 < n && static_cast<unsigned>((*content)[i]) == pad &&
         ((static_cast<unsigned>((*content)[i + 1]) & 0x80) != 0) == negative) {
    ++i;
  }
  if (n - i > 4) {
    fail(Errc::IntegerTooLarge);
    return std::nullopt;
  }

  std::uint32_t magnitude = negative ? 0xFFFFFFFFU : 0U;
  for (; i < n; ++i) {
    magnitude = (magnitude << 8) | static_cast<unsigned>((*content)[i]);
  }
  return static_cast<std::int32_t>(magnitude);
}

std::optional<std::uint64_t> Reader::unsignedContent(TagType expected, unsigned maxSignificant) {
  const auto content = primitiveContent(expected);
  if (!content) return std::nullopt;
  if (content->empty()) {
    fail(Errc::EmptyContent);
    return std::nullopt;
  }

  // Counter/Gauge/TimeTicks are ASN.1 INTEGERs constrained to be non-negative, so a Value with
  // the high bit set is correctly encoded with a leading zero octet. Plenty of agents omit it and
  // emit the bare four Octets instead. Reading the significant Octets as unsigned accepts both.
  std::size_t i = 0;
  while (i < content->size() && (*content)[i] == std::byte{0}) ++i;
  if (content->size() - i > maxSignificant) {
    fail(Errc::IntegerTooLarge);
    return std::nullopt;
  }

  std::uint64_t v = 0;
  for (; i < content->size(); ++i) {
    v = (v << 8) | static_cast<unsigned>((*content)[i]);
  }
  return v;
}

std::optional<std::uint32_t> Reader::unsigned32(TagType expected) {
  const auto v = unsignedContent(expected, 4);
  if (!v) return std::nullopt;
  return static_cast<std::uint32_t>(*v);
}

std::optional<std::uint64_t> Reader::unsigned64(TagType expected) {
  return unsignedContent(expected, 8);
}

std::optional<std::span<const std::byte>> Reader::octetStringView(TagType expected) {
  return primitiveContent(expected);
}

std::optional<Octets> Reader::octetString(TagType expected) {
  const auto content = primitiveContent(expected);
  if (!content) return std::nullopt;
  return Octets(content->begin(), content->end());
}

bool Reader::nullValue() {
  const auto content = primitiveContent(tag::null);
  if (!content) return false;
  if (!content->empty()) {
    fail(Errc::BadNull);
    return false;
  }
  return true;
}

std::optional<Oid> decodeOidContent(std::span<const std::byte> content, Errc& out) {
  out = Errc::Ok;
  if (content.empty()) {
    out = Errc::OidEmpty;
    return std::nullopt;
  }

  Oid result;
  result.reserve(content.size() + 1);

  std::size_t i = 0;
  bool firstSubid = true;
  while (i < content.size()) {
    if ((static_cast<unsigned>(content[i]) & 0x7F) == 0 &&
        (static_cast<unsigned>(content[i]) & 0x80) != 0) {
      // A leading 0x80 pads the sub-identifier with meaningless zero bits.
      out = Errc::OidNonMinimal;
      return std::nullopt;
    }

    std::uint64_t subid = 0;
    bool complete = false;
    while (i < content.size()) {
      const auto b = static_cast<unsigned>(content[i++]);
      subid = (subid << 7) | (b & 0x7F);
      if (subid > std::numeric_limits<std::uint32_t>::max()) {
        out = Errc::OidSubidOverflow;
        return std::nullopt;
      }
      if ((b & 0x80) == 0) {
        complete = true;
        break;
      }
    }
    if (!complete) {
      out = Errc::OidTruncatedSubid;
      return std::nullopt;
    }

    if (firstSubid) {
      // X.690 8.19.4, in reverse: the packed Value splits back into two arcs.
      firstSubid = false;
      if (subid < 40) {
        result.pushBack(0);
        result.pushBack(static_cast<std::uint32_t>(subid));
      } else if (subid < 80) {
        result.pushBack(1);
        result.pushBack(static_cast<std::uint32_t>(subid - 40));
      } else {
        result.pushBack(2);
        result.pushBack(static_cast<std::uint32_t>(subid - 80));
      }
    } else {
      result.pushBack(static_cast<std::uint32_t>(subid));
    }

    if (result.size() > Oid::maxSubids) {
      out = Errc::OidTooLong;
      return std::nullopt;
    }
  }
  return result;
}

std::optional<Oid> Reader::objectIdentifier() {
  const auto content = primitiveContent(tag::objectIdentifier);
  if (!content) return std::nullopt;
  Errc e = Errc::Ok;
  auto result = decodeOidContent(*content, e);
  if (!result) {
    fail(e);
    return std::nullopt;
  }
  return result;
}

std::optional<Value> Reader::anyValue() {
  if (m_ec) return std::nullopt;
  const auto t = peekTag();
  if (!t) {
    fail(Errc::Truncated);
    return std::nullopt;
  }

  switch (*t) {
    case tag::null:
      if (!nullValue()) return std::nullopt;
      return Value{null};
    case tag::integer: {
      const auto v = integer();
      if (!v) return std::nullopt;
      return Value{*v};
    }
    case tag::octetString: {
      auto v = octetString();
      if (!v) return std::nullopt;
      return Value{std::move(*v)};
    }
    case tag::objectIdentifier: {
      auto v = objectIdentifier();
      if (!v) return std::nullopt;
      return Value{std::move(*v)};
    }
    case tag::ipAddress: {
      const auto content = primitiveContent(tag::ipAddress);
      if (!content) return std::nullopt;
      if (content->size() != 4) {
        fail(Errc::BadIpAddress);
        return std::nullopt;
      }
      IpAddress addr;
      std::copy(content->begin(), content->end(), addr.value.begin());
      return Value{addr};
    }
    case tag::counter32: {
      const auto v = unsigned32(tag::counter32);
      if (!v) return std::nullopt;
      return Value{Counter32{*v}};
    }
    case tag::gauge32: {
      const auto v = unsigned32(tag::gauge32);
      if (!v) return std::nullopt;
      return Value{Gauge32{*v}};
    }
    case tag::timeticks: {
      const auto v = unsigned32(tag::timeticks);
      if (!v) return std::nullopt;
      return Value{TimeTicks{*v}};
    }
    case tag::counter64: {
      const auto v = unsigned64(tag::counter64);
      if (!v) return std::nullopt;
      return Value{Counter64{*v}};
    }
    case tag::opaque: {
      auto v = octetString(tag::opaque);
      if (!v) return std::nullopt;
      return Value{Opaque{std::move(*v)}};
    }
    case tag::noSuchObject:
    case tag::noSuchInstance:
    case tag::endOfMibView: {
      const auto content = primitiveContent(*t);
      if (!content) return std::nullopt;
      if (!content->empty()) {
        fail(Errc::TrailingData);
        return std::nullopt;
      }
      switch (*t) {
        case tag::noSuchObject:
          return Value{ValueException::NoSuchObject};
        case tag::noSuchInstance:
          return Value{ValueException::NoSuchInstance};
        default:
          return Value{ValueException::EndOfMibView};
      }
    }
    default:
      fail(Errc::UnknownValueTag);
      return std::nullopt;
  }
}

std::optional<Varbind> Reader::readVarbind() {
  if (m_ec) return std::nullopt;
  Varbind vb;
  {
    auto s = enter(tag::sequence);
    auto name = objectIdentifier();
    if (!name) return std::nullopt;
    auto val = anyValue();
    if (!val) return std::nullopt;
    vb.name = std::move(*name);
    vb.val = std::move(*val);
  }
  if (m_ec) return std::nullopt;  // the Scope guard may have flagged trailing data
  return vb;
}

std::optional<std::vector<Varbind>> Reader::varbindList() {
  if (m_ec) return std::nullopt;
  std::vector<Varbind> out;
  {
    auto s = enter(tag::sequence);
    while (ok() && !atEnd()) {
      auto vb = readVarbind();
      if (!vb) return std::nullopt;
      out.push_back(std::move(*vb));
    }
  }
  if (m_ec) return std::nullopt;
  return out;
}

}  // namespace snmpio::ber
