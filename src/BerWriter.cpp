#include <snmpio/ber/Writer.hpp>

#include <algorithm>
#include <array>
#include <string_view>

namespace snmpio::ber {
namespace {

// Octets needed for a definite length: one for the short form, otherwise one count octet plus the
// significant Octets of the length itself.
unsigned lengthOctets(std::size_t n) noexcept {
  if (n < 0x80) return 1;
  unsigned significant = 0;
  for (std::size_t v = n; v != 0; v >>= 8) ++significant;
  return 1 + significant;
}

// Base-128, most significant group first, no leading pad group.
unsigned subidOctets(std::uint64_t v) noexcept {
  unsigned n = 1;
  while (v >= 0x80) {
    v >>= 7;
    ++n;
  }
  return n;
}

}  // namespace

void Writer::fail(Errc e) noexcept {
  if (!m_ec) m_ec = make_error_code(e);
}

void Writer::putLength(std::size_t n) {
  if (n < 0x80) {
    put(static_cast<std::byte>(n));
    return;
  }
  const unsigned significant = lengthOctets(n) - 1;
  put(static_cast<std::byte>(0x80 | significant));
  for (unsigned i = significant; i-- > 0;) {
    put(static_cast<std::byte>((n >> (i * 8)) & 0xFF));
  }
}

Writer::Scope::~Scope() {
  if (m_writer == nullptr) return;
  Writer& w = *m_writer;
  const std::size_t contentStart = m_lengthPos + 1;
  const std::size_t contentLen = w.m_buf.size() - contentStart;
  const unsigned needed = lengthOctets(contentLen);

  if (needed > 1) {
    // Widen the placeholder in place. Every SNMP message has a handful of these, and the shifted
    // tail is at most one message long, so the copy is not worth avoiding.
    w.m_buf.insert(w.m_buf.begin() + static_cast<std::ptrdiff_t>(contentStart),
                   static_cast<std::size_t>(needed - 1), std::byte{0});
    w.m_buf[m_lengthPos] = static_cast<std::byte>(0x80 | (needed - 1));
    for (unsigned i = 0; i < needed - 1; ++i) {
      const unsigned shift = (needed - 2 - i) * 8;
      w.m_buf[m_lengthPos + 1 + i] = static_cast<std::byte>((contentLen >> shift) & 0xFF);
    }
  } else {
    w.m_buf[m_lengthPos] = static_cast<std::byte>(contentLen);
  }
}

Writer::Scope Writer::beginConstructed(TagType t) {
  if (!isConstructed(t)) fail(Errc::UnexpectedTag);
  putTag(t);
  const std::size_t lengthPos = m_buf.size();
  put(std::byte{0});  // placeholder, patched by ~Scope
  return Scope(this, lengthPos);
}

void Writer::integer(std::int32_t v, TagType t) {
  if (m_ec) return;
  std::array<std::byte, 4> encoded{};
  const auto u = static_cast<std::uint32_t>(v);
  for (unsigned i = 0; i < 4; ++i) {
    encoded[i] = static_cast<std::byte>((u >> ((3 - i) * 8)) & 0xFF);
  }
  // Strip sign padding down to the minimal form: drop a leading octet whenever it is pure sign
  // extension of the next one's top bit.
  std::size_t first = 0;
  const std::byte pad = v < 0 ? std::byte{0xFF} : std::byte{0x00};
  while (first + 1 < 4 && encoded[first] == pad &&
         (((static_cast<unsigned>(encoded[first + 1]) & 0x80) != 0) == (v < 0))) {
    ++first;
  }
  putTag(t);
  putLength(4 - first);
  for (std::size_t i = first; i < 4; ++i) put(encoded[i]);
}

void Writer::unsigned32(std::uint32_t v, TagType t) {
  unsigned64(v, t);
}

void Writer::unsigned64(std::uint64_t v, TagType t) {
  if (m_ec) return;
  std::array<std::byte, 9> encoded{};
  encoded[0] = std::byte{0};  // room for the non-negative marker
  for (unsigned i = 0; i < 8; ++i) {
    encoded[1 + i] = static_cast<std::byte>((v >> ((7 - i) * 8)) & 0xFF);
  }
  std::size_t first = 0;
  while (first + 1 < 9 && encoded[first] == std::byte{0} &&
         (static_cast<unsigned>(encoded[first + 1]) & 0x80) == 0) {
    ++first;
  }
  putTag(t);
  putLength(9 - first);
  for (std::size_t i = first; i < 9; ++i) put(encoded[i]);
}

void Writer::octetString(std::span<const std::byte> v, TagType t) {
  if (m_ec) return;
  putTag(t);
  putLength(v.size());
  m_buf.insert(m_buf.end(), v.begin(), v.end());
}

void Writer::octetString(std::string_view v, TagType t) {
  octetString(std::span(reinterpret_cast<const std::byte*>(v.data()), v.size()), t);
}

void Writer::nullValue() {
  if (m_ec) return;
  putTag(tag::null);
  putLength(0);
}

std::size_t encodedOidSize(const Oid& o) noexcept {
  if (!o.isEncodable()) return 0;
  std::size_t content = subidOctets((static_cast<std::uint64_t>(o[0]) * 40) + o[1]);
  for (std::size_t i = 2; i < o.size(); ++i) content += subidOctets(o[i]);
  return 1 + lengthOctets(content) + content;
}

void Writer::objectIdentifier(const Oid& o) {
  if (m_ec) return;
  if (!o.isEncodable()) {
    fail(Errc::OidNotEncodable);
    return;
  }

  std::size_t content = subidOctets((static_cast<std::uint64_t>(o[0]) * 40) + o[1]);
  for (std::size_t i = 2; i < o.size(); ++i) content += subidOctets(o[i]);

  putTag(tag::objectIdentifier);
  putLength(content);

  const auto emit = [this](std::uint64_t v) {
    const unsigned n = subidOctets(v);
    for (unsigned i = n; i-- > 0;) {
      const auto group = static_cast<std::byte>((v >> (i * 7)) & 0x7F);
      put(i == 0 ? group : (group | std::byte{0x80}));
    }
  };
  emit((static_cast<std::uint64_t>(o[0]) * 40) + o[1]);
  for (std::size_t i = 2; i < o.size(); ++i) emit(o[i]);
}

void Writer::write(const Value& v) {
  if (m_ec) return;
  std::visit(
      [this](const auto& held) {
        using T = std::decay_t<decltype(held)>;
        if constexpr (std::is_same_v<T, NullType>) {
          nullValue();
        } else if constexpr (std::is_same_v<T, std::int32_t>) {
          integer(held);
        } else if constexpr (std::is_same_v<T, Octets>) {
          octetString(held);
        } else if constexpr (std::is_same_v<T, Oid>) {
          objectIdentifier(held);
        } else if constexpr (std::is_same_v<T, IpAddress>) {
          octetString(std::span<const std::byte>(held.value), tag::ipAddress);
        } else if constexpr (std::is_same_v<T, Counter32>) {
          unsigned32(held.value, tag::counter32);
        } else if constexpr (std::is_same_v<T, Gauge32>) {
          unsigned32(held.value, tag::gauge32);
        } else if constexpr (std::is_same_v<T, TimeTicks>) {
          unsigned32(held.value, tag::timeticks);
        } else if constexpr (std::is_same_v<T, Counter64>) {
          unsigned64(held.value, tag::counter64);
        } else if constexpr (std::is_same_v<T, Opaque>) {
          octetString(held.value, tag::opaque);
        } else {
          switch (held) {
            case ValueException::NoSuchObject:
              tlv(tag::noSuchObject, {});
              break;
            case ValueException::NoSuchInstance:
              tlv(tag::noSuchInstance, {});
              break;
            case ValueException::EndOfMibView:
              tlv(tag::endOfMibView, {});
              break;
          }
        }
      },
      v);
}

void Writer::write(const Varbind& vb) {
  auto s = beginSequence();
  objectIdentifier(vb.name);
  write(vb.val);
}

void Writer::varbindList(std::span<const Varbind> vbs) {
  auto s = beginSequence();
  for (const auto& vb : vbs) write(vb);
}

void Writer::raw(std::span<const std::byte> bytes) {
  if (m_ec) return;
  m_buf.insert(m_buf.end(), bytes.begin(), bytes.end());
}

void Writer::tlv(TagType t, std::span<const std::byte> content) {
  if (m_ec) return;
  putTag(t);
  putLength(content.size());
  m_buf.insert(m_buf.end(), content.begin(), content.end());
}

}  // namespace snmpio::ber
