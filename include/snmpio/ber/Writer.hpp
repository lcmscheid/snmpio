#ifndef SNMPIO_BER_WRITER_HPP
#define SNMPIO_BER_WRITER_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <snmpio/Error.hpp>
#include <snmpio/Oid.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/ber/Tag.hpp>

namespace snmpio::ber {

// Builds a BER encoding into a contiguous buffer.
//
// BER puts a length before its content, and SNMP nests sequences several deep, so a forward
// Writer cannot know a length when it needs to write it. This one writes a one-octet placeholder,
// then patches it when the sequence closes, widening it in place if the content turned out to need
// more than 127 Octets. The alternative -- encoding back-to-front -- is faster but makes every
// encoder read backwards; at SNMP message sizes the memmove is not worth that.
//
// Errors are sticky, matching Reader: encoding something unencodable records the fault and turns
// subsequent writes into no-ops, so a caller checks once at the end.
class Writer {
 public:
  Writer() = default;
  explicit Writer(std::size_t reserveBytes) { m_buf.reserve(reserveBytes); }

  [[nodiscard]] bool ok() const noexcept { return !m_ec; }
  explicit operator bool() const noexcept { return ok(); }
  [[nodiscard]] net::ErrorCode error() const noexcept { return m_ec; }
  void fail(Errc e) noexcept;

  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return m_buf; }
  [[nodiscard]] std::size_t size() const noexcept { return m_buf.size(); }
  std::vector<std::byte> take() noexcept { return std::move(m_buf); }
  void clear() noexcept {
    m_buf.clear();
    m_ec = {};
  }

  // Guard returned by beginConstructed(). Patches the length on destruction.
  class Scope {
   public:
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;
    Scope(Scope&&) = delete;
    Scope& operator=(Scope&&) = delete;
    ~Scope();

   private:
    friend class Writer;
    Scope(Writer* w, std::size_t lengthPos) noexcept : m_writer(w), m_lengthPos(lengthPos) {}

    Writer* m_writer;
    std::size_t m_lengthPos;
  };

  [[nodiscard]] Scope beginConstructed(TagType t);
  [[nodiscard]] Scope beginSequence() { return beginConstructed(tag::sequence); }

  void integer(std::int32_t v, TagType t = tag::integer);
  void unsigned32(std::uint32_t v, TagType t);
  void unsigned64(std::uint64_t v, TagType t);
  void octetString(std::span<const std::byte> v, TagType t = tag::octetString);
  void octetString(std::string_view v, TagType t = tag::octetString);
  void nullValue();
  void objectIdentifier(const Oid& o);

  void write(const Value& v);
  void write(const Varbind& vb);
  void varbindList(std::span<const Varbind> vbs);

  // Raw escape hatches for the message layer: a preformed TLV, or a Header the caller fills in.
  void raw(std::span<const std::byte> bytes);
  void tlv(TagType t, std::span<const std::byte> content);

 private:
  void put(std::byte b) { m_buf.push_back(b); }
  void putTag(TagType t) { m_buf.push_back(static_cast<std::byte>(t)); }
  void putLength(std::size_t n);

  std::vector<std::byte> m_buf;
  net::ErrorCode m_ec{};
};

// Number of Octets objectIdentifier() would emit for o, Header included. Returns 0 if o is not
// encodable. The message layer needs this to size buffers before it commits to an encoding.
std::size_t encodedOidSize(const Oid& o) noexcept;

}  // namespace snmpio::ber

#endif  // SNMPIO_BER_WRITER_HPP
