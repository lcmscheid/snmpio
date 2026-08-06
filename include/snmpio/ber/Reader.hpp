#ifndef SNMPIO_BER_READER_HPP
#define SNMPIO_BER_READER_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <snmpio/Error.hpp>
#include <snmpio/Oid.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/ber/Tag.hpp>

namespace snmpio::ber {

// A non-throwing, non-allocating cursor over a BER-encoded buffer.
//
// Errors are sticky: the first failure is recorded and every subsequent read is a no-op returning
// std::nullopt. That means a decoder can be written as a straight run of reads with a single check
// at the end, instead of a check after every field -- which matters here, because the input is
// attacker-controlled and the error paths are the ones that must not be skipped by accident.
//
// Nesting is handled by Scope: enter() clamps the Reader to the content of a constructed TLV, and
// the returned guard restores the outer bound on destruction. A read can therefore never wander
// past the end of the element it is inside, and the guard reports leftover bytes as TrailingData.
//
// The Reader does not own the buffer. It must not outlive the bytes it was constructed over.
class Reader {
 public:
  explicit Reader(std::span<const std::byte> input) noexcept : m_buf(input), m_end(input.size()) {}

  [[nodiscard]] bool ok() const noexcept { return !m_ec; }
  explicit operator bool() const noexcept { return ok(); }
  [[nodiscard]] net::ErrorCode error() const noexcept { return m_ec; }

  // Records e if no error has been recorded yet. Later stages use this to fold higher-level
  // faults into the same sticky channel.
  void fail(Errc e) noexcept;

  [[nodiscard]] std::size_t remaining() const noexcept { return m_end - m_pos; }
  [[nodiscard]] bool atEnd() const noexcept { return m_pos >= m_end; }
  [[nodiscard]] std::size_t position() const noexcept { return m_pos; }

  // The next identifier octet, without consuming it. Empty at the end of the current Scope.
  [[nodiscard]] std::optional<TagType> peekTag() const noexcept;

  // Asserts the whole input was consumed. Call once, at the outermost level.
  bool finish() noexcept;

  // Guard returned by enter(). Immovable and Scope-bound on purpose: its whole job is to pair a
  // bound change with its restoration.
  class Scope {
   public:
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;
    Scope(Scope&&) = delete;
    Scope& operator=(Scope&&) = delete;
    ~Scope();

   private:
    friend class Reader;
    Scope(Reader* r, std::size_t savedEnd, std::size_t contentEnd) noexcept
        : m_reader(r), m_savedEnd(savedEnd), m_contentEnd(contentEnd) {}

    Reader* m_reader;
    std::size_t m_savedEnd;
    std::size_t m_contentEnd;
  };

  // Enters a constructed TLV of the given tag, clamping subsequent reads to its content. On
  // failure the error is recorded and the Scope is left empty, so reads inside it fail rather
  // than reading whatever followed.
  [[nodiscard]] Scope enter(TagType expected);

  // Primitives. Each checks the tag, then the content.
  std::optional<std::int32_t> integer(TagType expected = tag::integer);
  std::optional<std::uint32_t> unsigned32(TagType expected);
  std::optional<std::uint64_t> unsigned64(TagType expected);
  std::optional<Octets> octetString(TagType expected = tag::octetString);
  // Borrows the content instead of copying it; valid as long as the underlying buffer is.
  std::optional<std::span<const std::byte>> octetStringView(TagType expected = tag::octetString);
  bool nullValue();
  std::optional<Oid> objectIdentifier();

  // Any Value a Varbind may carry, dispatched on the tag.
  std::optional<Value> anyValue();
  std::optional<Varbind> readVarbind();
  // A VarBindList: SEQUENCE OF VarBind. Consumes the whole sequence.
  std::optional<std::vector<Varbind>> varbindList();

  // Header-level access, for the message and PDU layers in later stages.
  struct Header {
    TagType tag = 0;
    std::size_t length = 0;
  };
  std::optional<Header> readHeader();
  // Consumes and discards the next TLV whatever it is, returning its full extent (Header
  // included). Used to skip fields we do not model.
  std::optional<std::span<const std::byte>> skipElement();

 private:
  // Reads a primitive Header and returns its content, having checked the tag.
  std::optional<std::span<const std::byte>> primitiveContent(TagType expected);
  std::optional<std::uint64_t> unsignedContent(TagType expected, unsigned maxSignificant);

  std::span<const std::byte> m_buf;
  std::size_t m_pos = 0;
  std::size_t m_end = 0;
  net::ErrorCode m_ec{};
};

// Decodes an OBJECT IDENTIFIER's content Octets (i.e. the V of the TLV). Exposed because the
// message layer meets bare OID content in a few places, and because it is the single most
// fiddly decoder in the codec and deserves to be directly testable.
std::optional<Oid> decodeOidContent(std::span<const std::byte> content, Errc& out);

}  // namespace snmpio::ber

#endif  // SNMPIO_BER_READER_HPP
