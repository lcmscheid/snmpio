#ifndef SNMPIO_OID_HPP
#define SNMPIO_OID_HPP

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace snmpio {

// An object identifier: a sequence of 32-bit sub-identifiers.
//
// The type is deliberately permissive -- it will hold any sequence of sub-identifiers, including
// ones X.690 cannot encode -- because it also has to represent things that arrived off the wire
// from a misbehaving Agent. Encodability is a separate question, asked by isEncodable().
//
// Comparison is lexicographic on sub-identifiers, which is exactly SNMP's ordering, so the walk
// loop's "is this OID greater than the last one" check is a plain operator<.
class Oid {
 public:
  using ValueType = std::uint32_t;
  using Container = std::vector<ValueType>;
  using ConstIterator = Container::const_iterator;

  // RFC 3416 section 4.1: an object name carries at most 128 sub-identifiers.
  static constexpr std::size_t maxSubids = 128;

  Oid() = default;
  Oid(std::initializer_list<ValueType> subids) : m_subids(subids) {}
  explicit Oid(Container subids) : m_subids(std::move(subids)) {}
  explicit Oid(std::span<const ValueType> subids) : m_subids(subids.begin(), subids.end()) {}

  // Parses dotted-decimal form: "1.3.6.1.2.1.1.3.0", with an optional leading dot. Rejects empty
  // components, non-digits, values above 2^32-1 and more than maxSubids components.
  static std::optional<Oid> parse(std::string_view text);

  [[nodiscard]] std::string toString() const;

  [[nodiscard]] bool empty() const noexcept { return m_subids.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return m_subids.size(); }
  ValueType operator[](std::size_t i) const { return m_subids[i]; }
  [[nodiscard]] ConstIterator begin() const noexcept { return m_subids.begin(); }
  [[nodiscard]] ConstIterator end() const noexcept { return m_subids.end(); }
  [[nodiscard]] std::span<const ValueType> subids() const noexcept { return m_subids; }

  void pushBack(ValueType subid) { m_subids.push_back(subid); }
  void reserve(std::size_t n) { m_subids.reserve(n); }
  void clear() noexcept { m_subids.clear(); }

  // True if this OID can be written as a BER OBJECT IDENTIFIER: at least two arcs, first arc <= 2,
  // and second arc <= 39 when the first is 0 or 1 (X.690 section 8.19 packs the two into one
  // sub-identifier as 40*first + second).
  [[nodiscard]] bool isEncodable() const noexcept;

  // Subtree membership, in the sense CONTEXT.md gives it: the set of OIDs at or beneath a base.
  // An OID is a prefix of itself, so base.isPrefixOf(base) is true.
  [[nodiscard]] bool isPrefixOf(const Oid& other) const noexcept;

  // The child obtained by appending one sub-identifier -- e.g. an instance under a column.
  [[nodiscard]] Oid child(ValueType subid) const;

  friend bool operator==(const Oid& a, const Oid& b) noexcept { return a.m_subids == b.m_subids; }
  friend auto operator<=>(const Oid& a, const Oid& b) noexcept { return a.m_subids <=> b.m_subids; }

 private:
  Container m_subids;
};

}  // namespace snmpio

#endif  // SNMPIO_OID_HPP
