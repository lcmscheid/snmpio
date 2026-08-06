#include <snmpio/Oid.hpp>

#include <array>
#include <charconv>
#include <cstdio>
#include <limits>

namespace snmpio {

std::optional<Oid> Oid::parse(std::string_view text) {
  if (!text.empty() && text.front() == '.') text.remove_prefix(1);
  if (text.empty()) return std::nullopt;

  Oid result;
  std::size_t start = 0;
  while (true) {
    const std::size_t dot = text.find('.', start);
    const std::string_view part =
        text.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
    if (part.empty()) return std::nullopt;
    // from_chars would accept a leading '+'; SNMP dotted form does not.
    if (part.front() < '0' || part.front() > '9') return std::nullopt;

    std::uint64_t wide = 0;
    const auto* first = part.data();
    const auto* last = part.data() + part.size();
    const auto [ptr, ec] = std::from_chars(first, last, wide);
    if (ec != std::errc{} || ptr != last) return std::nullopt;
    if (wide > std::numeric_limits<ValueType>::max()) return std::nullopt;

    if (result.size() == maxSubids) return std::nullopt;
    result.pushBack(static_cast<ValueType>(wide));

    if (dot == std::string_view::npos) break;
    start = dot + 1;
  }
  return result;
}

std::string Oid::toString() const {
  std::string out;
  out.reserve(m_subids.size() * 4);
  std::array<char, 12> scratch{};
  for (std::size_t i = 0; i < m_subids.size(); ++i) {
    if (i != 0) out.push_back('.');
    const auto [ptr, ec] =
        std::to_chars(scratch.data(), scratch.data() + scratch.size(), m_subids[i]);
    out.append(scratch.data(), ptr);
  }
  return out;
}

bool Oid::isEncodable() const noexcept {
  if (m_subids.size() < 2) return false;
  if (m_subids.size() > maxSubids) return false;
  if (m_subids[0] > 2) return false;
  // X.690 8.19.4: the first two arcs are packed as 40*first + second, which is only reversible
  // when second stays below 40 for first arcs 0 and 1. For first arc 2 the second arc is
  // unbounded, because anything at or above 80 unambiguously decodes back to 2.
  if (m_subids[0] < 2 && m_subids[1] > 39) return false;
  if (m_subids[0] == 2 && m_subids[1] > std::numeric_limits<ValueType>::max() - 80) {
    return false;  // 40*2 + second would not fit a 32-bit sub-identifier
  }
  return true;
}

bool Oid::isPrefixOf(const Oid& other) const noexcept {
  if (m_subids.size() > other.m_subids.size()) return false;
  for (std::size_t i = 0; i < m_subids.size(); ++i) {
    if (m_subids[i] != other.m_subids[i]) return false;
  }
  return true;
}

Oid Oid::child(ValueType subid) const {
  Oid out = *this;
  out.pushBack(subid);
  return out;
}

}  // namespace snmpio
