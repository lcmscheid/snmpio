#ifndef SNMPIO_TESTS_BYTES_HPP
#define SNMPIO_TESTS_BYTES_HPP

#include <cstddef>
#include <initializer_list>
#include <iomanip>
#include <ostream>
#include <span>
#include <string>
#include <vector>

#include <snmpio/Value.hpp>

namespace snmpio::test {

inline std::vector<std::byte> bytes(std::initializer_list<int> vals) {
  std::vector<std::byte> out;
  out.reserve(vals.size());
  for (int v : vals) out.push_back(static_cast<std::byte>(v));
  return out;
}

inline std::string hex(std::span<const std::byte> b) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < b.size(); ++i) {
    if (i != 0) out.push_back(' ');
    const auto u = static_cast<unsigned char>(b[i]);
    out.push_back(digits[u >> 4]);
    out.push_back(digits[u & 0x0F]);
  }
  return out;
}

}  // namespace snmpio::test

// Printers, so a failing byte comparison reports hex rather than a wall of \xNN.
namespace std {
inline void PrintTo(const vector<byte>& b, ostream* os) {
  *os << ::snmpio::test::hex(b);
}
}  // namespace std

namespace snmpio {
inline void PrintTo(const Oid& o, std::ostream* os) {
  *os << o.toString();
}
inline void PrintTo(const Value& v, std::ostream* os) {
  *os << toString(v);
}
inline void PrintTo(const Varbind& vb, std::ostream* os) {
  *os << vb.name.toString() << " = " << toString(vb.val);
}
}  // namespace snmpio

#endif  // SNMPIO_TESTS_BYTES_HPP
