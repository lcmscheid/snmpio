#include <snmpio/Value.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <string>

namespace snmpio {
namespace {

bool allPrintable(const Octets& b) {
  return !b.empty() && std::ranges::all_of(b, [](std::byte c) {
    const auto u = static_cast<unsigned char>(c);
    return u >= 0x20 && u < 0x7F;
  });
}

std::string hex(const Octets& b) {
  static constexpr std::array<char, 17> digits{"0123456789abcdef"};
  std::string out;
  out.reserve(b.size() * 3);
  for (std::size_t i = 0; i < b.size(); ++i) {
    if (i != 0) out.push_back(' ');
    const auto u = static_cast<unsigned char>(b[i]);
    out.push_back(digits[u >> 4]);
    out.push_back(digits[u & 0x0F]);
  }
  return out;
}

template <typename T>
std::string num(T v) {
  std::array<char, 24> scratch{};
  const auto [ptr, ec] = std::to_chars(scratch.data(), scratch.data() + scratch.size(), v);
  return std::string(scratch.data(), ptr);
}

}  // namespace

std::string_view toString(ValueException e) noexcept {
  switch (e) {
    case ValueException::NoSuchObject:
      return "noSuchObject";
    case ValueException::NoSuchInstance:
      return "noSuchInstance";
    case ValueException::EndOfMibView:
      return "endOfMibView";
  }
  return "unknownException";
}

std::string toString(const Value& v) {
  return std::visit(
      [](const auto& held) -> std::string {
        using T = std::decay_t<decltype(held)>;
        if constexpr (std::is_same_v<T, NullType>) {
          return "NULL";
        } else if constexpr (std::is_same_v<T, std::int32_t>) {
          return num(held);
        } else if constexpr (std::is_same_v<T, Octets>) {
          if (held.empty()) return "\"\"";
          if (allPrintable(held)) {
            std::string out = "\"";
            for (const std::byte c : held) out.push_back(static_cast<char>(c));
            out.push_back('"');
            return out;
          }
          return hex(held);
        } else if constexpr (std::is_same_v<T, Oid>) {
          return held.toString();
        } else if constexpr (std::is_same_v<T, IpAddress>) {
          std::string out;
          for (std::size_t i = 0; i < held.value.size(); ++i) {
            if (i != 0) out.push_back('.');
            out += num(static_cast<unsigned>(held.value[i]));
          }
          return out;
        } else if constexpr (std::is_same_v<T, Counter32> || std::is_same_v<T, Gauge32> ||
                             std::is_same_v<T, TimeTicks> || std::is_same_v<T, Counter64>) {
          return num(held.value);
        } else if constexpr (std::is_same_v<T, Opaque>) {
          return hex(held.value);
        } else {
          return std::string(toString(held));
        }
      },
      v);
}

}  // namespace snmpio
