// The nesting path: a VarBindList exercises Scope entry, length patching and the trailing-data
// checks that a flat Value never reaches.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>

#include <snmpio/ber/Reader.hpp>
#include <snmpio/ber/Writer.hpp>

// libFuzzer looks this entry point up by name; the spelling is not ours to pick.
// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace snmpio;

  const std::span<const std::byte> input(reinterpret_cast<const std::byte*>(data), size);

  ber::Reader r(input);
  const auto decoded = r.varbindList();
  if (!decoded) {
    assert(!r.ok());
    return 0;
  }

  ber::Writer w;
  w.varbindList(*decoded);
  assert(w.ok());
  const auto reencoded = w.take();

  ber::Reader r2(reencoded);
  const auto again = r2.varbindList();
  assert(again);
  assert(r2.finish());
  assert(*again == *decoded);
  return 0;
}
