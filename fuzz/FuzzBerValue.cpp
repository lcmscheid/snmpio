// Decode arbitrary bytes as a Varbind Value, then -- if that succeeded -- re-encode and decode
// again. The second pass is the interesting half: it asserts that anything the decoder accepts is
// something the encoder can express and the decoder will read back identically, which is the
// invariant a message layer will rely on when it forwards a Value it did not construct.
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
  const auto decoded = r.anyValue();
  if (!decoded) {
    assert(!r.ok() && "a failed decode must leave an error behind");
    return 0;
  }

  // Rendering must not crash on anything that decoded.
  (void)toString(*decoded);

  ber::Writer w;
  w.write(*decoded);
  assert(w.ok() && "a decoded Value must be re-encodable");
  const auto reencoded = w.take();

  ber::Reader r2(reencoded);
  const auto again = r2.anyValue();
  assert(again && "our own encoding must decode");
  assert(r2.finish() && "our own encoding must be exactly consumed");
  assert(*again == *decoded && "encode/decode must be the identity");
  return 0;
}
