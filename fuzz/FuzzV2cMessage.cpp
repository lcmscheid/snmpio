// The whole datagram path: message framing, the version and community fields, and the PDU inside
// them. This is where bytes from the network first meet the library, so it is the surface that
// most deserves a fuzzer.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>

#include <snmpio/Pdu.hpp>

// libFuzzer looks this entry point up by name; the spelling is not ours to pick.
// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace snmpio;

  const std::span<const std::byte> input(reinterpret_cast<const std::byte*>(data), size);

  net::ErrorCode ec;
  const auto decoded = decodeV2cMessage(input, ec);
  if (!decoded) {
    assert(ec);
    return 0;
  }
  assert(!ec);

  // Anything accepted must re-encode and decode back identically -- the same round-trip identity
  // the codec fuzzers assert, one layer up.
  const auto reencoded = encodeV2cMessage(decoded->community, decoded->pdu, ec);
  assert(!ec);

  const auto again = decodeV2cMessage(reencoded, ec);
  assert(again);
  assert(again->community == decoded->community);
  assert(again->pdu.type == decoded->pdu.type);
  assert(again->pdu.requestId == decoded->pdu.requestId);
  assert(again->pdu.errorStatus == decoded->pdu.errorStatus);
  assert(again->pdu.errorIndex == decoded->pdu.errorIndex);
  assert(again->pdu.varbinds == decoded->pdu.varbinds);
  return 0;
}
