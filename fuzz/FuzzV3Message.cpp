// The SNMPv3 datagram: message framing, the USM security parameters inside their OCTET STRING,
// and the ScopedPDU. Two things here are worth a fuzzer that the v2c path does not have -- the
// digest's offset is derived from attacker-controlled length fields, and verifyAuth indexes the
// datagram with it.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <snmpio/Usm.hpp>
#include <snmpio/V3Message.hpp>

// libFuzzer looks this entry point up by name; the spelling is not ours to pick.
// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace snmpio;

  const std::span<const std::byte> input(reinterpret_cast<const std::byte*>(data), size);

  net::ErrorCode ec;
  const auto decoded = decodeV3Message(input, ec);
  if (!decoded) {
    assert(ec);
    return 0;
  }
  assert(!ec);

  // The offset the decoder reported has to name a real slice of this datagram, or verifyAuth
  // would read past the end of it.
  assert(decoded->authParamsOffset + decoded->security.authParams.size() <= size);

  // Any key will do: what is being exercised is the blanking and the indexing, not the crypto.
  static const Octets key(32, std::byte{0xA5});
  verifyAuth(input, *decoded, AuthProtocol::Sha256, key, ec);

  // Round-trip identity, as everywhere else in this codec. The digest cannot survive a re-encode
  // -- it is computed over the message, and the message is what changed -- so the comparison is
  // made at noAuthNoPriv, where there is no digest.
  V3Header header = decoded->header;
  header.level = SecurityLevel::NoAuthNoPriv;
  const auto reencoded =
      encodeV3Message(header, decoded->security, decoded->scoped, AuthProtocol::None, {}, ec);
  assert(!ec);

  const auto again = decodeV3Message(reencoded, ec);
  assert(again);
  assert(again->header.msgId == decoded->header.msgId);
  assert(again->header.maxSize == decoded->header.maxSize);
  assert(again->header.reportable == decoded->header.reportable);
  assert(again->security.engineId == decoded->security.engineId);
  assert(again->security.boots == decoded->security.boots);
  assert(again->security.time == decoded->security.time);
  assert(again->security.userName == decoded->security.userName);
  assert(again->security.privParams == decoded->security.privParams);
  assert(again->scoped.contextEngineId == decoded->scoped.contextEngineId);
  assert(again->scoped.contextName == decoded->scoped.contextName);
  assert(again->scoped.pdu.type == decoded->scoped.pdu.type);
  assert(again->scoped.pdu.requestId == decoded->scoped.pdu.requestId);
  assert(again->scoped.pdu.varbinds == decoded->scoped.pdu.varbinds);
  return 0;
}
