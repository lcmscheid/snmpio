// The dotted-decimal parser is the one place untrusted *text* enters the OID type -- configuration
// files, command lines, and anything a caller passes through. Whatever it accepts must survive a
// print/parse round trip.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <snmpio/Oid.hpp>
#include <snmpio/ber/Writer.hpp>

// libFuzzer looks this entry point up by name; the spelling is not ours to pick.
// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace snmpio;

  const std::string_view text(reinterpret_cast<const char*>(data), size);
  const auto parsed = Oid::parse(text);
  if (!parsed) return 0;

  const auto printed = parsed->toString();
  const auto reparsed = Oid::parse(printed);
  assert(reparsed && "toString output must parse");
  assert(*reparsed == *parsed && "print/parse must be the identity");

  if (parsed->isEncodable()) {
    ber::Writer w;
    w.objectIdentifier(*parsed);
    assert(w.ok());
    assert(w.size() == ber::encodedOidSize(*parsed));
  }
  return 0;
}
