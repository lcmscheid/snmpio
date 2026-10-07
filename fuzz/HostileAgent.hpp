#ifndef SNMPIO_FUZZ_HOSTILEAGENT_HPP
#define SNMPIO_FUZZ_HOSTILEAGENT_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <snmpio/Oid.hpp>
#include <snmpio/Pdu.hpp>
#include <snmpio/Target.hpp>
#include <snmpio/Usm.hpp>
#include <snmpio/V3Message.hpp>
#include <snmpio/Value.hpp>
#include <snmpio/detail/Net.hpp>

namespace snmpio::fuzz {

// The fuzz input, read front to back as a series of choices. A read past the end returns zero, and
// zero is always the benign choice, so an input runs out into a compliant Agent and every
// iteration ends soon after its interesting part is spent.
class Script {
 public:
  explicit Script(std::span<const std::byte> data) : m_data(data) {}

  [[nodiscard]] bool exhausted() const noexcept { return m_pos >= m_data.size(); }

  std::uint8_t byte() noexcept {
    if (exhausted()) return 0;
    return std::to_integer<std::uint8_t>(m_data[m_pos++]);
  }
  std::size_t pick(std::size_t n) noexcept { return byte() % n; }
  std::int32_t int32() noexcept {
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8U) | byte();
    return static_cast<std::int32_t>(v);
  }
  Octets bytes(std::size_t n) {
    const auto take = exhausted() ? 0 : std::min(n, m_data.size() - m_pos);
    const auto from = m_data.subspan(m_pos, take);
    m_pos += take;
    return {from.begin(), from.end()};
  }

 private:
  std::span<const std::byte> m_data;
  std::size_t m_pos = 0;
};

// Which protocol, and at which Security Level, one iteration speaks.
enum class Mode : std::uint8_t { V2c, NoAuthNoPriv, AuthNoPriv, AuthPriv };

struct Profile {
  Mode mode = Mode::V2c;
  Community community{"public"};
  Credentials creds;
};

// The OID Outstanding Request `index` asks for. The Agent reads it back out of each request to
// learn which Outstanding Request a Message ID belongs to, which nothing else on the wire says.
inline Oid requestOid(std::size_t index) {
  return Oid{1, 3, 6, 1, 2, 1, 1, static_cast<Oid::ValueType>(index + 1), 0};
}

inline std::optional<std::size_t> requestIndex(const Pdu& pdu) {
  if (pdu.varbinds.empty()) return std::nullopt;
  const Oid& name = pdu.varbinds.front().name;
  const Oid base{1, 3, 6, 1, 2, 1, 1};
  if (name.size() != base.size() + 2 || !base.isPrefixOf(name) || name[base.size()] == 0) {
    return std::nullopt;
  }
  if (name[base.size() + 1] != 0) return std::nullopt;
  return std::size_t{name[base.size()]} - 1;
}

struct Keys {
  Octets auth;
  Octets priv;
};

// The Localized Keys for these Credentials at this engineID. Derivation is a megabyte hash per key,
// and the Credentials come from a short fixed list, so the cache outlives the iteration. It is
// bounded because the engineIDs are the fuzz input's to choose.
inline Keys keysFor(const Credentials& creds, const Octets& engineId) {
  if (!isAuthenticated(creds.level) || engineId.empty()) return {};
  static std::map<std::tuple<AuthProtocol, PrivProtocol, Octets>, Keys> cache;
  auto cacheKey = std::make_tuple(creds.authProtocol, creds.privProtocol, engineId);
  if (const auto it = cache.find(cacheKey); it != cache.end()) return it->second;
  if (cache.size() >= 256) cache.clear();

  net::ErrorCode ec;
  Keys keys;
  keys.auth = localizedAuthKey(creds, engineId, ec);
  if (isEncrypted(creds.level)) keys.priv = localizedPrivKey(creds, engineId, ec);
  return cache.emplace(std::move(cacheKey), std::move(keys)).first->second;
}

// The Report a real Agent sends for usmStats counter `counter` (RFC 3414 section 5).
inline Pdu usmReport(std::uint32_t counter) {
  Pdu pdu;
  pdu.type = PduType::Report;
  pdu.varbinds = {Varbind{Oid{1, 3, 6, 1, 6, 3, 15, 1, 1, counter, 0}, Counter32{1}}};
  return pdu;
}

// A Scripted Agent whose script is the fuzz input, and the fuzzer's mouthpiece. It reads every real
// request the Client sends, so it knows which Message IDs are outstanding and which Outstanding
// Request owns each one, and answers each with whatever the input asks for: silence, compliant
// replies, replies with chosen fields rewritten, mutated bytes, mutated bytes signed again with the
// real key, or noise. Any of them can go out from a second socket instead, which is an off-path
// sender who guessed right about everything but the source address.
//
// It is not tests/ScriptedV3Agent. That one builds each reply from a few knobs, and the fields it
// fills in for itself -- the user name, the request-id, the digest -- are exactly the ones a fuzzer
// has to be able to get wrong. Every datagram this one sends is handed to `onSent` first, so the
// oracle judges the bytes that went out rather than what the Agent meant by them.
class HostileAgent {
 public:
  enum class Owner : std::uint8_t {
    Request,    // a Get the fuzzer initiated; `request` says which
    Discovery,  // either phase of Engine Discovery
    Unknown,    // a request this Agent could not read
  };

  // What the Agent learnt from the request that carried one Message ID (v3) or request-id (v2c).
  struct Seen {
    Owner owner = Owner::Unknown;
    std::size_t request = 0;
    SecurityLevel level = SecurityLevel::NoAuthNoPriv;
    Octets engineId;
  };

  using OnSent = std::function<void(std::span<const std::byte> datagram, bool fromTarget)>;

  // RFC 3414 section 5's counters.
  static constexpr std::uint32_t notInTimeWindows = 2;
  static constexpr std::uint32_t unknownUserNames = 3;
  static constexpr std::uint32_t unknownEngineIds = 4;
  static constexpr std::uint32_t wrongDigests = 5;
  static constexpr std::uint32_t decryptionErrors = 6;

  HostileAgent(net::IoContext& io, Profile profile, Script& script)
      : m_socket(io, net::UdpEndpoint(net::asio::ip::make_address("127.0.0.1"), 0)),
        m_stranger(io, net::UdpEndpoint(net::asio::ip::make_address("127.0.0.1"), 0)),
        m_profile(std::move(profile)),
        m_script(&script),
        m_keys(keysFor(m_profile.creds, m_engineId)) {
    receive();
  }

  void setOnSent(OnSent onSent) { m_onSent = std::move(onSent); }

  [[nodiscard]] net::UdpEndpoint endpoint() const { return m_socket.local_endpoint(); }
  [[nodiscard]] const Profile& profile() const noexcept { return m_profile; }

  [[nodiscard]] const Seen* seen(std::int32_t id) const {
    const auto it = m_seen.find(id);
    return it == m_seen.end() ? nullptr : &it->second;
  }

  void close() {
    net::ErrorCode ignored;
    std::ignore = m_socket.close(ignored);
    std::ignore = m_stranger.close(ignored);
  }

 private:
  // A v3 reply before it is encoded: every field the script can rewrite, and the keys it is
  // signed and encrypted with.
  struct V3Reply {
    V3Header header;
    UsmParameters usm;
    ScopedPdu scoped;
    Keys keys;
    bool corruptAuth = false;
    bool corruptPriv = false;
  };

  void receive() {
    m_socket.async_receive_from(net::asio::buffer(m_buf), m_from,
                                [this](net::ErrorCode ec, std::size_t n) {
                                  if (ec) return;
                                  answer(std::span<const std::byte>(m_buf).first(n));
                                  receive();
                                });
  }

  void remember(std::int32_t id, Seen seen) {
    if (m_seen.emplace(id, std::move(seen)).second) m_ids.push_back(id);
  }

  std::int32_t anotherId() {
    if (m_ids.empty()) return m_script->int32();
    return m_ids[m_script->pick(m_ids.size())];
  }

  static Seen seenFrom(const Pdu& pdu) {
    Seen s;
    if (pdu.varbinds.empty()) {
      s.owner = Owner::Discovery;
    } else if (const auto index = requestIndex(pdu)) {
      s.owner = Owner::Request;
      s.request = *index;
    }
    return s;
  }

  // The compliant Response: the request's Varbinds, each given a value.
  static Pdu respondTo(const Pdu& request) {
    Pdu pdu;
    pdu.type = PduType::Response;
    pdu.requestId = request.requestId;
    for (const auto& vb : request.varbinds) pdu.varbinds.push_back(Varbind{vb.name, 42});
    return pdu;
  }

  void answer(std::span<const std::byte> datagram) {
    if (m_profile.mode == Mode::V2c) {
      answerV2c(datagram);
    } else {
      answerV3(datagram);
    }
  }

  // How many replies this request gets: one compliant one once the script has run out, and
  // otherwise between none and three.
  std::size_t replyCount() {
    if (m_script->exhausted()) return 1;
    return (std::size_t{m_script->byte()} + 1) % 4;
  }

  // ---- v2c ----

  void answerV2c(std::span<const std::byte> datagram) {
    net::ErrorCode ec;
    const auto msg = decodeV2cMessage(datagram, ec);
    if (!msg) return;
    remember(msg->pdu.requestId, seenFrom(msg->pdu));

    for (auto n = replyCount(); n > 0; --n) {
      const auto kind = m_script->byte();
      const bool fromTarget = (kind & 0x80U) == 0;
      std::string community = msg->community;
      Pdu pdu = respondTo(msg->pdu);
      Octets bytes;
      switch (kind % 5) {
        case 0:
          bytes = encodeV2cMessage(community, pdu, ec);
          break;
        case 1:
          rewriteV2c(community, pdu);
          bytes = encodeV2cMessage(community, pdu, ec);
          break;
        case 2:
        case 3:
          rewriteV2c(community, pdu);
          bytes = encodeV2cMessage(community, pdu, ec);
          mutate(bytes);
          break;
        default:
          bytes = m_script->bytes(std::size_t{m_script->byte()} * 2);
          break;
      }
      send(bytes, fromTarget);
    }
  }

  void rewriteV2c(std::string& community, Pdu& pdu) {
    rewriteId(pdu.requestId);
    rewritePdu(pdu);
    if (m_script->pick(2) == 1) community = "private";
  }

  // ---- v3 ----

  void answerV3(std::span<const std::byte> datagram) {
    net::ErrorCode ec;
    auto msg = decodeV3Message(datagram, ec);
    if (!msg) return;

    const Keys keys = keysFor(m_profile.creds, msg->security.engineId);
    const bool authenticated =
        isAuthenticated(msg->header.level) &&
        verifyAuth(datagram, *msg, m_profile.creds.authProtocol, keys.auth, ec);
    const bool readable = !isEncrypted(msg->header.level) ||
                          decryptScopedPdu(*msg, m_profile.creds.privProtocol, keys.priv, ec);

    Seen seen = readable ? seenFrom(msg->scoped.pdu) : Seen{};
    seen.level = msg->header.level;
    seen.engineId = msg->security.engineId;
    remember(msg->header.msgId, std::move(seen));

    for (auto n = replyCount(); n > 0; --n) {
      const auto kind = m_script->byte();
      const bool fromTarget = (kind & 0x80U) == 0;
      V3Reply reply = compliantV3(*msg, authenticated, readable);
      Octets bytes;
      switch (kind % 5) {
        case 0:
          bytes = encode(reply);
          break;
        case 1:
          rewriteV3(reply, *msg);
          bytes = encode(reply);
          break;
        case 2:
          rewriteV3(reply, *msg);
          bytes = encode(reply);
          mutate(bytes);
          break;
        case 3:
          rewriteV3(reply, *msg);
          bytes = encode(reply);
          mutate(bytes);
          resign(bytes, reply);
          break;
        default:
          bytes = m_script->bytes(std::size_t{m_script->byte()} * 2);
          break;
      }
      send(bytes, fromTarget);
    }
  }

  // What a compliant Agent answers, in the order RFC 3414 section 3.2 checks things.
  [[nodiscard]] V3Reply compliantV3(const V3Message& request, bool authenticated,
                                    bool readable) const {
    V3Reply reply;
    reply.header.msgId = request.header.msgId;
    reply.header.reportable = false;
    reply.usm.engineId = m_engineId;
    reply.usm.boots = m_boots;
    reply.usm.time = m_time;
    reply.usm.userName = m_profile.creds.userName;
    reply.scoped.contextEngineId = m_engineId;
    reply.keys = m_keys;

    const auto report = [&reply, &request](std::uint32_t counter, SecurityLevel level) {
      reply.header.level = level;
      reply.scoped.pdu = usmReport(counter);
      reply.scoped.pdu.requestId = request.scoped.pdu.requestId;
    };
    const UsmParameters& usm = request.security;
    if (!readable) {
      report(decryptionErrors, SecurityLevel::NoAuthNoPriv);
    } else if (usm.engineId != m_engineId) {
      report(unknownEngineIds, SecurityLevel::NoAuthNoPriv);
    } else if (isAuthenticated(request.header.level) && usm.userName != m_profile.creds.userName) {
      report(unknownUserNames, SecurityLevel::NoAuthNoPriv);
    } else if (isAuthenticated(request.header.level) && !authenticated) {
      report(wrongDigests, SecurityLevel::NoAuthNoPriv);
    } else if (isAuthenticated(request.header.level) &&
               (usm.boots != m_boots || std::abs(usm.time - m_time) > timeWindow)) {
      report(notInTimeWindows, m_profile.creds.level);
    } else {
      reply.header.level = request.header.level;
      reply.scoped.pdu = respondTo(request.scoped.pdu);
    }
    return reply;
  }

  void rewriteV3(V3Reply& reply, const V3Message& request) {
    rewriteId(reply.header.msgId);
    rewriteId(reply.scoped.pdu.requestId);
    rewritePdu(reply.scoped.pdu);
    switch (m_script->pick(4)) {
      case 1:
        reply.header.level = SecurityLevel::NoAuthNoPriv;
        break;
      case 2:
        reply.header.level = SecurityLevel::AuthNoPriv;
        break;
      case 3:
        reply.header.level = SecurityLevel::AuthPriv;
        break;
      default:
        break;
    }
    switch (m_script->pick(4)) {
      case 1:
        reply.usm.engineId = request.security.engineId;
        break;
      case 2:
        reply.usm.engineId.clear();
        break;
      case 3:
        reply.usm.engineId = m_script->bytes(m_script->pick(40));
        break;
      default:
        break;
    }
    switch (m_script->pick(4)) {
      case 1:
        reply.usm.boots = m_script->int32();
        reply.usm.time = m_script->int32();
        break;
      case 2:
        reply.usm.boots = m_boots - 1;
        break;
      case 3:
        reply.usm.time = m_time - 1000;
        break;
      default:
        break;
    }
    if (m_script->pick(2) == 1) reply.usm.userName = "intruder";
    // Which key signs it. The Client verifies a reply with the key for the engineID its request
    // went to, which is the real one unless the identity phase was answered with another.
    switch (m_script->pick(4)) {
      case 1:
        reply.keys = keysFor(m_profile.creds, request.security.engineId);
        break;
      case 2:
        reply.corruptAuth = true;
        break;
      case 3:
        reply.corruptPriv = true;
        break;
      default:
        break;
    }
  }

  // A Message ID or request-id: kept, another one this Agent has seen, or anything at all.
  void rewriteId(std::int32_t& id) {
    switch (m_script->pick(4)) {
      case 1:
        id = anotherId();
        break;
      case 2:
        id = m_script->int32();
        break;
      case 3:
        id = static_cast<std::int32_t>(static_cast<std::uint32_t>(id) + 1U);
        break;
      default:
        break;
    }
  }

  void rewritePdu(Pdu& pdu) {
    switch (m_script->pick(5)) {
      case 1:
        pdu.type = PduType::Response;
        break;
      case 2:
        pdu.type = PduType::Report;
        break;
      case 3:
        pdu.type = PduType::Get;
        break;
      case 4:
        pdu.type = PduType::GetBulk;
        break;
      default:
        break;
    }
    // A Report's first Varbind names its counter: one of the six, one the Client does not know,
    // or an OID that is not a counter at all.
    if (const auto counter = m_script->pick(9); counter != 0) {
      pdu.varbinds = usmReport(static_cast<std::uint32_t>(counter)).varbinds;
      if (counter == 8) pdu.varbinds.front().name = Oid{1, 3, 6, 1, 2, 1, 1, 1, 0};
    }
    // Any error-status near the RFC's range, negative ones included: the Client hands it to the
    // caller as an agent-category code without interpreting it.
    if (const auto status = m_script->byte(); status != 0) {
      pdu.errorStatus = std::int32_t{status} - 128;
      pdu.errorIndex = 1;
    }
    switch (m_script->pick(3)) {
      case 1:
        pdu.varbinds.clear();
        break;
      case 2:
        pdu.varbinds.push_back(Varbind{Oid{1, 3, 6, 1, 2, 1, 2}, ValueException::EndOfMibView});
        break;
      default:
        break;
    }
  }

  // The Credentials' protocols where they have them, and stand-ins where a rewritten Security
  // Level claims one the Credentials do not: the digest or the ciphertext is then simply wrong.
  [[nodiscard]] Octets encode(const V3Reply& reply) const {
    AuthProtocol auth = m_profile.creds.authProtocol;
    Octets authKey = reply.keys.auth;
    if (auth == AuthProtocol::None) auth = AuthProtocol::Sha1;
    if (authKey.empty()) authKey.assign(keySize(auth), std::byte{0x5A});
    if (reply.corruptAuth) authKey.front() ^= std::byte{0xFF};

    PrivProtocol priv = m_profile.creds.privProtocol;
    Octets privKey = reply.keys.priv;
    if (priv == PrivProtocol::None) priv = PrivProtocol::Aes128;
    if (privKey.empty()) privKey.assign(privKeySize(priv), std::byte{0xA5});
    if (reply.corruptPriv) privKey.front() ^= std::byte{0xFF};

    net::ErrorCode ec;
    auto bytes =
        encodeV3Message(reply.header, reply.usm, reply.scoped, auth, authKey, ec, priv, privKey);
    if (ec) return {};
    return bytes;
  }

  // Signs mutated bytes again, so that the mutation reaches the checks behind the digest.
  void resign(Octets& bytes, const V3Reply& reply) const {
    const AuthProtocol auth = m_profile.creds.authProtocol;
    if (auth == AuthProtocol::None || reply.keys.auth.empty()) return;
    net::ErrorCode ec;
    const auto msg = decodeV3Message(bytes, ec);
    if (!msg || !isAuthenticated(msg->header.level)) return;
    const auto width = authParamsSize(auth);
    if (msg->security.authParams.size() != width) return;

    const auto field = std::span<std::byte>(bytes).subspan(msg->authParamsOffset, width);
    std::ranges::fill(field, std::byte{0});
    const auto digest = authDigest(auth, reply.keys.auth, bytes, ec);
    if (ec || digest.size() != width) return;
    std::ranges::copy(digest, field.begin());
  }

  // ---- both ----

  void mutate(Octets& bytes) {
    for (auto ops = m_script->pick(6); ops > 0 && !bytes.empty(); --ops) {
      const auto high = std::size_t{m_script->byte()};
      const auto at = ((high << 8U) | m_script->byte()) % bytes.size();
      switch (m_script->pick(4)) {
        case 0:
          bytes[at] ^= std::byte{static_cast<std::uint8_t>(1U << m_script->pick(8))};
          break;
        case 1:
          bytes[at] = std::byte{m_script->byte()};
          break;
        case 2:
          bytes.resize(at);
          break;
        default:
          bytes.insert(bytes.begin() + static_cast<std::ptrdiff_t>(at),
                       std::byte{m_script->byte()});
          break;
      }
    }
  }

  void send(const Octets& bytes, bool fromTarget) {
    if (m_onSent) m_onSent(bytes, fromTarget);
    net::ErrorCode ec;
    auto& socket = fromTarget ? m_socket : m_stranger;
    std::ignore = socket.send_to(net::asio::buffer(bytes), m_from, 0, ec);
  }

  net::UdpSocket m_socket;
  net::UdpSocket m_stranger;
  Profile m_profile;
  Script* m_script;
  OnSent m_onSent;
  Octets m_engineId{std::byte{0x80}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x88},
                    std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
  Keys m_keys;
  // RFC 3414 section 2.2.3's Time Window, which this Agent enforces on what it is sent.
  static constexpr std::int32_t timeWindow = 150;

  std::int32_t m_boots = 3;
  std::int32_t m_time = 1000;
  std::map<std::int32_t, Seen> m_seen;
  std::vector<std::int32_t> m_ids;
  net::UdpEndpoint m_from;
  std::vector<std::byte> m_buf = std::vector<std::byte>(65535);
};

}  // namespace snmpio::fuzz

#endif  // SNMPIO_FUZZ_HOSTILEAGENT_HPP
