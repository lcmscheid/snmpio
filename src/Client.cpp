#include <snmpio/Client.hpp>

#include <chrono>
#include <cstddef>
#include <limits>
#include <optional>
#include <random>
#include <tuple>
#include <utility>

namespace snmpio {
namespace {

// A UDP datagram cannot exceed this, so a buffer this size can never truncate a Response -- which
// matters, because a silently truncated message would decode as malformed rather than as too big.
constexpr std::size_t maxDatagram = 65535;

using net::asio::redirect_error;
using net::asio::use_awaitable;

std::int32_t randomRequestId() {
  // RFC 3416 does not require unpredictability, but a fixed starting point makes a restarted
  // Client collide with in-flight Responses from its previous life. Positive so the encoding
  // stays short and the value reads plainly in a capture.
  std::random_device rd;
  std::uniform_int_distribution<std::int32_t> dist(1, std::numeric_limits<std::int32_t>::max());
  return dist(rd);
}

}  // namespace

Client::Client(const net::Executor& ex)
    : m_strand(net::asio::make_strand(ex)), m_nextRequestId(randomRequestId()) {}

void Client::stop() {
  // Dispatched rather than posted: stop() is usually the last thing before the io_context drains,
  // and a posted cleanup would never run.
  net::asio::dispatch(m_strand, [this] {
    if (m_stopped) return;
    m_stopped = true;
    // close() hands back the same ErrorCode it writes to the out-parameter; std::ignore says the
    // discard is deliberate rather than forgotten.
    net::ErrorCode ignored;
    if (m_v4) std::ignore = m_v4->close(ignored);
    if (m_v6) std::ignore = m_v6->close(ignored);
    for (auto& [id, pending] : m_pending) pending->timer.cancel();
  });
}

std::vector<Varbind> Client::toVarbinds(std::vector<Oid> oids) {
  std::vector<Varbind> out;
  out.reserve(oids.size());
  // In place rather than push_back of a temporary -- see the note in tests/TestClient.cpp.
  for (auto& oid : oids) out.emplace_back(std::move(oid), null);
  return out;
}

Pdu Client::makePdu(PduType type, std::vector<Varbind> varbinds) {
  Pdu p;
  p.type = type;
  p.varbinds = std::move(varbinds);
  return p;
}

Pdu Client::makeBulkPdu(std::vector<Varbind> varbinds, std::int32_t nonRepeaters,
                        std::int32_t maxRepetitions) {
  Pdu p = makePdu(PduType::GetBulk, std::move(varbinds));
  p.setBulkParams(nonRepeaters, maxRepetitions);
  return p;
}

net::UdpSocket* Client::socketFor(const net::UdpEndpoint& to, net::ErrorCode& ec) {
  const bool v6 = to.address().is_v6();
  auto& slot = v6 ? m_v6 : m_v4;
  if (slot) return &*slot;

  slot.emplace(m_strand);
  std::ignore = slot->open(v6 ? net::Udp::v6() : net::Udp::v4(), ec);
  if (ec) {
    slot.reset();
    return nullptr;
  }
  // One receive loop per socket, running until the socket closes. It outlives every individual
  // request, which is the point: Responses are matched by request-id, not by who is waiting.
  net::asio::co_spawn(m_strand, receiveLoop(&*slot), net::asio::detached);
  return &*slot;
}

// By pointer, not by reference: a coroutine parameter that is a reference is a dangling hazard as
// a rule, and the rule is worth keeping even where -- as here -- the socket is a member that
// outlives the loop.
net::Awaitable<void> Client::receiveLoop(net::UdpSocket* sock) {
  std::vector<std::byte> buf(maxDatagram);

  for (;;) {
    net::UdpEndpoint from;
    net::ErrorCode ec;
    const std::size_t n = co_await sock->async_receive_from(net::asio::buffer(buf), from,
                                                            redirect_error(use_awaitable, ec));
    if (ec) co_return;  // the socket was closed, or the loop is over for good

    net::ErrorCode decodeEc;
    auto msg = decodeV2cMessage(std::span<const std::byte>(buf).first(n), decodeEc);
    if (!msg) continue;
    // A Report is control-plane traffic that only v3 produces, and stage 3 owns routing it. Any
    // other PDU type here is either a mis-sent request or someone probing us.
    if (msg->pdu.type != PduType::Response) continue;

    const auto it = m_pending.find(msg->pdu.requestId);
    if (it == m_pending.end()) continue;
    // The request-id is guessable and UDP is trivially spoofable, so a Response only counts if it
    // came back from the Target we asked and quoted the Community we used.
    if (from != it->second->from || msg->community != it->second->community) continue;

    it->second->response = std::move(msg->pdu);
    it->second->answered = true;
    it->second->timer.cancel();
  }
}

net::Awaitable<Client::RequestResult> Client::doRequest(Target target, Community community,
                                                        Pdu pdu) {
  if (m_stopped) co_return RequestResult{make_error_code(Errc::ClientStopped), Response{}};

  pdu.requestId = m_nextRequestId;
  m_nextRequestId =
      m_nextRequestId == std::numeric_limits<std::int32_t>::max() ? 1 : m_nextRequestId + 1;

  net::ErrorCode ec;
  const auto datagram = encodeV2cMessage(community.value, pdu, ec);
  if (ec) co_return RequestResult{ec, Response{}};

  net::UdpSocket* sock = socketFor(target.endpoint, ec);
  if (ec) co_return RequestResult{ec, Response{}};

  auto pending = std::make_shared<Pending>(co_await net::asio::this_coro::executor);
  pending->from = target.endpoint;
  pending->community = community.value;
  m_pending.emplace(pdu.requestId, pending);

  // Cancellation is handled here rather than thrown, so every exit still goes through the
  // bookkeeping below.
  co_await net::asio::this_coro::throw_if_cancelled(false);
  auto cancelState = co_await net::asio::this_coro::cancellation_state;
  const auto aborted = [&cancelState] {
    return (cancelState.cancelled() & net::asio::cancellation_type::terminal) !=
           net::asio::cancellation_type::none;
  };
  const auto softCancelled = [&cancelState, &aborted] {
    return cancelState.cancelled() != net::asio::cancellation_type::none && !aborted();
  };

  for (int attempt = 0; attempt <= target.retries; ++attempt) {
    co_await sock->async_send_to(net::asio::buffer(datagram), target.endpoint,
                                 redirect_error(use_awaitable, ec));
    if (ec) break;

    pending->timer.expires_after(target.timeout);
    // The wait's own ErrorCode says nothing useful: the receive loop cancels this timer to wake
    // us, so operation_aborted is the success path and expiry is the retry path.
    [[maybe_unused]] net::ErrorCode waitEc;
    co_await pending->timer.async_wait(redirect_error(use_awaitable, waitEc));
    if (pending->answered || m_stopped || aborted()) break;

    if (softCancelled()) {
      // A total signal is not this request's to act on -- it belongs to the Walk above us, which
      // stops at a batch boundary and wants this exchange finished (ADR-0004). It did however cut
      // the wait short, so wait out the rest of the deadline on a slot nothing can cancel, and
      // stop retransmitting either way.
      co_await pending->timer.async_wait(net::asio::bind_cancellation_slot(
          net::asio::cancellation_slot(), redirect_error(use_awaitable, waitEc)));
      break;
    }
  }

  m_pending.erase(pdu.requestId);

  if (!pending->answered) {
    if (aborted()) co_return RequestResult{net::asio::error::operation_aborted, Response{}};
    // Ahead of ec on purpose: stop() closes the socket, so the socket's own complaint about a
    // bad descriptor is a symptom of the stop and would bury the actual reason.
    if (m_stopped) co_return RequestResult{make_error_code(Errc::ClientStopped), Response{}};
    if (ec) co_return RequestResult{ec, Response{}};
    co_return RequestResult{make_error_code(Errc::Timeout), Response{}};
  }

  Response resp;
  resp.varbinds = std::move(pending->response.varbinds);
  resp.errorIndex = pending->response.errorIndex;
  if (pending->response.errorStatus != 0) {
    co_return RequestResult{
        make_error_code(static_cast<ErrorStatus>(pending->response.errorStatus)), std::move(resp)};
  }
  co_return RequestResult{net::ErrorCode{}, std::move(resp)};
}

net::Awaitable<Client::WalkResult> Client::doWalk(Target target, Community community, Oid base,
                                                  WalkOptions options, BatchHandler onBatch) {
  // A total cancellation is a request to stop cleanly at a batch boundary rather than to drop
  // everything, so it has to be observable here -- and observed, not thrown.
  co_await net::asio::this_coro::throw_if_cancelled(false);
  co_await net::asio::this_coro::reset_cancellation_state(net::asio::enable_total_cancellation());
  auto cancelState = co_await net::asio::this_coro::cancellation_state;
  // The two halves of ADR-0004's split, in one place so they cannot drift apart: terminal drops
  // everything and says so with operation_aborted, total stops here and reports an incomplete
  // Walk. Nothing else may turn a cancellation into an ordinary failure.
  const auto stopNow = [&cancelState]() -> std::optional<net::ErrorCode> {
    const auto c = cancelState.cancelled();
    if ((c & net::asio::cancellation_type::terminal) != net::asio::cancellation_type::none) {
      return net::ErrorCode(net::asio::error::operation_aborted);
    }
    if (c != net::asio::cancellation_type::none) return make_error_code(Errc::WalkIncomplete);
    return std::nullopt;
  };

  Oid current = base;
  std::int32_t maxRepetitions = options.maxRepetitions;

  for (;;) {
    if (const auto stop = stopNow()) co_return WalkResult{*stop};

    const Pdu req = maxRepetitions <= 0 ? makePdu(PduType::GetNext, toVarbinds({current}))
                                        : makeBulkPdu(toVarbinds({current}), 0, maxRepetitions);

    auto [ec, resp] = co_await doRequest(target, community, req);
    // tooBig means the Response did not fit, not that the request was wrong: ask for less and try
    // again. Only a deliberately misbehaving Simulator reaches this path (ADR-0006).
    if (ec == ErrorStatus::TooBig && maxRepetitions > 1) {
      maxRepetitions /= 2;
      continue;
    }
    if (ec) {
      // A cancellation that cut the exchange short is an incomplete Walk, not a fault of the
      // Target's -- a total cancel against a silent Target must not surface as a Timeout.
      if (const auto stop = stopNow()) co_return WalkResult{*stop};
      co_return WalkResult{ec};
    }
    if (resp.varbinds.empty()) co_return WalkResult{make_error_code(Errc::MissingVarbind)};

    std::vector<Varbind> batch;
    batch.reserve(resp.varbinds.size());
    bool done = false;
    for (auto& vb : resp.varbinds) {
      // endOfMibView -- or either of the noSuch markers, from an Agent that should not be sending
      // them here -- ends the Walk, as does leaving the Subtree.
      if (isException(vb.val) || !base.isPrefixOf(vb.name)) {
        done = true;
        break;
      }
      // ADR-0004: an Agent that repeats an OID would otherwise walk forever.
      if (!(current < vb.name)) co_return WalkResult{make_error_code(Errc::NonIncreasingOid)};
      current = vb.name;
      batch.push_back(std::move(vb));
    }

    if (!batch.empty() && !onBatch(batch))
      co_return WalkResult{make_error_code(Errc::WalkIncomplete)};
    if (done) co_return WalkResult{net::ErrorCode{}};
  }
}

net::Awaitable<Client::CollectResult> Client::doWalkCollect(Target target, Community community,
                                                            Oid base, WalkOptions options) {
  std::vector<Varbind> collected;
  auto [ec] = co_await doWalk(std::move(target), std::move(community), std::move(base), options,
                              [&collected](std::span<const Varbind> batch) {
                                collected.insert(collected.end(), batch.begin(), batch.end());
                                return true;
                              });
  // ADR-0004 again: `total` keeps what arrived, `terminal` drops everything immediately.
  if (ec == net::asio::error::operation_aborted) collected.clear();
  co_return CollectResult{ec, std::move(collected)};
}

}  // namespace snmpio
