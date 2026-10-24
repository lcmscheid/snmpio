#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <snmpio/Client.hpp>

#include "CompletionOracle.hpp"
#include "ReplyDelivery.hpp"
#include "ScriptedAgent.hpp"
#include "ScriptedV3Agent.hpp"
#include "SoakPlan.hpp"

// The soak: the deployment snmpio exists for, randomised (#32, threat model C1-C3).
//
// Eight Clients share one io_context that four threads run, each Client with a Scripted Agent of
// its own; even slots speak v2c and odd ones v3. Every completion is bound to a strand on a second
// io_context, as an application whose own threads are not the I/O threads would bind it. Four more
// threads carry out SoakPlan.hpp's plan: they initiate from wherever the plan puts them, cancel
// from a thread that need not be the initiator, and stop or destroy a Client, which an Agent being
// removed and added back then replaces. Agents answer at once, late, never, twice, or after a
// garbled copy of the answer.
//
// Every request goes through the counting oracle. What it may complete with is worked out from
// what the plan did to it -- a reply, or Timeout where the Agent never answers; operation_aborted
// once cancelled, WalkIncomplete for a Walk a total signal reached; ClientStopped where its own
// Client was stopped or destroyed, and only there -- so that one Client's Stopping turning up in
// another's requests fails it (C3).
//
// The seed is printed, and SNMPIO_SOAK_SEED replays it: the same requests, cancellations, stops
// and destructions, at the same moments and from the same threads. SNMPIO_SOAK_SECONDS sets the
// duration, two seconds by default. The threads' interleavings around the plan are not the seed's
// to repeat, so a seed that failed once fails again more often than not, rather than every time.

namespace snmpio::test::soak {
namespace {

using std::chrono::milliseconds;
using std::chrono::steady_clock;

// The MIB every Agent serves: rowsPerBehaviour rows under soakRoot.b for each Behaviour b. A
// request names its Behaviour as the component after soakRoot, and the Agent reads it from there.
const Oid soakRoot{1, 3, 6, 1, 4, 1, 32, 1};
constexpr std::uint32_t rowsPerBehaviour = 6;
constexpr std::uint32_t behaviours = 5;

constexpr auto attemptTimeout = milliseconds(200);
constexpr int retries = 1;
constexpr auto wholeDeadline = attemptTimeout * (retries + 1);
constexpr WalkOptions walkOptions{2};
// A late reply lands in this window, well inside the first attempt's deadline.
constexpr auto lateFrom = milliseconds(20);
constexpr auto lateSpread = milliseconds(80);
// What every request has to complete within once the plan's last event is done: its whole deadline
// several times over, so that a request still outstanding at the end was stranded, not slow.
constexpr auto drainLimit = std::chrono::seconds(10);

constexpr int clientIoThreads = 4;
constexpr int callerIoThreads = 2;
// How many requests of one Behaviour a plan needs before the soak insists the Agents produced it.
constexpr std::ptrdiff_t minimumPlanned = 10;
// Detailed failures reported before the rest are only counted.
constexpr int failuresInDetail = 20;

const Community soakCommunity{Community("public")};

// Two Security Levels among the v3 slots, so that one run takes authPriv's path as well.
Credentials credentialsFor(int slot) {
  if (slot % 4 == 1) {
    return Credentials{"bert",       SecurityLevel::AuthNoPriv, AuthProtocol::Sha256,
                       "maplesyrup", PrivProtocol::None,        ""};
  }
  return Credentials{"ernie",      SecurityLevel::AuthPriv, AuthProtocol::Sha256,
                     "maplesyrup", PrivProtocol::Aes128,    "rubberduck"};
}

// ---------------------------------------------------------------------------
// The Agents' side.
// ---------------------------------------------------------------------------

Behaviour behaviourOf(const Pdu& pdu) {
  // Engine Discovery's probes name nothing; they, and anything else outside the MIB, are answered
  // at once.
  if (pdu.varbinds.empty()) return Behaviour::Prompt;
  const Oid& name = pdu.varbinds.front().name;
  if (name.size() <= soakRoot.size() || !soakRoot.isPrefixOf(name)) return Behaviour::Prompt;
  const auto b = name[soakRoot.size()];
  if (b < 1 || b > behaviours) return Behaviour::Prompt;
  return static_cast<Behaviour>(b);
}

ReplyDelivery deliveryFor(const Pdu& request) {
  ReplyDelivery d;
  switch (behaviourOf(request)) {
    case Behaviour::Late: {
      // Drawn from the name, so the same request is late by the same amount every run.
      std::uint64_t h = 0;
      for (const auto subid : request.varbinds.front().name) h = (h * 31) + subid;
      d.delay = lateFrom + milliseconds(static_cast<std::int64_t>(
                               h % static_cast<std::uint64_t>(lateSpread.count())));
      break;
    }
    case Behaviour::Twice:
      d.copies = 2;
      break;
    case Behaviour::Garbled:
      d.truncatedCopyFirst = true;
      break;
    case Behaviour::Prompt:
    case Behaviour::Never:
      break;
  }
  return d;
}

const std::vector<Varbind>& mib() {
  static const std::vector<Varbind> rows = [] {
    std::vector<Varbind> out;
    for (std::uint32_t b = 1; b <= behaviours; ++b) {
      for (std::uint32_t k = 1; k <= rowsPerBehaviour; ++k)
        out.emplace_back(soakRoot.child(b).child(k), Gauge32{k});
    }
    return out;
  }();
  return rows;
}

// The data plane both kinds of Agent share: GET and SET echo what they were asked, GETNEXT and
// GETBULK walk the MIB from the first name.
Pdu answer(const Pdu& request) {
  Pdu p;
  p.type = PduType::Response;
  if (request.type == PduType::Get || request.type == PduType::Set) {
    p.varbinds = request.varbinds;
    for (auto& vb : p.varbinds) {
      if (request.type == PduType::Get) vb.val = Gauge32{1};
    }
    return p;
  }
  const Oid& from = request.varbinds.at(0).name;
  const auto count = request.type == PduType::GetBulk
                         ? static_cast<std::size_t>(request.maxRepetitions())
                         : std::size_t{1};
  for (const auto& vb : mib()) {
    if (p.varbinds.size() >= count) break;
    if (from < vb.name) p.varbinds.push_back(vb);
  }
  if (p.varbinds.size() < count)
    p.varbinds.emplace_back(Oid{1, 3, 6, 1, 6}, ValueException::EndOfMibView);
  return p;
}

// One slot's Agent, of whichever version the slot speaks.
class SoakAgent {
 public:
  SoakAgent(net::IoContext& io, int slot) {
    if (!isV3(slot)) {
      m_v2c = std::make_unique<ScriptedAgent>(io, [](const V2cMessage& msg) -> std::optional<Pdu> {
        if (behaviourOf(msg.pdu) == Behaviour::Never) return std::nullopt;
        return answer(msg.pdu);
      });
      m_v2c->setDelivery(deliveryFor);
      return;
    }
    m_v3 = std::make_unique<ScriptedV3Agent>(io, credentialsFor(slot), answer);
    m_v3->setResponder([agent = m_v3.get()](const ScriptedV3Agent::Request& req)
                           -> std::optional<ScriptedV3Agent::Reply> {
      if (behaviourOf(req.message.scoped.pdu) == Behaviour::Never) return std::nullopt;
      return agent->behaveLikeACompliantAgent(req);
    });
    m_v3->setDelivery(deliveryFor);
  }

  [[nodiscard]] Target target() const {
    Target t;
    t.endpoint = m_v2c ? m_v2c->endpoint() : m_v3->endpoint();
    t.timeout = attemptTimeout;
    t.retries = retries;
    return t;
  }

  // Closed on its own strand, which the io_context's threads may be running.
  void close() {
    if (m_v2c) {
      net::asio::dispatch(m_v2c->executor(), [agent = m_v2c.get()] { agent->close(); });
    } else {
      net::asio::dispatch(m_v3->executor(), [agent = m_v3.get()] { agent->close(); });
    }
  }

  // Read once every thread has joined.
  [[nodiscard]] const DeliveryCounts& deliveries() const {
    return m_v2c ? m_v2c->deliveries() : m_v3->deliveries();
  }

 private:
  std::unique_ptr<ScriptedAgent> m_v2c;
  std::unique_ptr<ScriptedV3Agent> m_v3;
};

// ---------------------------------------------------------------------------
// The Clients' side.
// ---------------------------------------------------------------------------

// What became of one Client instance, as its requests need to know.
struct ClientState {
  // Set before Stopping begins, so a request that sees ClientStopped finds it set.
  std::atomic<bool> stopping = false;
  // Set once stop() or ~Client has returned: no Batch may be delivered after (L6).
  std::atomic<bool> stopped = false;
};

// One Client instance. Destroying it is destroying the Client, on whichever thread lets go of it
// last -- the one that removed it from its slot, or one that was still initiating on it.
class Instance {
 public:
  explicit Instance(const net::Executor& ex) : m_client(std::in_place, ex) {}
  Instance(const Instance&) = delete;
  Instance& operator=(const Instance&) = delete;
  Instance(Instance&&) = delete;
  Instance& operator=(Instance&&) = delete;
  ~Instance() {
    m_state->stopping = true;
    m_client.reset();
    m_state->stopped = true;
  }

  Client& client() { return *m_client; }
  [[nodiscard]] const std::shared_ptr<ClientState>& state() const { return m_state; }

  void stop() {
    m_state->stopping = true;
    m_client->stop();
    m_state->stopped = true;
  }

 private:
  std::shared_ptr<ClientState> m_state = std::make_shared<ClientState>();
  std::optional<Client> m_client;
};

// A Client slot: the Client currently serving one Agent. A Stop or a Destroy replaces it.
class Slot {
 public:
  explicit Slot(net::Executor ex) : m_ex(std::move(ex)), m_current(fresh()) {}

  [[nodiscard]] std::shared_ptr<Instance> current() {
    const std::scoped_lock lock(m_mutex);
    return m_current;
  }

  // The Agent is removed and added back: the old Client goes, a new one takes its place.
  void destroy() {
    auto next = fresh();
    {
      const std::scoped_lock lock(m_mutex);
      std::swap(m_current, next);
    }
    // The last hold on the old Client, unless an initiator still has it for a moment.
    next.reset();
  }

  void stop() {
    const auto stopping = current();
    stopping->stop();
    auto next = fresh();
    const std::scoped_lock lock(m_mutex);
    if (m_current == stopping) std::swap(m_current, next);
  }

  // At the end, on the test thread.
  void retire() {
    const std::scoped_lock lock(m_mutex);
    m_current.reset();
  }

 private:
  [[nodiscard]] std::shared_ptr<Instance> fresh() const { return std::make_shared<Instance>(m_ex); }

  net::Executor m_ex;
  std::mutex m_mutex;
  std::shared_ptr<Instance> m_current;
};

// Counts completions, so the test thread can wait for the last with a limit.
class Completions {
 public:
  void add() {
    {
      const std::scoped_lock lock(m_mutex);
      ++m_count;
    }
    m_changed.notify_all();
  }
  [[nodiscard]] bool waitFor(std::size_t count, std::chrono::seconds limit) {
    std::unique_lock lock(m_mutex);
    return m_changed.wait_for(lock, limit, [&] { return m_count >= count; });
  }
  [[nodiscard]] std::size_t count() {
    const std::scoped_lock lock(m_mutex);
    return m_count;
  }

 private:
  std::mutex m_mutex;
  std::condition_variable m_changed;
  std::size_t m_count = 0;
};

// Everything known about one planned request. Each field has one writer, and the checks read them
// only after every thread has joined.
struct Record {
  std::optional<CompletionOracle> oracle;  // built before any thread starts
  net::asio::cancellation_signal signal;

  // The initiating thread's, published by `initiated` to the thread that cancels.
  std::shared_ptr<ClientState> client;
  steady_clock::time_point initiatedAt;
  std::atomic<bool> initiated = false;

  // The cancelling thread's.
  bool terminal = false;
  bool total = false;

  // The completion's, on the caller strand. Whether Stopping had begun on the request's Client is
  // read there too: Stopping sets the flag before it does anything, and its ClientStopped reaches
  // the completion through the strands that order everything after it.
  steady_clock::time_point completedAt;
  std::size_t collected = 0;
  bool clientWasStopping = false;

  // The Batch handler's, on the Client's strand.
  std::atomic<std::size_t> batched = 0;
  std::atomic<bool> batchAfterStopping = false;
};

bool isWalk(Operation op) {
  return op == Operation::Walk || op == Operation::WalkCollect;
}

// One row of the MIB per request, spread over the rows, with the request's index after it so that
// no two requests name the same instance.
Oid nameFor(const Request& r, int index) {
  const auto row = 1 + (static_cast<std::uint32_t>(index) % rowsPerBehaviour);
  return soakRoot.child(static_cast<std::uint32_t>(r.behaviour))
      .child(row)
      .child(static_cast<std::uint32_t>(index));
}

class Soak {
 public:
  explicit Soak(Plan plan) : m_plan(std::move(plan)), m_records(m_plan.requests.size()) {
    for (int slot = 0; slot < clientSlots; ++slot) {
      m_agents.push_back(std::make_unique<SoakAgent>(m_clientIo, slot));
      m_slots.push_back(std::make_unique<Slot>(m_clientIo.get_executor()));
    }
    for (auto& record : m_records) record.oracle.emplace(m_callerIo);
  }

  void run() {
    std::vector<std::thread> io;
    io.reserve(clientIoThreads + callerIoThreads);
    for (int i = 0; i < clientIoThreads; ++i) io.emplace_back([this] { m_clientIo.run(); });
    for (int i = 0; i < callerIoThreads; ++i) io.emplace_back([this] { m_callerIo.run(); });

    // A moment's lead, so every thread is waiting before the first event is due.
    const auto start = steady_clock::now() + milliseconds(20);
    std::vector<std::thread> initiators;
    initiators.reserve(initiatorThreads);
    for (int t = 0; t < initiatorThreads; ++t) {
      initiators.emplace_back([this, t, start] {
        for (const auto& e : m_plan.events) {
          if (e.thread != t) continue;
          std::this_thread::sleep_until(start + e.at);
          perform(e);
        }
      });
    }
    for (auto& t : initiators) t.join();

    m_drained = m_completions.waitFor(m_records.size(), drainLimit);

    for (auto& slot : m_slots) slot->retire();
    for (auto& agent : m_agents) agent->close();
    m_clientWork.reset();
    m_callerWork.reset();
    for (auto& t : io) t.join();
  }

  void check() {
    EXPECT_TRUE(m_drained) << m_records.size() - m_completions.count() << " of " << m_records.size()
                           << " requests had not completed " << drainLimit.count()
                           << " s after the plan's last event";
    printOutcomes();
    int failures = 0;
    for (std::size_t i = 0; i < m_records.size(); ++i) {
      if (!checkOne(static_cast<int>(i), m_plan.requests[i], m_records[i])) continue;
      if (++failures > failuresInDetail) break;
    }

    // A run whose Agents never misbehaved proved less than it says. Asked only of a plan with
    // enough requests of the kind that a few lost to Stopping cannot account for none at all.
    DeliveryCounts sum;
    for (const auto& agent : m_agents) {
      sum.delayed += agent->deliveries().delayed;
      sum.duplicated += agent->deliveries().duplicated;
      sum.truncated += agent->deliveries().truncated;
    }
    const auto planned = [this](Behaviour b) {
      return std::ranges::count(m_plan.requests, b, &Request::behaviour) >= minimumPlanned;
    };
    if (planned(Behaviour::Late)) {
      EXPECT_GT(sum.delayed, 0) << "no Agent answered late";
    }
    if (planned(Behaviour::Twice)) {
      EXPECT_GT(sum.duplicated, 0) << "no Agent answered twice";
    }
    if (planned(Behaviour::Garbled)) {
      EXPECT_GT(sum.truncated, 0) << "no Agent sent a garbled copy";
    }
  }

 private:
  // What the requests completed with, for the log: a run where nothing was ever stopped or
  // cancelled in flight looks green and proves little, and this is where that shows.
  void printOutcomes() const {
    std::map<std::string, int> tally;
    for (const auto& record : m_records) {
      if (record.oracle->invocations().empty()) {
        ++tally["(never completed)"];
        continue;
      }
      const auto code = record.oracle->invocations().front().code;
      ++tally[code ? code.message() : "success"];
    }
    std::cout << "[ SOAK     ] completed:";
    const char* separator = " ";
    for (const auto& [what, count] : tally) {
      std::cout << separator << count << " " << what;
      separator = ", ";
    }
    std::cout << "\n" << std::flush;
  }

  void perform(const Event& e) {
    switch (e.action) {
      case Action::Initiate:
        initiate(e.request);
        break;
      case Action::CancelTerminal:
      case Action::CancelTotal:
        cancel(e);
        break;
      case Action::Stop:
        m_slots.at(static_cast<std::size_t>(e.slot))->stop();
        break;
      case Action::Destroy:
        m_slots.at(static_cast<std::size_t>(e.slot))->destroy();
        break;
    }
  }

  void initiate(int index) {
    const auto& request = m_plan.requests.at(static_cast<std::size_t>(index));
    auto& record = m_records.at(static_cast<std::size_t>(index));
    const auto instance = m_slots.at(static_cast<std::size_t>(request.slot))->current();
    record.client = instance->state();
    record.initiatedAt = steady_clock::now();

    const auto target = m_agents.at(static_cast<std::size_t>(request.slot))->target();
    if (isV3(request.slot)) {
      initiateOn(instance->client(), target, credentialsFor(request.slot), request, index, record);
    } else {
      initiateOn(instance->client(), target, soakCommunity, request, index, record);
    }
    record.initiated.store(true, std::memory_order_release);
    record.initiated.notify_all();
  }

  template <typename Auth>
  void initiateOn(Client& client, const Target& target, const Auth& auth, const Request& request,
                  int index, Record& record) {
    const auto completed = [this, &record](net::ErrorCode, const auto&...) {
      record.completedAt = steady_clock::now();
      record.clientWasStopping = record.client->stopping;
      m_completions.add();
    };
    const auto token = [&record](auto then) {
      return net::asio::bind_cancellation_slot(record.signal.slot(),
                                               record.oracle->handler(std::move(then)));
    };
    const Oid name = nameFor(request, index);
    const Oid base = soakRoot.child(static_cast<std::uint32_t>(request.behaviour));

    switch (request.operation) {
      case Operation::Get:
        client.asyncGet(target, auth, {name}, token(completed));
        break;
      case Operation::GetNext:
        client.asyncGetNext(target, auth, {name}, token(completed));
        break;
      case Operation::GetBulk:
        client.asyncGetBulk(target, auth, {name}, 0, 2, token(completed));
        break;
      case Operation::Set:
        client.asyncSet(target, auth, {Varbind{name, Gauge32{static_cast<std::uint32_t>(index)}}},
                        token(completed));
        break;
      case Operation::Walk:
        client.asyncWalk(
            target, auth, base, walkOptions,
            [&record, state = record.client](std::span<const Varbind> batch) {
              if (state->stopped) record.batchAfterStopping = true;
              record.batched += batch.size();
              return true;
            },
            token(completed));
        break;
      case Operation::WalkCollect:
        client.asyncWalkCollect(
            target, auth, base, walkOptions,
            token([completed, &record](net::ErrorCode ec, const std::vector<Varbind>& rows) {
              record.collected = rows.size();
              completed(ec);
            }));
        break;
    }
  }

  // Waits for the initiation, which the plan puts strictly earlier but perhaps on a thread that
  // has not reached it yet. One thread cancels each request (SoakPlan.hpp), so the signal is never
  // emitted from two at once.
  void cancel(const Event& e) {
    auto& record = m_records.at(static_cast<std::size_t>(e.request));
    record.initiated.wait(false, std::memory_order_acquire);
    if (e.action == Action::CancelTerminal) {
      record.terminal = true;
      record.signal.emit(net::asio::cancellation_type::terminal);
    } else {
      record.total = true;
      record.signal.emit(net::asio::cancellation_type::total);
    }
  }

  // True if the request failed a check.
  static bool checkOne(int index, const Request& request, const Record& record) {
    std::vector<net::ErrorCode> allowed;
    allowed.push_back(request.behaviour == Behaviour::Never ? make_error_code(Errc::Timeout)
                                                            : net::ErrorCode{});
    if (record.terminal || record.total) allowed.emplace_back(net::asio::error::operation_aborted);
    if (record.total && isWalk(request.operation))
      allowed.push_back(make_error_code(Errc::WalkIncomplete));
    if (record.clientWasStopping) allowed.push_back(make_error_code(Errc::ClientStopped));

    const auto context = [&] {
      std::string text = "request " + std::to_string(index) + ": " + describe(request);
      if (record.terminal) text += ", cancelled terminal";
      if (record.total) text += ", cancelled total";
      if (record.clientWasStopping) text += ", its Client stopping";
      return text;
    };

    const auto result = record.oracle->completedExactlyOnce(allowed);
    if (!result) {
      ADD_FAILURE() << context() << ": " << result.message();
      return true;
    }
    bool failed = false;
    const auto code = record.oracle->invocations().front().code;
    const auto took = record.completedAt - record.initiatedAt;

    if (record.batchAfterStopping) {
      ADD_FAILURE() << context() << ": a Batch was delivered after Stopping returned";
      failed = true;
    }
    // Deadlines under concurrency: no request gives up early (R5).
    if (code == Errc::Timeout && took < wholeDeadline) {
      ADD_FAILURE() << context() << ": timed out after "
                    << std::chrono::duration_cast<milliseconds>(took).count()
                    << " ms, before its whole deadline";
      failed = true;
    }
    if (!code && isWalk(request.operation)) {
      const auto rows =
          request.operation == Operation::Walk ? record.batched.load() : record.collected;
      if (rows != rowsPerBehaviour) {
        ADD_FAILURE() << context() << ": a complete Walk handed back " << rows << " rows, not "
                      << rowsPerBehaviour;
        failed = true;
      }
    }
    // Every answer lands inside the first attempt's deadline, so one that took longer was lost
    // and retransmitted for -- a reply that overtook its send, say, which only several threads
    // running the io_context produce. v2c only: a v3 request's first request to an Engine waits
    // behind a discovery and a key derivation that its own deadline does not cover.
    if (!code && !isV3(request.slot) && !isWalk(request.operation) && took >= attemptTimeout) {
      ADD_FAILURE() << context() << ": answered only after "
                    << std::chrono::duration_cast<milliseconds>(took).count()
                    << " ms, past the first attempt's deadline";
      failed = true;
    }
    return failed;
  }

  Plan m_plan;
  net::IoContext m_clientIo;
  net::IoContext m_callerIo;
  net::asio::executor_work_guard<net::IoContext::executor_type> m_clientWork =
      net::asio::make_work_guard(m_clientIo);
  net::asio::executor_work_guard<net::IoContext::executor_type> m_callerWork =
      net::asio::make_work_guard(m_callerIo);
  std::vector<std::unique_ptr<SoakAgent>> m_agents;
  std::vector<std::unique_ptr<Slot>> m_slots;
  std::vector<Record> m_records;
  Completions m_completions;
  bool m_drained = false;
};

std::optional<std::string> envVar(const char* name) {
  // NOLINTNEXTLINE(concurrency-mt-unsafe): read before any thread of the soak's exists.
  const char* const value = std::getenv(name);
  if (value == nullptr || *value == '\0') return std::nullopt;
  return std::string(value);
}

TEST(Soak, ShapedLikeTheDeployment) {
  std::uint64_t seed = std::random_device{}();
  seed = (seed << 32U) ^ std::random_device{}();
  if (const auto text = envVar("SNMPIO_SOAK_SEED")) {
    const auto parsed = parseSeed(*text);
    ASSERT_TRUE(parsed.has_value()) << "SNMPIO_SOAK_SEED is not a seed: " << *text;
    seed = *parsed;
  }
  auto duration = milliseconds(2000);
  if (const auto text = envVar("SNMPIO_SOAK_SECONDS")) {
    const auto parsed = parseSeconds(*text);
    ASSERT_TRUE(parsed.has_value()) << "SNMPIO_SOAK_SECONDS is not a duration: " << *text;
    duration = *parsed;
  }

  const auto plan = makePlan(seed, duration);
  std::cout << "[ SOAK     ] seed " << seed << " for " << duration.count()
            << " ms: " << summary(plan) << "\n[ SOAK     ] replay with SNMPIO_SOAK_SEED=" << seed
            << " SNMPIO_SOAK_SECONDS=" << static_cast<double>(duration.count()) / 1000 << "\n"
            << std::flush;
  RecordProperty("seed", std::to_string(seed));
  SCOPED_TRACE(testing::Message() << "SNMPIO_SOAK_SEED=" << seed);

  Soak soak(plan);
  soak.run();
  soak.check();
}

}  // namespace
}  // namespace snmpio::test::soak
