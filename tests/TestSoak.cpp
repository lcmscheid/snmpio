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
#include <variant>
#include <vector>

#include <snmpio/Client.hpp>
#include <snmpio/detail/OutstandingView.hpp>

#include "CompletionOracle.hpp"
#include "MasterKeys.hpp"
#include "OutstandingReads.hpp"
#include "ReplyDelivery.hpp"
#include "ScriptedAgent.hpp"
#include "ScriptedV3Agent.hpp"
#include "SoakPlan.hpp"

// The soak: the deployment snmpio exists for, randomised (#32, threat model C1-C3).
//
// Eight Clients share one io_context that four threads run, each Client polling a Target of its
// own, behind which a Scripted Agent answers; even slots speak v2c and odd ones v3. Every
// completion is bound to a strand on a second io_context, as an application whose own threads are
// not the I/O threads would bind it. Four more threads carry out SoakPlan.hpp's plan: they initiate
// from wherever the plan puts them, cancel from a thread that need not be the initiator, and stop
// or destroy a Client, which the slot's next generation then replaces, as a Target leaving the
// inventory and coming back would. Agents answer at once, late, never, twice, or after malformed
// datagrams: one whose length claims four gigabytes, and a truncated copy of the answer.
//
// Every request goes through the counting oracle. What it may complete with is worked out from
// what the plan did to it -- a reply, or Timeout where the Agent never answers; operation_aborted
// once cancelled, WalkIncomplete for a Walk a total signal reached; ClientStopped where its own
// Client was stopped or destroyed, and only there -- so that one Client's Stopping turning up in
// another's requests fails it (C3). A terminal signal narrows that further, by when it went out:
// a request may not succeed on an answer its Agent sent only after the signal, nor time out if
// the signal went out before its whole deadline could have passed (L2).
//
// The seed is printed, and SNMPIO_SOAK_SEED replays it: the same requests, cancellations, stops
// and destructions, in the same order, reaching the same generation of the same slot's Client,
// due at the same moments, and from the same threads. SNMPIO_SOAK_SECONDS sets the duration, two
// seconds by default. When each lands relative to the others is the scheduler's -- a thread that
// waits on an initiation, or on a Batch handler running elsewhere, falls behind the plan -- so a
// seed that failed once fails again more often than not, rather than every time.

namespace snmpio::test::soak {
namespace {

using std::chrono::milliseconds;
using std::chrono::steady_clock;

// The MIB every Agent serves: a Subtree of its own for each planned request, soakRoot.b.i for
// request i with Behaviour b, holding rowsPerRequest rows. The Agent reads the Behaviour from the
// component after soakRoot and the request from the one after that, so every exchange -- a Walk's
// included -- says which request it belongs to.
const Oid soakRoot{1, 3, 6, 1, 4, 1, 32, 1};
constexpr std::uint32_t rowsPerRequest = 6;
// The highest Behaviour, as the sub-identifier its Subtrees sit under.
constexpr auto lastBehaviourArc = static_cast<std::uint32_t>(behaviourCount);

constexpr auto attemptTimeout = milliseconds(200);
constexpr int retries = 1;
constexpr auto wholeDeadline = attemptTimeout * (retries + 1);
constexpr WalkOptions walkOptions{2};
// How long a request may still take once a terminal signal has gone out: half an attempt's
// deadline, as Deadlines.hpp's atOnceLimit reasons, so that one ignored until a deadline shows.
constexpr auto terminalLimit = attemptTimeout / 2;
// A late reply lands in this window, well inside the first attempt's deadline.
constexpr auto lateFrom = milliseconds(20);
constexpr auto lateSpread = milliseconds(80);
// What every request has to complete within once the plan's last event is done: its whole deadline
// several times over, so that a request still outstanding at the end was stranded, not slow.
constexpr auto drainLimit = std::chrono::seconds(10);
// What a Client's own work may still take once every request has completed: a discovery its
// cancelled requests left running, through both phases' whole deadlines, and the derivation its
// time-sync phase may queue behind, with room for a sanitizer's slowdown.
constexpr auto settleLimit = milliseconds(4 * wholeDeadline);

constexpr int clientIoThreads = 4;
constexpr int callerIoThreads = 2;
// How many requests of one Behaviour a plan needs before the soak insists the Agents produced it.
constexpr std::ptrdiff_t minimumPlanned = 10;
// Detailed failures reported before the rest are only counted.
constexpr int failuresInDetail = 20;

const Community soakCommunity{Community("public")};

// Two Security Levels among the v3 slots, so that one run takes authPriv's path as well. These are
// the Agents' Credentials; the Clients get clientCredentialsFor's.
Credentials credentialsFor(int slot) {
  if (slot % 4 == 1) {
    return Credentials{"bert",       SecurityLevel::AuthNoPriv, AuthProtocol::Sha256,
                       "maplesyrup", PrivProtocol::None,        ""};
  }
  return Credentials{"ernie",      SecurityLevel::AuthPriv, AuthProtocol::Sha256,
                     "maplesyrup", PrivProtocol::Aes128,    "rubberduck"};
}

// The last v3 slot, an authPriv one, whose Clients are handed the passwords and derive both Master
// Keys on the Deriver, so that the soak takes that path too, held to the same bounds.
constexpr int passwordSlot = clientSlots - 1;
static_assert(isV3(passwordSlot));

// What every Client in a v3 slot is handed: as the README's deployment does, each password replaced
// by its Master Key, derived before the soak starts -- but for passwordSlot's, which keep them.
Credentials clientCredentialsFor(int slot) {
  return slot == passwordSlot ? credentialsFor(slot) : test::withMasterKeys(credentialsFor(slot));
}

// ---------------------------------------------------------------------------
// The Agents' side.
// ---------------------------------------------------------------------------

Behaviour behaviourOf(const Pdu& pdu) {
  // Engine Discovery's requests name nothing; they, and anything else outside the MIB, are
  // answered at once.
  if (pdu.varbinds.empty()) return Behaviour::Prompt;
  const Oid& name = pdu.varbinds.front().name;
  if (name.size() <= soakRoot.size() || !soakRoot.isPrefixOf(name)) return Behaviour::Prompt;
  const auto b = name[soakRoot.size()];
  if (b < 1 || b > lastBehaviourArc) return Behaviour::Prompt;
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
    case Behaviour::Malformed:
      d.malformedFirst = true;
      break;
    case Behaviour::Prompt:
    case Behaviour::Never:
      break;
  }
  return d;
}

// The request's Subtree a name lies in, soakRoot.b.i, if it lies in one.
std::optional<Oid> subtreeOf(const Oid& name) {
  const auto depth = soakRoot.size() + 2;
  if (name.size() < depth || !soakRoot.isPrefixOf(name)) return std::nullopt;
  return Oid(std::span(name.begin(), name.begin() + static_cast<std::ptrdiff_t>(depth)));
}

// The rows of the Subtree a name lies in, and what follows them. An even request's Subtree runs on
// into the next request's first row, so a Walk of it ends by leaving its Subtree; an odd one's
// ends the MIB, so a Walk of it ends at endOfMibView. Both are ways a Walk can end.
std::vector<Varbind> rowsAround(const Oid& name) {
  std::vector<Varbind> rows;
  const auto base = subtreeOf(name);
  if (!base) return rows;
  for (std::uint32_t k = 1; k <= rowsPerRequest; ++k) rows.emplace_back(base->child(k), Gauge32{k});
  const auto request = (*base)[base->size() - 1];
  if (request % 2 == 0) {
    const auto next = Oid(std::span(base->begin(), base->end() - 1));
    rows.emplace_back(next.child(request + 1).child(1), Gauge32{1});
  }
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
  for (const auto& vb : rowsAround(from)) {
    if (p.varbinds.size() >= count) break;
    if (from < vb.name) p.varbinds.push_back(vb);
  }
  if (p.varbinds.size() < count)
    p.varbinds.emplace_back(Oid{1, 3, 6, 1, 6}, ValueException::EndOfMibView);
  return p;
}

// Which planned request a PDU belongs to: the Subtree its first name lies in. Engine Discovery's
// requests name nothing, and belong to none.
std::optional<std::size_t> requestIndexOf(const Pdu& pdu) {
  if (pdu.varbinds.empty()) return std::nullopt;
  const auto base = subtreeOf(pdu.varbinds.front().name);
  if (!base) return std::nullopt;
  return static_cast<std::size_t>((*base)[base->size() - 1]);
}

bool staysSilent(const Pdu& pdu) {
  return behaviourOf(pdu) == Behaviour::Never;
}

// One slot's Agent, of whichever version the slot speaks.
class SoakAgent {
 public:
  SoakAgent(net::IoContext& io, int slot, const DeliveryPlan& delivery) {
    if (!isV3(slot)) {
      auto agent =
          std::make_unique<ScriptedAgent>(io, [](const V2cMessage& msg) -> std::optional<Pdu> {
            if (staysSilent(msg.pdu)) return std::nullopt;
            return answer(msg.pdu);
          });
      agent->setDelivery(delivery);
      m_agent = std::move(agent);
      return;
    }
    auto agent = std::make_unique<ScriptedV3Agent>(io, credentialsFor(slot), answer);
    agent->setResponder([raw = agent.get()](const ScriptedV3Agent::Request& req)
                            -> std::optional<ScriptedV3Agent::Reply> {
      if (staysSilent(req.message.scoped.pdu)) return std::nullopt;
      return raw->behaveLikeACompliantAgent(req);
    });
    agent->setDelivery(delivery);
    m_agent = std::move(agent);
  }

  [[nodiscard]] Target target() const {
    Target t;
    t.endpoint = std::visit([](const auto& agent) { return agent->endpoint(); }, m_agent);
    t.timeout = attemptTimeout;
    t.retries = retries;
    return t;
  }

  // Closed on its own strand, which the io_context's threads may be running.
  void close() {
    std::visit(
        [](const auto& agent) {
          net::asio::dispatch(agent->executor(), [raw = agent.get()] { raw->close(); });
        },
        m_agent);
  }

  // Read once every thread has joined.
  [[nodiscard]] const DeliveryCounts& deliveries() const {
    return std::visit(
        [](const auto& agent) -> const DeliveryCounts& { return agent->deliveries(); }, m_agent);
  }

 private:
  std::variant<std::unique_ptr<ScriptedAgent>, std::unique_ptr<ScriptedV3Agent>> m_agent;
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

// One generation of a slot's Client. Destroying this is destroying the Client, on whichever thread
// lets go of it last -- the one that ended its generation, or one that was still initiating on it.
class ClientInstance {
 public:
  explicit ClientInstance(const net::Executor& ex) : m_client(std::in_place, ex) {}
  ClientInstance(const ClientInstance&) = delete;
  ClientInstance& operator=(const ClientInstance&) = delete;
  ClientInstance(ClientInstance&&) = delete;
  ClientInstance& operator=(ClientInstance&&) = delete;
  ~ClientInstance() {
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

// A Client slot: the Clients that poll one Target in turn, one per generation. The plan names the
// generation each request and disruption reaches, so a thread running behind the plan still
// reaches the Client the seed chose. A generation's Client is made when first needed, and let go
// once the plan has stopped or destroyed it and every request planned on it has been initiated.
//
// Every Client let go here is held in a local declared ahead of the lock, so it is destroyed once
// the lock is let go: ~Client, like stop(), can wait on a Batch handler running on another thread.
class Slot {
 public:
  Slot(net::Executor ex, const std::vector<int>& requestsPerGeneration) : m_ex(std::move(ex)) {
    m_generations.resize(requestsPerGeneration.size());
    for (std::size_t g = 0; g < requestsPerGeneration.size(); ++g)
      m_generations[g].initiationsLeft = requestsPerGeneration[g];
  }

  // For an initiation, which then calls initiated().
  [[nodiscard]] std::shared_ptr<ClientInstance> acquire(int generation) {
    const std::scoped_lock lock(m_mutex);
    return clientOf(generation);
  }

  void initiated(int generation) {
    std::shared_ptr<ClientInstance> released;
    const std::scoped_lock lock(m_mutex);
    auto& g = m_generations.at(static_cast<std::size_t>(generation));
    --g.initiationsLeft;
    if (g.ended && g.initiationsLeft == 0) released = std::move(g.client);
  }

  // Stops the generation's Client, made now if its requests are yet to come so that they meet a
  // stopped Client, as they would have had the plan run to the microsecond.
  void stop(int generation) {
    std::shared_ptr<ClientInstance> stopping;
    {
      const std::scoped_lock lock(m_mutex);
      const auto& g = m_generations.at(static_cast<std::size_t>(generation));
      if (g.client || g.initiationsLeft > 0) stopping = clientOf(generation);
    }
    if (stopping) stopping->stop();
    end(generation);
  }

  // The Target leaves the inventory: the generation's Client goes once nothing else holds it.
  void destroy(int generation) { end(generation); }

  // At the end, on the test thread: every Client still here, stopped by the plan or not, to be read
  // (detail::OutstandingView) before retire() lets them go.
  [[nodiscard]] std::vector<std::shared_ptr<ClientInstance>> remaining() {
    std::vector<std::shared_ptr<ClientInstance>> clients;
    const std::scoped_lock lock(m_mutex);
    for (const auto& g : m_generations) {
      if (g.client) clients.push_back(g.client);
    }
    return clients;
  }

  // At the end, on the test thread.
  void retire() {
    std::vector<std::shared_ptr<ClientInstance>> released;
    const std::scoped_lock lock(m_mutex);
    released.reserve(m_generations.size());
    for (auto& g : m_generations) released.push_back(std::move(g.client));
  }

 private:
  struct Generation {
    std::shared_ptr<ClientInstance> client;
    int initiationsLeft = 0;
    bool ended = false;
  };

  // Under m_mutex.
  std::shared_ptr<ClientInstance> clientOf(int generation) {
    auto& g = m_generations.at(static_cast<std::size_t>(generation));
    if (!g.client) g.client = std::make_shared<ClientInstance>(m_ex);
    return g.client;
  }

  void end(int generation) {
    std::shared_ptr<ClientInstance> released;
    const std::scoped_lock lock(m_mutex);
    auto& g = m_generations.at(static_cast<std::size_t>(generation));
    g.ended = true;
    if (g.initiationsLeft == 0) released = std::move(g.client);
  }

  net::Executor m_ex;
  std::mutex m_mutex;
  std::vector<Generation> m_generations;
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

  // The cancelling thread's. terminalAt is taken once emit() has returned, by when the signal is
  // queued on the Client's strand, ahead of any reply that arrives after it: co_spawn dispatches
  // the signal to its executor when the handler has one of its own, and Client::spawn always binds
  // one.
  bool terminal = false;
  bool total = false;
  steady_clock::time_point terminalAt;

  // When the Agent first sent a whole answer to each exchange of the request, keyed by the name
  // the exchange asked from: one for a request, one per step for a Walk. Retransmissions ask from
  // the same name, so only the first answer to each counts. Written on the Agent's strand.
  mutable std::mutex answersMutex;
  std::map<Oid, steady_clock::time_point> firstAnswers;

  void noteAnswer(const Oid& askedFrom) {
    const auto now = steady_clock::now();
    const std::scoped_lock lock(answersMutex);
    firstAnswers.try_emplace(askedFrom, now);
  }
  // Whether every exchange the request was answered in had its answer on the way by t. A request
  // can succeed only once each of its exchanges is answered, so one that succeeded after a
  // terminal signal sent at t, with an exchange answered only later, ignored the signal.
  [[nodiscard]] bool answeredBy(steady_clock::time_point t) const {
    const std::scoped_lock lock(answersMutex);
    return !firstAnswers.empty() &&
           std::ranges::all_of(firstAnswers, [t](const auto& kv) { return kv.second <= t; });
  }

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

// The request's own Subtree, which a Walk walks: soakRoot.b.i, as subtreeOf() reads it back.
Oid subtreeFor(const Request& r, int index) {
  return soakRoot.child(static_cast<std::uint32_t>(r.behaviour))
      .child(static_cast<std::uint32_t>(index));
}

// One row of the request's Subtree, spread over the rows, for a request that is not a Walk.
Oid nameFor(const Request& r, int index) {
  return subtreeFor(r, index).child(1 + (static_cast<std::uint32_t>(index) % rowsPerRequest));
}

class Soak {
 public:
  explicit Soak(Plan plan) : m_plan(std::move(plan)), m_records(m_plan.requests.size()) {
    const DeliveryPlan delivery = [this](const Pdu& request) {
      auto d = deliveryFor(request);
      const auto index = requestIndexOf(request);
      if (index && *index < m_records.size()) {
        d.onAnswer = [record = &m_records[*index], askedFrom = request.varbinds.front().name] {
          record->noteAnswer(askedFrom);
        };
      }
      return d;
    };
    for (int slot = 0; slot < clientSlots; ++slot) {
      m_credentials.push_back(isV3(slot) ? std::optional(clientCredentialsFor(slot))
                                         : std::nullopt);
      m_agents.push_back(std::make_unique<SoakAgent>(m_clientIo, slot, delivery));
      m_slots.push_back(
          std::make_unique<Slot>(m_clientIo.get_executor(),
                                 m_plan.requestsPerGeneration.at(static_cast<std::size_t>(slot))));
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

    readWhatIsHeld();

    for (auto& slot : m_slots) slot->retire();
    for (auto& agent : m_agents) agent->close();
    m_clientWork.reset();
    m_callerWork.reset();
    for (auto& t : io) t.join();
  }

  // #51: whatever a request left behind that sends nothing -- an exchange still mapped, a discovery
  // or a derivation still registered, a waiter still parked. Read for every Client still alive,
  // with the threads still running it, on its own strand, and before anything stops it: so what
  // reads zero settled on its own rather than being cleared by Stopping. The plan's Stops have
  // stopped some of them already, and those read zero too. The ones it destroyed cannot be read.
  //
  // Every request has completed by now, but a discovery whose requests were all cancelled carries
  // on to its own end (ADR-0003). Each is given settleLimit to get there before it reads as held.
  void readWhatIsHeld() {
    for (const auto& slot : m_slots) {
      for (const auto& instance : slot->remaining()) {
        m_heldAtTheEnd.push_back(test::settledOnStrand(instance->client(), settleLimit));
      }
    }
  }

  void check() {
    EXPECT_TRUE(m_drained) << m_records.size() - m_completions.count() << " of " << m_records.size()
                           << " requests had not completed " << drainLimit.count()
                           << " s after the plan's last event";
    printOutcomes();
    for (std::size_t i = 0; i < m_heldAtTheEnd.size(); ++i) {
      const auto& held = m_heldAtTheEnd[i];
      if (!held) {
        ADD_FAILURE() << "remaining Client " << i << "'s strand never ran the read";
        continue;
      }
      EXPECT_EQ(*held, snmpio::detail::OutstandingCounts{})
          << "remaining Client " << i << " still held something " << settleLimit.count()
          << " ms after its last request completed";
    }
    int failures = 0;
    for (std::size_t i = 0; i < m_records.size(); ++i) {
      if (!checkOne(static_cast<int>(i), m_plan.requests[i], m_records[i])) continue;
      if (++failures > failuresInDetail) break;
    }

    // A run whose Agents never misbehaved proved less than it says. Asked only of a plan with
    // enough requests of the kind that a few lost to Stopping cannot account for none at all.
    DeliveryCounts sum;
    for (const auto& agent : m_agents) sum += agent->deliveries();
    const auto planned = [this](Behaviour b) {
      return std::ranges::count(m_plan.requests, b, &Request::behaviour) >= minimumPlanned;
    };
    if (planned(Behaviour::Late)) {
      EXPECT_GT(sum.delayed, 0) << "no Agent answered late";
    }
    if (planned(Behaviour::Twice)) {
      EXPECT_GT(sum.duplicated, 0) << "no Agent answered twice";
    }
    if (planned(Behaviour::Malformed)) {
      EXPECT_GT(sum.malformed, 0) << "no Agent sent malformed datagrams";
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
        initiate(e.request.value());
        break;
      case Action::CancelTerminal:
      case Action::CancelTotal:
        cancel(e.action, e.request.value());
        break;
      case Action::Stop:
        slotOf(e.client).stop(e.client.generation);
        break;
      case Action::Destroy:
        slotOf(e.client).destroy(e.client.generation);
        break;
    }
  }

  Slot& slotOf(const ClientRef& client) {
    return *m_slots.at(static_cast<std::size_t>(client.slot));
  }

  void initiate(int index) {
    const auto& request = m_plan.requests.at(static_cast<std::size_t>(index));
    auto& record = m_records.at(static_cast<std::size_t>(index));
    auto& slot = slotOf(request.client);
    {
      const auto instance = slot.acquire(request.client.generation);
      record.client = instance->state();
      record.initiatedAt = steady_clock::now();

      const auto target = m_agents.at(static_cast<std::size_t>(request.client.slot))->target();
      if (isV3(request.client.slot)) {
        initiateOn(instance->client(), target,
                   *m_credentials.at(static_cast<std::size_t>(request.client.slot)), request, index,
                   record);
      } else {
        initiateOn(instance->client(), target, soakCommunity, request, index, record);
      }
      record.initiated.store(true, std::memory_order_release);
      record.initiated.notify_all();
    }
    // After this thread's own hold is gone, so that the slot's release can be the last.
    slot.initiated(request.client.generation);
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
    const Oid base = subtreeFor(request, index);

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
  void cancel(Action action, int index) {
    auto& record = m_records.at(static_cast<std::size_t>(index));
    record.initiated.wait(false, std::memory_order_acquire);
    if (action == Action::CancelTerminal) {
      record.terminal = true;
      record.signal.emit(net::asio::cancellation_type::terminal);
      record.terminalAt = steady_clock::now();
    } else {
      record.total = true;
      record.signal.emit(net::asio::cancellation_type::total);
    }
  }

  // True if the request failed a check.
  static bool checkOne(int index, const Request& request, const Record& record) {
    std::vector<net::ErrorCode> allowed;
    // What the Agent's behaviour alone ends the request with, unless a terminal signal rules it
    // out. The signal reaches the strand ahead of any answer sent after it, and the Client weighs
    // terminal ahead of an answer in hand, so such an answer cannot complete the request. Nor can
    // a deadline the signal went out before: the expiry reaches the strand behind it. One gap
    // remains: an answer sent before the signal may still complete it, which is right for a Client
    // that got there first and wrong for one that ignored the signal. The two look the same from
    // here; ClientCancel's sweep of a terminal signal across a reply in hand (#74) pins that race
    // deterministically.
    if (request.behaviour == Behaviour::Never) {
      if (!record.terminal || record.terminalAt >= record.initiatedAt + wholeDeadline)
        allowed.push_back(make_error_code(Errc::Timeout));
    } else if (!record.terminal || record.answeredBy(record.terminalAt)) {
      allowed.emplace_back();
    }
    // Client.hpp's rule: terminal is operation_aborted everywhere, and outranks total; total is
    // operation_aborted for a request and WalkIncomplete for a Walk.
    if (record.terminal || (record.total && !isWalk(request.operation)))
      allowed.emplace_back(net::asio::error::operation_aborted);
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
    // A terminal signal drops a request at once, whatever wait it is in (L2): one that ended long
    // after it was ignored or lost on its way to the strand, and waited out something else (#71).
    if (record.terminal && record.completedAt - record.terminalAt > terminalLimit) {
      ADD_FAILURE() << context() << ": completed "
                    << std::chrono::duration_cast<milliseconds>(record.completedAt -
                                                                record.terminalAt)
                           .count()
                    << " ms after its terminal cancellation";
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
      if (rows != rowsPerRequest) {
        ADD_FAILURE() << context() << ": a complete Walk handed back " << rows << " rows, not "
                      << rowsPerRequest;
        failed = true;
      }
    }
    // Every answer lands inside the first attempt's deadline, so one that took longer was lost
    // and retransmitted for -- a reply that overtook its send, say, which only several threads
    // running the io_context produce.
    if (!code && !isWalk(request.operation) && took >= attemptTimeout) {
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
  // Per slot, for the v3 ones: what every Client in the slot is handed. Written before any thread
  // starts, and only read after.
  std::vector<std::optional<Credentials>> m_credentials;
  std::vector<std::unique_ptr<Slot>> m_slots;
  std::vector<Record> m_records;
  Completions m_completions;
  bool m_drained = false;
  // One per Client still alive at the end, read on its strand before it was let go: empty if the
  // strand never ran the read.
  std::vector<std::optional<snmpio::detail::OutstandingCounts>> m_heldAtTheEnd;
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
