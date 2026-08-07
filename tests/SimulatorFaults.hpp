#ifndef SNMPIO_TESTS_SIMULATORFAULTS_HPP
#define SNMPIO_TESTS_SIMULATORFAULTS_HPP

#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <tuple>

#include <snmpio/detail/Net.hpp>

namespace snmpio::test {

// Tells the Simulator to misbehave, over the same form POST its web UI uses.
//
// Not an Agent, and not named as one: CONTEXT.md keeps *Agent* for a command responder, and this
// is the thing driving one from the other side. The Agent it drives is the *Simulator*, which is
// the only Agent that can be told any of this.
//
// Every fault this drives is a condition a correct Agent never produces, which is the whole reason
// the Simulator is CI's primary target (ADR-0006): the guards in Walk, the boots/time comparison,
// and the decoder's refusal of malformed input only run once something has already gone wrong.
//
// Faults are cleared in the destructor, so a test that fails an assertion mid-fault does not hand
// a broken Agent to the next one -- which would fail it for a reason that is not its own.
class SimulatorFaults {
 public:
  // The control channel is on the Target's own address, one port over -- it is the same process.
  // ponytail: the URL takes a v4 literal; a v6 Simulator would want the brackets a URL wants.
  SimulatorFaults(const net::UdpEndpoint& target, std::uint16_t controlPort)
      : m_control(target.address().to_string() + ":" + std::to_string(controlPort)) {}

  SimulatorFaults(const SimulatorFaults&) = delete;
  SimulatorFaults(SimulatorFaults&&) = delete;
  SimulatorFaults& operator=(const SimulatorFaults&) = delete;
  SimulatorFaults& operator=(SimulatorFaults&&) = delete;
  // The Agent's own state, not this object's, so a failed clear on the way out has nothing left
  // to report to: the next test's own set() is what fails if it did not take.
  ~SimulatorFaults() { std::ignore = clear(); }

  // Fault names are the Simulator's own: tooBig, nonIncreasingOID, truncateBytes, engineBootsBump
  // and the rest. Returns false when the Agent did not answer 200 (curl's -f), which a test
  // asserts on rather than ignoring: a fault that was never set makes the assertion after it
  // meaningless.
  [[nodiscard]] bool set(std::string_view name, std::string_view value) {
    return post("/faults", std::string("name=").append(name).append("&value=").append(value));
  }

  [[nodiscard]] bool clear() { return post("/faults/clear", ""); }

 private:
  // curl rather than an HTTP client written here: it is already what CI waits for the Simulator's
  // UI with, and the whole of the exchange is one form POST whose status is the only answer.
  bool post(std::string_view path, const std::string& body) {
    std::string command("curl -fsS -o /dev/null --max-time 5 --data '");
    // Single-quoted, and every value passed in is a fault name or a number written in this tree --
    // nothing here comes from outside it.
    command.append(body).append("' http://").append(m_control).append(path);
    // NOLINTNEXTLINE(concurrency-mt-unsafe,cert-env33-c,bugprone-command-processor): a test helper.
    return std::system(command.c_str()) == 0;
  }

  std::string m_control;
};

}  // namespace snmpio::test

#endif  // SNMPIO_TESTS_SIMULATORFAULTS_HPP
