# Support both Boost.Asio and standalone Asio from one source

The library compiles against either Boost.Asio or standalone Asio, selected by a
`SNMP_USE_BOOST_ASIO` CMake option, with a single internal shim header aliasing the namespace and
error-code type. We default to standalone Asio so that consumers are not forced to take a Boost
dependency, while Boost.Asio remains available for codebases already invested in Boost.

This looks like over-engineering, and it is recorded here because it is not: the choice leaks into
**every public signature** — `asio::awaitable` vs `boost::asio::awaitable`, `std::error_code` vs
`boost::system::error_code` — so it cannot be retrofitted without breaking every user. Paying roughly
fifty lines of aliasing at the start avoids an unfixable decision later.

## Consequences

Public headers must never name the Asio namespace or `error_code` type directly; they go through the
shim. CI has to build both configurations, or the untested one will silently rot.
