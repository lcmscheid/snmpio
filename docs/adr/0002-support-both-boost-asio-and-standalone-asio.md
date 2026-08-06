# Support both Boost.Asio and standalone Asio from one source

The library compiles against either Boost.Asio or standalone Asio, selected by a
`SNMP_USE_BOOST_ASIO` CMake option, with a single internal shim header aliasing the namespace and
error-code type. **Boost.Asio is the default**, with standalone Asio available for consumers who
would rather not take a Boost dependency.

This looks like over-engineering, and it is recorded here because it is not: the choice leaks into
**every public signature** — `asio::awaitable` vs `boost::asio::awaitable`, `std::error_code` vs
`boost::system::error_code` — so it cannot be retrofitted without breaking every user. Paying roughly
fifty lines of aliasing at the start avoids an unfixable decision later.

## Consequences

Public headers must never name the Asio namespace or `error_code` type directly; they go through the
shim. CI has to build both configurations, or the untested one will silently rot.

The default is only a default. Because it is a build-time switch and not a source change, flipping
it costs nothing structural — which is the whole point of paying for the shim up front. What would
be expensive is *not* having the shim, and that part of this decision is unchanged.

## Amendment, 2026-08-06: the default is now Boost.Asio

Originally recorded the other way round, on the reasoning that a default of standalone Asio avoids
imposing a Boost dependency on consumers. Reversed in practice: Boost is what the development
environment has, and a default that does not configure out of the box on the machine the work
happens on is a default that gets worked around on every checkout rather than used.

Standalone Asio is unchanged in status — still supported, still built by CI on every commit, still
one `-DSNMP_USE_BOOST_ASIO=OFF` away. Only which of the two you get for free has moved.
