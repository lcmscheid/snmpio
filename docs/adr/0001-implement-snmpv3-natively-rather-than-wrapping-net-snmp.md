# Implement SNMPv3 natively rather than wrapping net-snmp

net-snmp is the obvious foundation for anything SNMP, so a future reader will ask why we did not use
it. **We did in fact start there** — an async net-snmp wrapper was prototyped first, and this
decision is the result of hitting its limits rather than of analysis alone. We are now implementing
the protocol natively — BER codec, message processing, USM, engine discovery
— on Asio and OpenSSL EVP, because net-snmp performs SNMPv3 engine discovery **synchronously inside
its send path** (`usm_discover_engineid()` calls `snmp_sess_synch_response()`, reached from
`snmpv3_build()` during send), which is precisely the blocking round-trip an async library cannot
contain. The escape hatch (`SNMP_FLAGS_DONT_PROBE`) requires us to drive discovery ourselves, meaning
we would write the interesting half of USM anyway while still inheriting net-snmp's `fd_set`/`select`
readiness model and its large MIB-parsing subsystem that we do not need.

## Considered options

- **Wrap net-snmp.** Fastest to first working GET, and correct by construction. **Prototyped and
  abandoned.** Rejected for the synchronous-discovery reason above: the result is an async-looking
  facade over blocking calls, typically run on a dedicated thread pool. The prototype is retained
  privately for reference; we are explicitly *not* shipping it as an alternate backend, since
  maintaining two backends behind one API would constrain the public API to the intersection of what
  both can express.
- **FFI to a Rust crate (`async-snmp` or `snmp2`).** Both genuinely implement USM. Rejected because
  neither exposes a C ABI, both are tokio-native, and adopting one means running two reactors in one
  process and marshalling every completion back onto the caller's Asio executor — paying the full
  price of a foreign async runtime to avoid writing roughly two thousand lines of C++.
- **Build on SNMP++.** The only complete C++ USM implementation, but its threading model is not Asio
  (same impedance problem as net-snmp), its design predates C++11, and its licence is a bespoke
  HP-derived grant we could not verify against upstream. Useful as a correctness oracle only.

## Consequences

The scope is smaller than it appears — measured from the reference implementations, USM is on the
order of 1,100 lines in Go and 1,200 in Rust, and we deliberately carry no MIB parsing because
GET/SET/WALK are numeric-OID operations. The real cost is not code volume but *field knowledge*: the
interop workarounds that mature implementations have accumulated. We therefore treat gosnmp
(BSD-3-Clause) and `async-snmp` (MIT OR Apache-2.0) as reading references and port their algorithm
constants, state machines, key-extension handling and test-case lists, with attribution in `NOTICE`.

The full analysis behind this decision, with primary-source citations, is in
[`docs/research/async-snmpv3-cpp-library-options.md`](../research/async-snmpv3-cpp-library-options.md).
