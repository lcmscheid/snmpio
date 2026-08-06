# snmpio

An async C++20 library for SNMPv2c and SNMPv3 command generation — GET, GETNEXT, GETBULK, SET and
subtree walks — built directly on Asio with no net-snmp dependency. Manager side only.

The domain vocabulary this codebase uses is defined in [`CONTEXT.md`](CONTEXT.md); the decisions
that shaped it are in [`docs/adr/`](docs/adr).

## Status

**Stage 1 of 6.** SNMPv2c works end to end over UDP: GET, GETNEXT, GETBULK, SET and Walk.

| Stage | Deliverable | State |
|---|---|---|
| 0 | CMake skeleton, OID/value types, BER encode/decode + fuzz targets | **done** |
| 1 | v2c GET / GETNEXT / GETBULK / SET and Walk over Asio UDP | **done** |
| 2 | v3 message framing, USM auth (MD5, SHA-1, SHA-2), password-to-key, key localization | next |
| 3 | Async engine discovery, time sync, Report handling | |
| 4 | Privacy: AES-128, then AES-192/256 under both key extensions, DES behind an opt-in | |
| 5 | Interop matrix vs the Simulator, `snmpd`, and real vendor gear | |
| 6 | Docs, cancellation semantics, error taxonomy, packaging | |

## Building

```sh
cmake --preset default      # or: standalone, debug, asan, tidy, fuzz
cmake --build --preset default
ctest --preset default
```

Requires a C++20 compiler with coroutine support, CMake 3.24+, and either Boost.Asio 1.77 or
newer (the default) or standalone Asio 1.21 or newer. The version floor is per-operation
cancellation, which the Walk's `total`/`terminal` split is built on. CMake enforces it for
Boost and for standalone Asio found via its config package; the bare-include-directory fallback
has no version to check.
To avoid the Boost dependency, use the `standalone` preset — standalone Asio is `asio` on Arch and
`libasio-dev` on Debian/Ubuntu.

| Preset | What it is |
|---|---|
| `default` | Boost.Asio, `RelWithDebInfo` |
| `standalone` | Standalone Asio, `RelWithDebInfo` |
| `debug` | Boost.Asio, `Debug` |
| `asan` | Boost.Asio, `Debug`, address + undefined-behaviour sanitizers |
| `tidy` | Clang with `clang-tidy` folded into the build |
| `fuzz` | Clang, fuzzers on, tests off |

Each writes to `build/<preset>/`. Editors that read `CMakePresets.json` (VS Code CMake Tools,
CLion, Qt Creator) will offer these directly.

| Option | Default | Meaning |
|---|---|---|
| `SNMP_USE_BOOST_ASIO` | `ON` | Build against Boost.Asio rather than standalone Asio (ADR-0002) |
| `SNMPIO_BUILD_TESTS` | on if top-level | Build the GoogleTest suite |
| `SNMPIO_BUILD_FUZZERS` | `OFF` | Build the libFuzzer targets (Clang only) |
| `SNMPIO_SANITIZE` | `OFF` | Address and undefined-behaviour sanitizers |
| `SNMPIO_WERROR` | `OFF` | Treat warnings as errors |

The Asio choice appears in every public signature, so it is resolved at configure time rather than
at first use — a consumer who gets it wrong finds out from CMake instead of from a page of template
errors. CI builds both.

## Naming

| | |
|---|---|
| types, files | `UpperCamelCase` |
| functions, variables | `lowerCamelCase` |
| private members | `m_lowerCamelCase` |
| namespaces | `lower_case` |

`clang-format` only reflows code, so the convention is enforced by
[`.clang-tidy`](.clang-tidy)'s `readability-identifier-naming`. Public struct fields stay plain
`lowerCamelCase` — `m_` marks encapsulated state, and `vb.m_name` on a POD is only noise.

## Static analysis

[`.clang-tidy`](.clang-tidy) enables `bugprone`, `cert`, `clang-analyzer`, `concurrency`,
`cppcoreguidelines`, `misc`, `modernize`, `performance`, `portability` and `readability` with
`WarningsAsErrors: '*'`. Every disabled check carries its reason in the file — a check switched off
because it was noisy once is a check that will not catch the real defect later.

```sh
cmake --preset default                          # always writes compile_commands.json
clang-tidy -p build/default src/*.cpp tests/*.cpp fuzz/*.cpp
```

Both clang tools are pinned to **22.1.8** — their output changes between major versions, so an
unpinned local install will reformat files CI then rejects. Match it with
`pip install clang-format==22.1.8 clang-tidy==22.1.8` if your distro ships something else.

Or fold it into the build with `-DSNMPIO_CLANG_TIDY=ON`. `tests/` and `fuzz/` carry an overlay
relaxing what only applies to library code (GoogleTest's do-while macros, fixture tables,
`*Oid::parse("1.3.6.1")` on a literal).

Three `NOLINT`s exist, each with its reason at the site: `make_error_code`, whose spelling is fixed
by the standard because both `error_code` types call it unqualified through ADL; the
`SNMPIO_REGISTER_ERROR_CODE_ENUM` macro, which opens a namespace and so cannot be a template; and
the fixed PRNG seed in the round-trip sweep, which exists precisely to be reproducible.

## Fuzzing

```sh
cmake --preset fuzz
cmake --build --preset fuzz
mkdir -p .fuzz-work
./build/fuzz/fuzz/FuzzV2cMessage .fuzz-work fuzz/corpus
```

The first directory is where libFuzzer writes what it finds; `fuzz/corpus` is passed read-only so
the curated seeds stay curated.

Four targets, each asserting a round-trip identity rather than merely "does not crash":

- `FuzzBerValue` — anything the value decoder accepts must re-encode and decode back identically.
- `FuzzBerVarbindList` — the same, over the nesting path: scope entry, length patching, and the
  trailing-data checks a flat value never reaches.
- `FuzzOidText` — the dotted-decimal parser, which is where untrusted *text* enters the OID type.
- `FuzzV2cMessage` — the whole datagram: framing, version, community and the PDU inside them. This
  is the surface a hostile Agent actually reaches.

## What stage 1 contains

- `snmpio::Client` — the Command Generator. It owns the sockets, the outstanding-request table and
  the strand everything internal runs on; there is no session type (ADR-0003). `asyncGet`,
  `asyncGetNext`, `asyncGetBulk`, `asyncSet`, `asyncWalk` and `asyncWalkCollect` all take an Asio
  completion token and report failure as an `error_code`.
- `snmpio::Target` / `snmpio::Community` — a transport endpoint with its timeout and retry count,
  and the string that authorizes a v2c request. Neither knows about the other.
- `snmpio::Pdu` / `snmpio::PduType` — the RFC 3416 PDUs, plus the SNMPv2c message framing around
  them. GETBULK's non-repeaters and max-repetitions are the error-status and error-index slots,
  named by accessors rather than duplicated into a second struct.
- `snmpio::ErrorStatus` — the Agent's own error-status, in a category of its own so that its
  numbering stays the RFC's. A `tooBig` from an Agent is never confused with one of our faults.

Three failure channels reach a completion handler, and they stay distinguishable: the system
category for socket faults, `snmpio` for timeouts and malformed Responses, `snmp-agent` for an
error-status the Agent returned.

Walks stream by default and collect on request (ADR-0004). Both reject a non-increasing OID, both
stop at the Subtree boundary, and both degrade `max-repetitions` when an Agent answers `tooBig`.
Cancellation is split as the ADR requires: `total` stops at a batch boundary and reports
`Errc::WalkIncomplete` alongside what was already delivered, `terminal` drops everything with
`operation_aborted`.

Not yet here, and deliberately: SNMPv3 in any form, Report routing (stage 3), and hostname
resolution — a `Target` is built from an `asio::ip::udp::endpoint`, so resolving is the caller's
choice of resolver rather than a policy this library picks.

## What stage 0 contains

- `snmpio::Oid` — a permissive OID type with lexicographic ordering and subtree-prefix testing. It
  will hold sequences X.690 cannot encode, because it also has to represent what a misbehaving Agent
  sent; `isEncodable()` is the separate question.
- `snmpio::Value` / `snmpio::Varbind` — a variant over the RFC 2578 application types and the three
  RFC 3416 exception markers. Counter32, Gauge32 and TimeTicks are distinct types, not aliases of
  `uint32_t`.
- `snmpio::ber::Reader` / `snmpio::ber::Writer` — a non-throwing codec with sticky errors, so a
  decoder is a straight run of reads with one check at the end. The reader clamps every read to the
  element it is inside; the writer patches sequence lengths in place.
- `snmpio::Errc` — the codec error taxonomy, registered with whichever `error_code` the Asio choice
  selected.

The codec is deliberately **lenient where leniency is unambiguous and strict where it is not**:
redundant integer sign padding and non-minimal long-form lengths are accepted, because agents emit
them and there is only one thing they can mean; indefinite lengths, high-tag-number form, oversized
sub-identifiers and non-minimal OID sub-identifiers are rejected.

## What it deliberately does not contain

No MIB parsing, in this stage or any later one. GET, SET and WALK operate on numeric OIDs, and
nothing in RFC 3411/3412/3414/3416/3417 requires MIB knowledge. If symbolic names are ever wanted
they belong in a separate optional target consuming pre-compiled MIB data.

## Contributing

Issues and specs live in [GitHub Issues](https://github.com/lcmscheid/snmpio/issues). Triage uses
five labels — `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE), and ADR-0007 for why. Same licence as
[`snmp-fault-agent`](https://github.com/lcmscheid/snmp-fault-agent), the simulator CI tests against.

There are no per-file copyright headers, deliberately: copyright is automatic, and a boilerplate
block on every file is upkeep that buys nothing.
