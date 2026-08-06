# snmpio

An async C++20 library for SNMPv2c and SNMPv3 command generation — GET, GETNEXT, GETBULK, SET and
subtree walks — built directly on Asio with no net-snmp dependency. Manager side only.

The domain vocabulary this codebase uses is defined in [`CONTEXT.md`](CONTEXT.md); the decisions
that shaped it are in [`docs/adr/`](docs/adr).

## Status

**Stage 4 of 6.** SNMPv2c and SNMPv3 both work end to end over UDP: GET, GETNEXT, GETBULK, SET and
Walk, at all three Security Levels. Engine Discovery, time synchronisation and Report routing happen
underneath and are never surfaced. `authPriv` speaks DES, AES-128, and AES-192/256 under both the
Blumenthal and the Reeder key extension.

| Stage | Deliverable | State |
|---|---|---|
| 0 | CMake skeleton, OID/value types, BER encode/decode + fuzz targets | **done** |
| 1 | v2c GET / GETNEXT / GETBULK / SET and Walk over Asio UDP | **done** |
| 2 | v3 message framing, USM auth (MD5, SHA-1, SHA-2), password-to-key, key localization | **done** |
| 3 | Async engine discovery, time sync, Report handling | **done** |
| 4 | Privacy: AES-128, then AES-192/256 under both key extensions, DES behind the legacy provider | **done** |
| 5 | Interop matrix vs the Simulator, `snmpd`, and real vendor gear | next |
| 6 | Docs, cancellation semantics, error taxonomy, packaging | |

## Building

```sh
cmake --preset default      # or: standalone, debug, asan, tidy, fuzz
cmake --build --preset default
ctest --preset default
```

Requires a C++20 compiler with coroutine support, CMake 3.24+, OpenSSL 3.0 or newer, and either
Boost.Asio 1.77 or newer (the default) or standalone Asio 1.21 or newer. The Asio floor is
per-operation cancellation, which the Walk's `total`/`terminal` split is built on. CMake enforces
it for Boost and for standalone Asio found via its config package; the bare-include-directory
fallback has no version to check.

OpenSSL supplies the hashes and HMACs USM needs (ADR-0001). It is required rather than optional:
SNMPv3 is the reason this library exists, and a build with USM silently missing would be a trap.

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

Four `NOLINT`s exist, each with its reason at the site: `make_error_code`, whose spelling is fixed
by the standard because both `error_code` types call it unqualified through ADL; the
`SNMPIO_REGISTER_ERROR_CODE_ENUM` macro, which opens a namespace and so cannot be a template; the
fixed PRNG seed in the round-trip sweep, which exists precisely to be reproducible; and the
`std::getenv` the interop harness reads its Target from, which runs before any test thread does.

## Interop tests

`ctest` runs everything against the Scripted Agent, which shares our own reading of the protocol.
The interop suite is the half that does not: it talks to an Agent nobody here wrote, over a real
socket. There is no Agent in a bare checkout, so those tests **skip** unless a Target is named.
`-R Interop` selects exactly the live ones — the harness's own parsing tests are named `Harness*`,
so a run filtered to `Interop` that reports all green really did reach an Agent.

```sh
SNMPIO_INTEROP_TARGET=127.0.0.1:16161 ctest --preset default -R Interop --output-on-failure
```

`SNMPIO_INTEROP_TARGET` is the Target the Agent answers at, as `address`, `address:port` or
`[v6]:port`. Unset, the suite skips.

An address, not a hostname. A `Target` is built from an endpoint so that choosing a resolver stays
the caller's business (stage 1), and the harness is a caller like any other — so a hostname is
rejected outright rather than quietly resolved. A variable that is set but unusable **fails** the
suite; only an unset one skips it, since a typo that skipped would report green for an Agent it
never reached.

Any Agent will do. An `snmpd` on a spare port is enough to see it work:

```sh
printf 'rocommunity public 127.0.0.1\n' > /tmp/snmpd.conf
snmpd -f -Lo -C -c /tmp/snmpd.conf udp:127.0.0.1:16161
```

The suite currently proves one live exchange — a v2c GET of `sysDescr.0`, which it prints, because
no two Agents say the same thing and which one answered is the first thing a failed run needs. CI
runs it against a containerless `snmpd` on every commit. SNMPv3 against `snmpd`, the Simulator at a
pinned digest and the misbehaviour cases are the rest of stage 5.

## Fuzzing

```sh
cmake --preset fuzz
cmake --build --preset fuzz
mkdir -p .fuzz-work
./build/fuzz/fuzz/FuzzV2cMessage .fuzz-work fuzz/corpus
```

The first directory is where libFuzzer writes what it finds; `fuzz/corpus` is passed read-only so
the curated seeds stay curated.

Five targets, each asserting a round-trip identity rather than merely "does not crash":

- `FuzzBerValue` — anything the value decoder accepts must re-encode and decode back identically.
- `FuzzBerVarbindList` — the same, over the nesting path: scope entry, length patching, and the
  trailing-data checks a flat value never reaches.
- `FuzzOidText` — the dotted-decimal parser, which is where untrusted *text* enters the OID type.
- `FuzzV2cMessage` — the whole datagram: framing, version, community and the PDU inside them. This
  is the surface a hostile Agent actually reaches.
- `FuzzV3Message` — the v3 datagram, `verifyAuth` over whatever it decodes to, and `decryptScopedPdu`
  over an encryptedPDU. The digest's offset is derived from attacker-controlled length fields and is
  then used to index the datagram, which is exactly the shape of bug a fuzzer under ASan finds and
  review does not; decryption then hands a buffer of noise to the BER decoder, which is the same
  shape one layer down.

## What stage 4 contains

- `snmpio::PrivProtocol` and two more `Credentials` fields — the privacy protocol and its own
  secret. There is no second hash to name: USM derives the privacy key with the *authentication*
  protocol's hash. `authPriv` with no privacy protocol fails with `Errc::UnsupportedPrivProtocol`
  rather than being sent in the clear.
- **DES-CBC** (RFC 3414 section 8) and **AES-CFB128** at 128, 192 and 256 bits (RFC 3826 and the
  Blumenthal draft). ADR-0005 is why DES is here at all; it lives in OpenSSL 3.x's legacy provider,
  which is loaded lazily on first use, so a build without it loses *that operation* and not the
  library.
- **Both key extensions**, because the Localized Key is shorter than an AES-192/256 key whenever
  the hash is. `Aes192`/`Aes256` are Blumenthal — append the hash of the key so far — and
  `Aes192C`/`Aes256C` are Reeder, which runs the key back through password-to-key and localizes it
  again. They are separate enumerators rather than a protocol plus a flag, so "AES-192, extension
  unspecified" is a state that cannot be written down (CONTEXT.md: never inferred, never guessed).
- **Encryption inside the message layer**, not beside it: `encodeV3Message` encrypts the ScopedPDU
  and writes the salt it chose into msgPrivacyParameters, then computes the digest over the
  finished message — so authentication covers the ciphertext, and the two are done in the order
  RFC 3414 section 3.2 checks them in.
- `decodeV3Message` stops at the ciphertext and `decryptScopedPdu` opens it, because the key is a
  property of the *request this answers* and finding that request needs the `msgID` the decode
  produced. A reply that will not decrypt is dropped exactly like one whose digest is wrong: the
  request stays outstanding and its retransmission timer keeps running.
- The privacy key is cached beside the authentication one, on (engineID, hash, secret, privacy
  protocol). The protocol is part of the cache key because it decides how far the derivation is
  extended — and under Reeder that extension is a second megabyte hash.

"DES behind an opt-in", as the stage was first written, is the legacy provider rather than a build
flag: ADR-0005 rules a build flag out, so the opt-in is naming `PrivProtocol::Des` on an OpenSSL
that has the provider. Nothing else changes shape for it.

Not in stage 4: 3DES, which ADR-0005 names alongside DES and no stage yet carries -- an open gap
against that ADR rather than a decision against it -- and IDEA, which ADR-0005 excludes outright.

## What stage 3 contains

- `Client`'s six operations again, taking `Credentials` where the v2c ones take a `Community`.
  Same completion signatures, same three error categories; the type of that one argument is the
  whole of the difference at the call site.
- **Engine Discovery**, RFC 3414 section 4, as ordinary async work on the `Client`'s existing
  strand — which is the entire point of ADR-0001, since net-snmp doing this synchronously inside
  its send path is why this library exists. Phase one learns the engineID; phase two, needed only
  when authenticating, learns the boots/time pair. Requests arriving while a discovery is in
  flight queue behind it rather than each probing separately.
- **Caches**, owned by the `Client` because ADR-0003 says there is nowhere else, and keyed the way
  that ADR requires: the Authoritative Engine on its **engineID**, with a separate endpoint→engineID
  index, and the Localized Key on (engineID, protocol, secret). One Engine reachable at two Targets
  is therefore one cache entry and one megabyte-hash derivation, which is the whole reason there is
  no session type.
- **Report routing.** The six `usmStats` counters map to outcomes in one table: `notInTimeWindows`
  and `unknownEngineIDs` resynchronise and retry exactly once, the rest fail the request with an
  `ErrorCode` naming which. No Report ever reaches a completion handler.
- **The Time Window**, 150 seconds, checked against the cached pair projected forward by the local
  clock rather than against a raw cached number.
- Discovery **outlives the request that started it** (ADR-0003 again): it runs detached on the
  Client's strand, so cancelling whichever request happened to arrive first does not cancel what
  every other request is queued behind.

A **Response** that fails to decode, to authenticate, or to be timely is dropped, not failed — the
request stays outstanding and its retransmission timer keeps running. UDP is spoofable and the
`msgID` is guessable, so the alternative is a library whose requests anyone on the path can cancel.

**Reports are the exception, and cannot not be.** The four counters worth hearing about are exactly
the ones an Engine cannot sign — it does not know the user, or the key, or the engineID it was
addressed by — so refusing an unauthenticated Report would turn "wrong password" into "timed out".
They are accepted against an outstanding `msgID` from the address we sent to, which is the same bar
a spoofed v2c Response clears. What an unauthenticated Report can never do is change cached state:
resynchronising the boots/time pair requires a Report whose digest verified, and anything else that
asks us to resynchronise gets a full re-discovery instead, whose own answer is authenticated.

Outstanding requests are keyed on the Message ID rather than the PDU's request-id, as CONTEXT.md
requires: a message that cannot be opened must still be attributable to the request that sent it.

## What stage 2 contains

- `snmpio::AuthProtocol` / `snmpio::SecurityLevel` / `snmpio::Credentials` — the USM user, the
  level they authenticate at, and the protocol behind it. MD5 and SHA-1 are present on purpose
  (ADR-0005). Security Level is valued as its `msgFlags` bits, the way `PduType` is valued as its
  BER tag.
- `snmpio::passwordToKey` / `snmpio::localizeKey` — RFC 3414 appendix A.2's megabyte expansion, and
  the hash that binds the resulting Master Key to one Engine. Both are checked against the RFC's
  own MD5 and SHA-1 vectors. Neither caches: a cache without an owner is a leak, and stage 3 owns
  the per-(Credentials, engineID) one.
- `snmpio::V3Header` / `snmpio::UsmParameters` / `snmpio::ScopedPdu` — RFC 3412's message framing,
  RFC 3414's security parameters inside their OCTET STRING, and the PDU with the context it is
  interpreted in.
- `encodeV3Message` / `verifyAuth` — the digest computed over the finished message with its own
  field blanked, and checked in constant time on the way back. Each layer is encoded into its own
  buffer and then wrapped, so that a sequence length widening past 127 Octets cannot silently move
  the digest; the long-user-name test is the one that fails if that changes.

Not in stage 2: privacy, which arrived with stage 4 and put the encryption either side of the
digest in `encodeV3Message` and `decryptScopedPdu`; and timeliness, which needs the cached engine
state discovery produces and so arrived with stage 3.

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

Not in stage 1, and deliberately: SNMPv3 in any form (stages 2 and 3), and hostname resolution —
a `Target` is built from an `asio::ip::udp::endpoint`, so resolving is the caller's choice of
resolver rather than a policy this library picks, in this stage or any later one.

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
