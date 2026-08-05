# Async SNMPv3 C++ library — build natively, port, or wrap net-snmp?

**Date:** 2026-08-05
**Repo activity / source checks all performed:** 2026-08-05

**Question being answered:** We want a modern async C++ (CMake, Boost.Asio) library for SNMPv3
GET / SET / SNMPWALK. (1) Is implementing SNMPv3 natively — BER, USM, crypto, message processing,
engine discovery — feasible and sensible without wrapping net-snmp? (2) Could it be based on or
ported from an existing implementation, e.g. a Rust async SNMP crate, or bound via FFI?
(3) What are the realistic options and their trade-offs?

**Citation rule used here:** every capability claim links to the RFC section, repo file, or docs page
that establishes it. Where I could not verify something from a primary source I say **unverified**.

---

## TL;DR / recommendation

**Implement SNMPv3 natively in C++ on Boost.Asio, using gosnmp and the Rust `async-snmp` /
`snmp2` crates as *reading references* (not as code to link against), and OpenSSL EVP for crypto.
Do not wrap net-snmp. Do not FFI into a Rust crate.**

The reasoning, in order of weight:

1. **The scope is genuinely small.** SNMPv3 USM is not a large protocol. Concrete evidence, measured
   from the actual sources on 2026-08-05:
   - `snmp2`'s complete v3/USM implementation (all auth protocols, DES + AES-128/192/256, key
     localization, engine time handling) is **one 1,229-line file**
     ([src/v3.rs](https://github.com/roboplc/snmp2/blob/main/src/v3.rs)).
   - gosnmp's USM is **1,079 lines**
     ([v3_usm.go](https://github.com/gosnmp/gosnmp/blob/master/v3_usm.go)).
   - `async-snmp`'s v3 subsystem is ~5,400 lines *including* doc comments and inline unit tests
     (`src/v3/{auth,privacy,engine,usm,encode,process}.rs`).

   You are not reimplementing net-snmp. You are reimplementing a BER subset, an HMAC/cipher
   wrapper, and a small state machine. That is a few-thousand-line C++ library, not a multi-year
   effort.

2. **The wrapper option is actively bad for an async library.** net-snmp performs SNMPv3 engine
   discovery **synchronously, inside the send path**. Verified in source: `usm_discover_engineid()`
   calls `snmp_sess_synch_response()`
   ([snmpusm.c:3867–3881](https://github.com/net-snmp/net-snmp/blob/master/snmplib/snmpusm.c)), and
   `snmpv3_engineID_probe()` is invoked from `snmpv3_build()` during send
   ([snmp_api.c:5224–5236](https://github.com/net-snmp/net-snmp/blob/master/snmplib/snmp_api.c)) as
   well as from `snmp_sess_add()`
   ([snmp_api.c:1979–1981](https://github.com/net-snmp/net-snmp/blob/master/snmplib/snmp_api.c)).
   A blocking round-trip inside `async_send` is precisely the thing an Asio library must not do.
   There is an escape hatch (`SNMP_FLAGS_DONT_PROBE` + `snmpv3_probe_usm_pdu_create()`,
   [snmp_api.c:1420–1444](https://github.com/net-snmp/net-snmp/blob/master/snmplib/snmp_api.c)), but
   taking it means you drive discovery yourself — i.e. you write the interesting half of USM anyway,
   and still inherit net-snmp's `fd_set`/`select` integration model.

3. **The Rust FFI option buys you a runtime you don't want.** The only Rust crates with complete v3
   are tokio-based. Linking them means shipping a tokio reactor alongside your `io_context`,
   marshalling completions across the boundary, and exporting a C ABI that doesn't exist yet
   (neither `snmp2` nor `async-snmp` has a `cbindgen`/`cxx` surface — verified by inspecting both
   crate trees). All that to avoid writing ~2,000 lines of C++.

4. **Porting is the right use of the prior art.** gosnmp is BSD-3-Clause
   ([LICENSE](https://github.com/gosnmp/gosnmp/blob/master/LICENSE)) and `snmp2` / `async-snmp` are
   MIT-OR-Apache-2.0 — all permissive and all compatible with reading them as references and even
   with derived work, given attribution. Their value is the *interop knowledge* baked in, not the
   code. Example: gosnmp carries an explicit workaround for Dell EMC switches that answer discovery
   probes with `usmStatsUnknownUserNames` rather than `usmStatsUnknownEngineIDs`
   ([v3.go:166–173](https://github.com/gosnmp/gosnmp/blob/master/v3.go)). You will not derive that
   from the RFC.

**Secondary recommendation:** if the timeline is hard and SNMPv3 is needed *now* in C++, SNMP++
(agentpp.com) is the only serious existing C++ USM implementation and it already covers everything
including the non-standard AES variants — but its threading/async model is not Asio, and its license
is an HP-derived custom permissive text, not Apache-2.0 (see below). Treat it as a fallback or a
correctness oracle, not a foundation.

---

## What SNMPv3 actually requires

### Architecture and message layer

- **RFC 3411** defines the engine as four subsystems — Dispatcher (§3.1.1.2), Message Processing
  (§3.1.1.3), Security (§3.1.1.4), Access Control (§3.1.2) — and the three securityLevels
  `noAuthNoPriv` / `authNoPriv` / `authPriv` (§3.4.3). Abstract Service Interfaces are in §4.
  ([RFC 3411](https://datatracker.ietf.org/doc/html/rfc3411))
  *A pure manager-side library needs the Dispatcher/MP/Security shape but can skip Access Control
  entirely (that's VACM, an agent concern).*

- **RFC 3412** defines the v3 message: `msgVersion`, `msgGlobalData` (`msgID`, `msgMaxSize`,
  `msgFlags`, `msgSecurityModel`), `msgSecurityParameters` as an OCTET STRING, and `msgData` as
  either plaintext or encrypted `ScopedPDU` (`contextEngineID`, `contextName`, `data`). ASN.1 module
  in §6; `msgFlags` bits (authFlag=0, privFlag=1, reportableFlag=2, reserved bits MUST be zero on
  send) in §6.4. Critically, §6.2 states the `msgID` is engine-level and **need not match** the
  PDU's `request-id` — the engine must be able to identify a message even when decryption fails.
  ([RFC 3412](https://datatracker.ietf.org/doc/html/rfc3412))
  *Implication: your outstanding-request map must be keyed on `msgID`, not `request-id`.*

- **RFC 3416** defines the PDUs and their context tags: GetRequest `[0]`, GetNextRequest `[1]`,
  Response `[2]`, SetRequest `[3]`, GetBulkRequest `[5]`, InformRequest `[6]`, SNMPv2-Trap `[7]`,
  Report `[8]` (§3). GetBulk's `non-repeaters` N / `max-repetitions` M semantics are §4.2.3.
  ObjectSyntax application types: IpAddress `[APPLICATION 0]`, Counter32 `[1]`, Unsigned32/Gauge32
  `[2]`, TimeTicks `[3]`, Opaque `[4]`, Counter64 `[6]`. VarBind exceptions `noSuchObject [0]`,
  `noSuchInstance [1]`, `endOfMibView [2]`, all IMPLICIT NULL (§3).
  ([RFC 3416](https://datatracker.ietf.org/doc/html/rfc3416))

- **RFC 3417** §3.2: UDP/IPv4 is the preferred mapping, port 161 (command responder) / 162
  (notification receiver); implementations must accept messages of at least 484 octets, 1472
  recommended. §8: BER with **definite-form lengths only**, primitive form for simple types.
  ([RFC 3417](https://datatracker.ietf.org/doc/html/rfc3417))
  *This is why the BER subset is small: no indefinite lengths, no CER/DER canonicalization needed.*

### USM security

**RFC 3414** ([full text](https://datatracker.ietf.org/doc/html/rfc3414)) is the bulk of the work:

| Requirement | RFC 3414 section | Notes |
|---|---|---|
| Elements of procedure, outgoing (9 steps) | §3.1 | encrypt → set engine IDs → set boots/time → encode user → authenticate whole message |
| Elements of procedure, incoming (12 steps) | §3.2 | parse secparams → known engine? → user lookup → authenticate → **timeliness** → decrypt |
| `msgAuthoritativeEngineID` | §2.2.1 | defeats cross-engine replay |
| `msgAuthoritativeEngineBoots` / `Time` | §2.2.2 | time resets to 0 and boots increments at 2147483647 |
| 150-second time window | §2.2.3 | same value for all users |
| Time synchronization / `latestReceivedEngineTime` | §3.2 step 7b | update local state only if boots increased, or boots equal and time newer |
| Discovery procedure | §4 | noAuthNoPriv request, empty user, empty engineID → Report carries the engineID; then authenticated request with boots/time = 0 → Report carries real boots/time |
| Password-to-key | Appendix A.2 (A.2.1 MD5, A.2.2 SHA); test vectors A.3 | expand password to 1,048,576 octets, hash, then `H(Ku ‖ engineID ‖ Ku)` for localization |
| Key change | Appendix A.5 (+ test vectors) | only needed if you support USM key change over SNMP |
| HMAC-MD5-96 | §6 | truncate to 12 octets |
| HMAC-SHA-96 | §7 | truncate to 12 octets |
| CBC-DES privacy | §8.1.1 (IV §8.1.1.1, encrypt §8.1.1.2, decrypt §8.1.1.3) | 16-octet localized key: first 8 = DES key, last 8 = pre-IV; salt = boots ‖ local counter; IV = pre-IV XOR salt |
| usmStats report OIDs | §5 | `UnsupportedSecLevels`, `NotInTimeWindows`, `UnknownUserNames`, `UnknownEngineIDs`, `WrongDigests`, `DecryptionErrors` |
| `notInTimeWindow` reports at authNoPriv | §3.2 step 7a | a report that is itself authenticated |

**RFC 3826** adds AES: **CFB128-AES-128 only**, key = first 128 bits of the localized key, IV =
32-bit `snmpEngineBoots` ‖ 32-bit `snmpEngineTime` ‖ 64-bit salt integer. It explicitly does *not*
define AES-192 or AES-256. ([RFC 3826](https://datatracker.ietf.org/doc/html/rfc3826))

**RFC 7860** adds the SHA-2 auth protocols
([RFC 7860](https://datatracker.ietf.org/doc/html/rfc7860)):

| Protocol | Hash | Truncation (HMAC output in msg) | Key length | OID |
|---|---|---|---|---|
| usmHMAC128SHA224AuthProtocol | SHA-224 | 16 octets | 28 | 1.3.6.1.6.3.10.1.1.4 |
| usmHMAC192SHA256AuthProtocol | SHA-256 | 24 octets | 32 | 1.3.6.1.6.3.10.1.1.5 |
| usmHMAC256SHA384AuthProtocol | SHA-384 | 32 octets | 48 | 1.3.6.1.6.3.10.1.1.6 |
| usmHMAC384SHA512AuthProtocol | SHA-512 | 48 octets | 64 | 1.3.6.1.6.3.10.1.1.7 |

RFC 7860 reuses RFC 3414 Appendix A.1's password-to-key with the hash swapped ("the derivation
SHOULD be performed using the password-to-key algorithm from Appendix A.1 of RFC 3414 with MD5 being
replaced by the SHA-2 hash function H").

### The genuinely hard / subtle parts

These are where a from-scratch implementation will actually lose time:

1. **Engine discovery is a two-phase handshake, not one round-trip.** RFC 3414 §4 requires a
   noAuth probe to learn the engineID, *then* an authenticated request with boots/time zeroed to
   provoke a `notInTimeWindow` Report that carries the real boots/time. Devices vary in how they
   respond; gosnmp explicitly tolerates `usmStatsUnknownUserNames` in place of
   `usmStatsUnknownEngineIDs` ([v3.go:166–173](https://github.com/gosnmp/gosnmp/blob/master/v3.go)).

2. **Time sync bookkeeping.** You must track `latestReceivedEngineTime` separately from the boots/time
   pair and apply the RFC 3414 §3.2 step 7b ordering rule, and the client must *not* locally bump
   boots when its extrapolated time saturates — see `async-snmp`'s note on exactly this in
   [src/v3/engine.rs](https://github.com/lukeod/async-snmp/blob/main/src/v3/engine.rs) ("the client
   does not locally increment `engine_boots` … the authoritative engine is responsible").

3. **AES-192/256 are not standardized, and there are *two* incompatible key-extension schemes.**
   - **Blumenthal** — `draft-blumenthal-aes-usm-04` §3.1.2.1, which extends the localized key by
     `Kul = Kul ‖ H(Kul)` repeated `ceil(256/nnn)` times
     ([draft text](https://www.ietf.org/archive/id/draft-blumenthal-aes-usm-04.txt)).
   - **Reeder** — `draft-reeder-snmpv3-usm-3desede-00` §2.1, which instead *chains the
     password-to-key algorithm itself*, feeding each output back in with the same engineID
     ([draft text](https://www.ietf.org/archive/id/draft-reeder-snmpv3-usm-3desede-00.txt)). This
     draft's actual subject is 3DES-EDE (32-octet key: 24 for the three DES subkeys, 8 as pre-IV);
     the key-extension is a side effect that Cisco later reused for AES-192/256.
   - The Reeder draft is **expired** (IESG state "Expired", last updated 1999-10-07 —
     [datatracker](https://datatracker.ietf.org/doc/draft-reeder-snmpv3-usm-3desede/)).
   - Real implementations therefore ship *both* and let the user pick. gosnmp has separate enum
     values `AES192`/`AES256` (Blumenthal) and `AES192C`/`AES256C` (Reeder) —
     [v3_usm.go:122–127](https://github.com/gosnmp/gosnmp/blob/master/v3_usm.go). SNMP++ has
     `PrivAES` and a separate `PrivAESW3DESKeyExt` whose comment reads "Encryption module using AES
     but using non standard key extension … illegally use the 3DES key extension algorithm with AES
     privacy" —
     [auth_priv.h:677–686](https://github.com/ClausKlein/snmp_pp/blob/develop/include/snmp_pp/auth_priv.h).
     `async-snmp` models it as a `KeyExtension::{Blumenthal, Reeder}` enum
     ([src/v3/privacy.rs:185–186, 262–266](https://github.com/lukeod/async-snmp/blob/main/src/v3/privacy.rs)).

   **This is the single most likely source of "works with Cisco, fails with Juniper" bugs.**

4. **Authenticate-over-the-whole-message with a placeholder.** RFC 3414 §3.1 step 8a requires the
   HMAC to be computed over the fully serialized message with the auth-parameters field present but
   zero-filled, then patched in place. That means your BER encoder must produce a buffer you can
   locate a field inside and overwrite without re-encoding — a real design constraint on the codec.
   (`snmp_usm` in modern_snmp has a whole `pos_finder.rs` module for exactly this:
   [src/snmp_usm/src/pos_finder.rs](https://github.com/davedufresne/modern_snmp/blob/master/src/snmp_usm/src/pos_finder.rs).)

5. **Report PDUs are a normal, expected control-plane response**, not an error. A `Report` may arrive
   in place of a `Response` at any time and must be routed back to the session state machine
   (usually triggering re-discovery/re-sync and a transparent retry), not surfaced to the caller.

6. **SNMPWALK over v3 is stateful over many round-trips**, each of which may hit a boots/time
   rollover, an engine restart, or a `tooBig`. `async-snmp` bisects GET/GETNEXT batches on `tooBig`
   automatically ([README](https://github.com/lukeod/async-snmp/blob/main/README.md)); worth copying.

---

## Ecosystem survey

### Rust

| Project | License | SNMPv3 / USM | Async | Maintenance (checked 2026-08-05) | Source |
|---|---|---|---|---|---|
| **`async-snmp`** (lukeod) | MIT OR Apache-2.0 | **Yes, most complete found.** MD5, SHA-1, SHA-224/256/384/512; DES, 3DES-EDE, AES-128/192/256-CFB; **both** Blumenthal and Reeder key extensions; engine discovery + time sync per RFC 3414 §4/§3.2; RFC KAT tests | Yes, tokio-first | Created 2025-12-30; last push 2026-07-20; 18 releases; v0.16.0; 8 stars; **357 of ~370 commits from one author** | [repo](https://github.com/lukeod/async-snmp) |
| **`snmp2`** (roboplc) | Apache-2.0 (crates.io says MIT OR Apache-2.0) | **Yes.** MD5, SHA-1, SHA-224/256/384/512; DES, AES-128/192/256-CFB; engine boots/time handling with a 150 s window constant | Yes (`tokio` feature) — `AsyncSession` over `tokio::net::UdpSocket` | Last push 2026-07-12; v0.5.2 published 2026-07-12; 57 stars; 10 contributors | [repo](https://github.com/roboplc/snmp2) · [src/v3.rs](https://github.com/roboplc/snmp2/blob/main/src/v3.rs) |
| **`modern_snmp`** / `snmp_usm` (davedufresne) | MIT OR Apache-2.0 | **Partial.** HMAC-MD5-96, HMAC-SHA-96, timeliness verification, DES, AES(-128). **No SHA-2, no AES-192/256** | No (sync) | Last push 2024-08-23; 33 stars; 5 open issues | [repo](https://github.com/davedufresne/modern_snmp) · [snmp_usm README](https://github.com/davedufresne/modern_snmp/blob/master/src/snmp_usm/README.md) |
| **`rasn-snmp`** (librasn) | MIT OR Apache-2.0 | **Data model only.** Defines `Message`, `HeaderData`, `ScopedPdu`, `USMSecurityParameters` — **204 lines total** for v3, zero crypto. Its own doc says the encrypted PDU "MUST be decrypted by the security model in use" | N/A (codec) | rasn last push 2026-05-04; rasn-snmp 0.28.13 published 2026-04-24; 374 stars on rasn | [v3.rs](https://github.com/librasn/rasn/blob/main/standards/snmp/src/v3.rs) |
| **`csnmp`** (RavuAlHemio) | CC0-1.0 | **No — SNMP2c only** (README "Features: SNMP2c") | Yes (tokio) | Last push 2024-07-04; v0.6.0 published 2024-01-10; 7 stars | [repo](https://github.com/RavuAlHemio/csnmp) |
| **`snmp`** (hroi/rust-snmp) | MIT/Apache-2.0 (no LICENSE file detected via GitHub API) | **No — v1/v2c only.** `snmp2` is a fork of this | No (sync) | Last release 0.2.2 on **2017-04-05**; last push 2021-03-30; effectively abandoned | [repo](https://github.com/hroi/rust-snmp) |
| **`snmp-parser`** (rusticata) | NOASSERTION (dual MIT/Apache per repo convention — **unverified**) | Parser only, for IDS/dissection. No USM crypto | N/A | Last push 2026-01-19; 45 stars | [repo](https://github.com/rusticata/snmp-parser) |
| `netsnmp-sys` | — | net-snmp FFI bindings; inherits all net-snmp behaviour | No | **Unverified** — not inspected | — |

**Rust verdict:** two crates (`async-snmp`, `snmp2`) genuinely implement SNMPv3 USM and are both
async. `async-snmp` is the more complete and better-tested of the two but is **seven months old with
one substantive author** — the code quality and RFC fidelity are high (it validates against RFC 3414
Appendix A.3/A.5 and RFC 6234 HMAC vectors in
[tests/kat.rs](https://github.com/lukeod/async-snmp/blob/main/tests/kat.rs), and runs interop tests
against a containerized `snmpd`), but the field-hours behind it are not comparable to net-snmp or
gosnmp. **As a reference to read: excellent. As a dependency to bet a product on: premature.**

### Go

| Project | License | SNMPv3 / USM | Async | Maintenance | Source |
|---|---|---|---|---|---|
| **`gosnmp`** | BSD-3-Clause | **Yes, mature.** Auth: MD5, SHA-1, SHA-224/256/384/512. Priv: DES, AES-128, AES192/AES256 (Blumenthal), AES192C/AES256C (Reeder). Engine discovery via `discoveryRequired()` + `negotiateInitialSecurityParameters()` | Goroutine/blocking-IO model (not callback-async), but concurrency-friendly | Last push 2026-08-01; 1,253 stars; 71 open issues; active since 2012 | [v3_usm.go](https://github.com/gosnmp/gosnmp/blob/master/v3_usm.go) · [v3.go](https://github.com/gosnmp/gosnmp/blob/master/v3.go) · [LICENSE](https://github.com/gosnmp/gosnmp/blob/master/LICENSE) |

**Go verdict:** the best *reading* reference of all of them. It's flat, readable, ~1,100 lines for
USM, BSD-3-Clause (attribution-only), and 14 years of field bug reports are encoded in it. The
`v3_discovery_test.go`, `v3_usm_pwdcache_test.go` and `v3_credentials_test.go` files are directly
useful as a test-case checklist.

### C / C++

| Project | License | SNMPv3 / USM | Async model | Maintenance | Source |
|---|---|---|---|---|---|
| **SNMP++ / AGENT++** (Fock/Katz, agentpp.com) | Custom permissive HP-derived text in headers (SNMP++ v3.4: "Permission to use, copy, modify, distribute and/or sell … without fee", grants royalty-free license to derivatives). Third parties describe 3.6.3 as Apache-2.0 — **unverified against upstream source**; the ClausKlein `agent_pp` fork *is* tagged Apache-2.0 | **Yes, the most complete C++ USM in existence.** Auth output lengths defined for MD5, SHA-1, SHA-224/256/384/512; `PrivDES`, `PrivAES` (128/192/256), `PrivAESW3DESKeyExt` (Reeder/Cisco extension), `Priv3DES_EDE`, `PrivIDEA` | Own thread + internal event list; **not** Asio, not a completion-token model | Upstream active (SNMP++ 3.6.5 changelog); ClausKlein CMake fork last pushed 2025-10-31 | [agentpp.com](https://www.agentpp.com/) · [auth_priv.h](https://github.com/ClausKlein/snmp_pp/blob/develop/include/snmp_pp/auth_priv.h) · [usm_v3.h](https://github.com/ClausKlein/snmp_pp/blob/develop/include/snmp_pp/usm_v3.h) · [agent_pp fork](https://github.com/ClausKlein/agent_pp) |
| **net-snmp** | BSD-ish (NOASSERTION on GitHub) | Yes, complete and the de-facto reference | `snmp_sess_async_send` + `snmp_sess_select_info`/`snmp_sess_read`/`snmp_sess_timeout` — a `select(2)` fd_set model. **v3 discovery is synchronous inside send** | Very active; last push 2026-08-05; 486 stars, 352 open issues | [snmp_sess_api man page](https://netsnmp.org/man/snmp_sess_api.html) · [snmp_api.c](https://github.com/net-snmp/net-snmp/blob/master/snmplib/snmp_api.c) · [snmpusm.c](https://github.com/net-snmp/net-snmp/blob/master/snmplib/snmpusm.c) |
| **lwIP SNMP agent** | BSD (lwIP) | v3 agent support exists, gated on `LWIP_SNMP_V3_MBEDTLS` (mbedTLS backend). **Agent-side only**, embedded-oriented — not a manager/client library | lwIP's own callback model | Part of lwIP | [lwIP SNMPv2c/v3 agent docs](https://www.nongnu.org/lwip/2_1_x/group__snmp.html) |
| `choopm/snmppp` | NOASSERTION | net-snmp wrapper ("modern C++ wrapper library for net-snmp, thread-safe with v2/v3: Sessions may not be shared across threads") | inherits net-snmp | last push **2020-11-04**; 39 stars | [repo](https://github.com/choopm/snmppp) |
| Boost.Asio-based SNMP on GitHub | — | **Essentially nonexistent.** GitHub search for `snmp asio` returns two repos: `y-fedorov/snmp_test` ("net-snmp with boost.asio async", last push **2013-11-30**, 3 stars) and `Mishok7889/snmp-asio` (0 stars, no description, last push 2025-05-21). Neither is a usable base | — | — | GitHub search API, checked 2026-08-05 |

**C++ verdict:** there is a real gap here. Apart from SNMP++ (whose design predates C++11 by a
decade) and net-snmp wrappers, **no modern async C++ SNMPv3 library exists**. That is both the
justification for building this and a warning that nobody has found it easy enough to be worth doing.

---

## Detailed findings on notable candidates

### net-snmp as the baseline

The single-session API (`snmp_sess_init/open/session/send/async_send/select_info/read/timeout/close/error`)
is the correct entry point for a threaded or event-driven app; sessions from `snmp_sess_open()` must
**not** be mixed with the traditional `snmp_select_info()`/`snmp_close()` calls
([man page](https://netsnmp.org/man/snmp_sess_api.html)).

Integrating that with an Asio `io_context` means, per iteration:

1. Call `snmp_sess_select_info()` to get an `fd_set` plus a `timeval`.
2. Diff that `fd_set` against the `asio::posix::stream_descriptor` objects you currently hold —
   adding new fds and dropping vanished ones.
3. Arm an `asio::steady_timer` from the returned `timeval`.
4. On readiness, call `snmp_sess_read()` with a reconstructed `fd_set`; on timer expiry call
   `snmp_sess_timeout()`.

Vincent Bernat's practitioner writeup of doing exactly this with libevent
([blog](https://vincent.bernat.ch/en/blog/2012-snmp-event-loop)) identifies three concrete problems,
all of which I was able to corroborate against the API and source: the continuous fd add/remove
churn; the `FD_SETSIZE` 1024 ceiling (mitigated only from net-snmp 5.5 by
`snmp_select_info2()`/`snmp_read2()` with `netsnmp_large_fd_set`); and **synchronous SNMPv3
discovery**. I verified the third directly in source — see the TL;DR, point 2. That blog is a
secondary source; the source-code line references are the authority.

**Net assessment:** a net-snmp wrapper gives you correctness fast but forces a fundamentally alien
readiness-polling shape into an Asio library, adds a heavyweight dependency with a large MIB-parsing
subsystem you don't need, and still requires you to hand-roll async discovery. The very thing that
makes wrapping attractive (USM is done for you) is the thing you'd have to partly redo.

### `async-snmp` (Rust) — the best available reference implementation

Read this one if you read only one. Structural notes from the source tree:

- Clean layering that maps almost 1:1 onto what you'd want in C++:
  `src/ber/{tag,length,encode,decode}` → `src/message/v3` → `src/v3/{auth,privacy,usm,engine,process}`
  → `src/client/{builder,v3,walk,retry}` → `src/transport/{udp,udp_core,tcp}`.
- `src/v3/crypto/mod.rs` is a **pluggable provider trait** with `rustcrypto.rs` and `fips.rs`
  (aws-lc-rs) implementations. This is exactly the seam a C++ port wants for OpenSSL-vs-Botan.
- `src/v3/engine.rs` (1,555 lines) is the model to copy for engine caching, boots/time extrapolation,
  and the anti-replay rule. It defines `TIME_WINDOW = 150` and `MAX_ENGINE_TIME = 2_147_483_647` with
  RFC section citations in the doc comments.
- Correctness evidence: `tests/kat.rs` (912 lines) checks against RFC 3414 A.3.1/A.3.2 (password-to-key
  MD5/SHA-1), A.5.1/A.5.2 (key change), and RFC 6234 §8.5 HMAC vectors; `tests/interop.rs` +
  `tests/containers/snmpd/` run against a real `snmpd` in a container; there's a `fuzz/` directory
  with BER-decoder, message-parser and OID-parser targets, plus `tests/proptest.rs`.
- Honest maturity warning in its own README: "not currently stable. While pre v1.0, breaking changes
  are likely to occur frequently, no attempt will be made to maintain backward compatibility pre-1.0."

**Note on RFC 7860 test vectors:** `async-snmp` comments that for SHA-224/256/384/512 key
localization "No RFC-specified test vector exists, but we verify consistency"
([tests/kat.rs:104](https://github.com/lukeod/async-snmp/blob/main/tests/kat.rs)). I did not find
official SHA-2 password-to-key vectors in RFC 7860 either. **Plan to cross-validate SHA-2 key
localization against net-snmp's `snmpkey`/`net-snmp-create-v3-user` output rather than against a spec
vector.**

### `snmp2` (Rust) — the compactness proof

`src/v3.rs` is worth reading precisely because it is *one file*. It shows how small the whole USM
layer can be when you don't build an abstraction cathedral around it. It also has a well-designed
`AuthErrorKind` enum (`EngineBootsMismatch`, `EngineTimeMismatch`, `SignatureMismatch`,
`ReplyNotEncrypted`, `KeyExtensionRequired`, …) that is essentially a checklist of the failure modes
your C++ error enum needs. Note it supports both OpenSSL and pure-Rust crypto backends via features,
with OpenSSL winning if both are enabled.

Gap vs `async-snmp`: no 3DES, and I did not find explicit Blumenthal-vs-Reeder key-extension
selection — it has a `KeyExtensionRequired` error, suggesting the caller must supply extended key
material rather than the library deriving both variants. **Partially verified** (I read the algorithm
dispatch, not every path).

### `rasn-snmp` — tempting but not what it looks like

The one crate that might have seemed like a "free ASN.1 layer" is only a type definition module. The
v3 file is 204 lines and its `ScopedPduData` doc explicitly defers decryption to "the security model
in use". Meanwhile `rasn` itself is a full generic ASN.1 codec framework — far heavier than the
DER-subset codec SNMP actually needs (RFC 3417 §8: definite lengths, primitive forms). **A hand-written
SNMP BER codec in C++ is on the order of 800–1,500 lines and will be faster and easier to make
patch-in-place friendly than any general codec.**

### SNMP++ — the C++ fallback

`include/snmp_pp/auth_priv.h` is a genuinely useful artifact even if you don't use the library: it
enumerates every auth output length (`SNMPv3_AP_OUTPUT_LENGTH_{MD5,SHA,SHA224,SHA256,SHA384,SHA512}`)
and every privacy module including the awkward ones (`PrivAESW3DESKeyExt`, `Priv3DES_EDE`,
`PrivIDEA`). Its class hierarchy (`Auth` / `Priv` base classes with `get_id()`, `get_hash_len()`,
`get_min_key_len()`, `extend_short_key()`) is a sound design that ports directly.

Two blockers for using it as a foundation:
- **Async model mismatch.** I found no `async`/callback declarations in the public `snmp.h` grep;
  SNMP++ uses an internal event-list + thread design. Bolting Asio onto it means the same
  impedance problem as net-snmp.
- **Licence ambiguity.** The header text in the source I read (SNMP++ v3.4, ClausKlein fork) is a
  bespoke HP-derived permissive grant, *not* Apache-2.0, despite third-party packaging claims about
  3.6.3. If SNMP++ code were to be used or ported, **get the licence question resolved against the
  actual upstream 3.6.x tarball from agentpp.com** — I could not verify it from a primary source.

---

## FFI vs native-port vs from-scratch

### Option A — FFI to a Rust crate (`async-snmp` or `snmp2`)

What it would concretely involve:

- **No C ABI exists.** Neither crate exposes `#[no_mangle] extern "C"` functions or a `cxx::bridge`
  (verified by inspecting both full source trees on 2026-08-05). You would write and maintain a
  shim crate: either `cbindgen` (C header from Rust `extern "C"`) or `cxx` (bidirectional, safer,
  but constrains the types you can pass across).
- **CMake integration is the easy part.** [Corrosion](https://corrosion-rs.github.io/corrosion/introduction.html)
  imports Rust static/dylib targets into CMake and they work with `target_link_libraries()`; it
  requires CMake ≥3.22 for v0.6 (≥3.15 for v0.5). This is a solved problem.
- **The runtime mismatch is the killer, and it is not cosmetic.** Both crates are tokio-native.
  `async-snmp`'s `Cargo.toml` requires tokio with `net`, `time`, `sync`, `rt`, `macros`, `io-util`;
  `snmp2`'s `AsyncSession` holds a `tokio::net::UdpSocket` directly. Your C++ side owns an
  `io_context` and epoll. You would therefore ship **two reactors and two socket-ownership models in
  one process**, and every operation would cross: C++ initiates → shim posts onto a tokio runtime
  thread → tokio does the I/O and crypto → completion must be marshalled back onto the caller's Asio
  executor via `asio::post` and a thread-safe channel. Cancellation, timeouts and shutdown ordering
  all have to be modelled twice. Asio completion tokens (`use_awaitable`, `use_future`,
  `deferred`) would all have to be built on top of that hand-rolled bridge rather than falling out
  naturally from `async_initiate`.
- **Debuggability collapses.** A wire-level interop bug now requires reading Rust, a shim, and C++.
- **Distribution cost.** Every consumer of your library needs a Rust toolchain in their build, or you
  ship prebuilt static libs per platform.

**Verdict: not worth it.** You would be paying the full price of a foreign async runtime to avoid
writing ~2,000 lines of straightforward C++. The FFI shim itself would likely be comparable in size
and subtlety to the USM code you're trying to avoid writing.

### Option B — Port from Rust/Go into C++

Read `gosnmp/v3_usm.go` + `async-snmp/src/v3/*` + RFC 3414 side by side and write idiomatic C++.
This is *not* mechanical transliteration — Go's blocking style and Rust's ownership both dissolve
when you re-express them in an Asio composed-operation. What you actually port across is:

- the algorithm constants and truncation lengths (mechanical, error-prone, worth copying carefully),
- the discovery/time-sync state machine,
- the key-extension variant handling,
- **the interop workarounds**, which are the real value,
- the test vectors and test-case list.

Licensing: gosnmp is BSD-3-Clause (retain the copyright notice if you copy anything recognisable);
`async-snmp` and `snmp2` are MIT OR Apache-2.0 (also attribution-only). All three are compatible with
a permissively-licensed C++ library. **If you copy structure or comments verbatim, add an attribution
notice; if you only read them and reimplement, you're clear either way, but attribution costs nothing
and is the right thing to do.**

**Verdict: this is the recommended path**, in combination with Option C — "port" and "from scratch"
are not really distinct here, since the porting is at the level of algorithm and state machine, not
lines of code.

### Option C — From scratch against the RFCs only

Doable, and the RFC coverage above is complete enough to do it. But you would rediscover the AES-192/256
key-extension split, the Dell-EMC-style discovery quirks, and the `msgID`-vs-`request-id` trap the hard
way. There is no reason to refuse free knowledge.

### Option D — Wrap net-snmp

Fastest to *first working GET*, worst long-term shape. See TL;DR point 2. The one scenario where it
wins: you need SNMPv3 working in two weeks, correctness matters more than API elegance, and you are
willing to run net-snmp calls on a dedicated thread pool and `asio::post` results back — i.e. accept
that it is not really an async library, just an async-looking facade over blocking calls. That is a
legitimate *interim* strategy and could even ship as an alternate backend behind the same public API.

---

## Recommended architecture for the Boost.Asio C++ library

Five layers, each independently testable, with the crypto and transport both behind seams.

**Layer 0 — OID and value types (`snmp::oid`, `snmp::value`)**
- `oid` as a small-buffer-optimized `std::vector<uint32_t>`-alike (most OIDs are < 24 sub-identifiers);
  parse/format dotted-decimal; lexicographic comparison (needed for walk termination).
- `value` as a `std::variant` over the RFC 3416 §3 ObjectSyntax set plus the three exception markers.
- **Zero MIB dependency.** See the MIB section below.

**Layer 1 — BER codec (`snmp::ber`)**
- Definite-length, primitive-form-only encode/decode per RFC 3417 §8. No indefinite lengths, no
  BER-vs-DER ambiguity to handle.
- Encoder writes into a caller-supplied buffer and **returns byte offsets for fields that need
  in-place patching** — specifically `msgAuthenticationParameters` (RFC 3414 §3.1 step 8a) and the
  encrypted-payload octet string. This is a hard requirement flowing from the auth-over-whole-message
  rule; design it in from the start rather than retrofitting.
- Decoder is a non-owning cursor over a `std::span<const std::byte>`, returning views. **Fuzz this
  layer** — it is the entire attack surface for hostile agents.

**Layer 2 — message codec (`snmp::msg`)**
- v3 message structure per RFC 3412 §6: `msgGlobalData` (msgID, msgMaxSize, msgFlags, msgSecurityModel),
  opaque `msgSecurityParameters`, `ScopedPDU`.
- PDU types and varbind lists per RFC 3416 §3.
- v1/v2c community messages live here too, sharing the PDU/varbind code — which is why v2c comes
  nearly free once this layer exists.

**Layer 3 — USM security (`snmp::usm`)**
- `auth_protocol` and `priv_protocol` as enums; a `crypto_provider` interface with `hmac()`,
  `encrypt()`, `decrypt()` — mirroring `async-snmp`'s provider trait so OpenSSL can be swapped for
  Botan/libsodium or a FIPS module later.
- `master_key` (password-to-key, RFC 3414 A.2) → `localized_key` (`H(Ku ‖ engineID ‖ Ku)`) →
  per-protocol derived auth key and priv key. **Cache localized keys per (password, engineID,
  protocol)** — the password-to-key step hashes ~1 MiB and is deliberately slow; gosnmp has a
  password cache for exactly this reason.
- `key_extension` enum `{ none, blumenthal, reeder }`, applied when the priv protocol needs more key
  material than the hash produces. **Expose this in the public config** — do not guess.
- `secure_outgoing()` / `process_incoming()` implementing RFC 3414 §3.1 / §3.2 as pure functions over
  buffers. **Entirely synchronous and I/O-free** — this is what makes it unit-testable against RFC
  vectors.
- Constant-time HMAC comparison; zeroize keys on destruction.

**Layer 4 — session and engine state (`snmp::session`)**
- Owns an `engine_cache` keyed by peer endpoint: `{ engine_id, boots, time_at_reference,
  reference_instant, latest_received_engine_time }`, with the RFC 3414 §3.2 step 7b update rule and
  the 150-second window (§2.2.3).
- **The discovery handshake is a composed asynchronous operation**, not a blocking call — this is the
  central design point that distinguishes this library from net-snmp. Requests issued before
  discovery completes queue behind it and resume automatically; there is exactly one in-flight
  discovery per engine.
- Outstanding-request map keyed on **`msgID`** (RFC 3412 §6.2), with per-request timeout and retry.
- Report PDU handling: `usmStatsUnknownEngineIDs` → re-discover; `usmStatsNotInTimeWindows` →
  resync boots/time and retry once; `usmStatsWrongDigests` / `UnknownUserNames` → surface as a
  permanent auth error, do not retry.
- Retry policy with a bounded retry count and exponential backoff, separate from discovery retries.

**Layer 5 — transport (`snmp::transport`)**
- A single `asio::ip::udp::socket` per transport object, **shared across many targets** (as
  `async-snmp` does for fd efficiency), with an inbound demultiplexer routing datagrams to sessions
  by source endpoint + msgID.
- Interface kept narrow (`async_send_to`, `async_receive_from`) so an optional TCP transport (RFC 3430)
  or a test double slots in.

**Layer 6 — public API (`snmp::client`)**
- `async_get`, `async_get_next`, `async_get_bulk`, `async_set`, `async_walk`.
- **Every one implemented via `asio::async_initiate` / `async_compose`**, so all three completion
  token styles fall out for free from one implementation: callbacks, `asio::use_future`, and
  `asio::use_awaitable` / C++20 coroutines. Support per-operation cancellation via
  `asio::cancellation_slot` and honour `asio::associated_executor` so completions land on the
  caller's executor/strand.
- `async_walk` as a composed operation over repeated GETNEXT (v1) or GETBULK (v2c/v3), terminating on
  `endOfMibView`, on an OID lexicographically outside the requested subtree, or on a non-increasing
  OID (agent bug guard — **this check is mandatory; a buggy agent will otherwise loop you forever**).
  Offer both a "collect all" form and an incremental/streaming form so large walks don't buffer
  unboundedly.
- Session objects are **not** thread-safe individually; make them safe by construction via an
  `asio::strand`, and say so in the docs.

**Crypto choice: OpenSSL 3.x EVP.**
- HMAC: `EVP_MAC` with `"HMAC"` + digest name — MD5, SHA1, SHA224, SHA256, SHA384, SHA512 all
  available.
- AES-CFB128: `AES-128-CFB`, `AES-192-CFB`, `AES-256-CFB` are in the **default** provider (and the
  FIPS provider) — [EVP_CIPHER-AES](https://docs.openssl.org/3.0/man7/EVP_CIPHER-AES/).
- **DES-CBC is in the legacy provider, not the default one.** OpenSSL 3.x moved `DES_ECB`, `DES_CBC`,
  `DES_OFB`, `DES_CFB`, `DES_CFB1`, `DES_CFB8` and `DESX_CBC` to legacy —
  [OSSL_PROVIDER-legacy](https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-legacy/). **Consequence:
  DES privacy (RFC 3414 §8) requires the application to explicitly load the legacy provider** via
  `OSSL_PROVIDER_load(NULL, "legacy")` or an openssl.cnf change. Design decision: make DES an opt-in
  CMake feature (`SNMP_ENABLE_DES=OFF` by default) that loads the legacy provider on demand and
  fails loudly if unavailable, rather than silently degrading. DES is obsolete anyway; AES-128 is the
  sane default.
- 3DES (`DES-EDE3-CBC`) status: **verified by experiment on this machine, OpenSSL 3.6.3, 2026-08-05 —
  it IS in the default provider.** `echo test | openssl enc -des-ede3-cbc -provider default` succeeds,
  whereas `-des-cbc -provider default` fails with `inner_evp_generic_fetch:unsupported`. So single-DES
  is legacy-only but 3DES-EDE is not. (Still a draft-only USM protocol, so skipping it remains
  reasonable — but the provider question is settled.)
- Alternative backends (Botan, libsodium, mbedTLS) are worth keeping possible via the
  `crypto_provider` seam, but OpenSSL is the pragmatic default: it's everywhere, and DES/MD5 legacy
  support is exactly the sort of thing libsodium deliberately refuses to provide.

**MIB handling: out of scope, deliberately.**
GET / SET / WALK operate on numeric OIDs. RFC 3416 §3 defines `VarBind` as containing an OBJECT
IDENTIFIER — nothing in RFC 3411/3412/3414/3416/3417 requires MIB knowledge. MIB files (SMIv2,
RFC 2578) exist only to map names ↔ numbers and to attach display hints and syntax. net-snmp's own
tooling makes this explicit: `snmpget -On` prints numeric OIDs and works without loading any MIB
([net-snmp output options](https://net-snmp.sourceforge.io/tutorial/tutorial-5/commands/output-options.html)).

**Therefore: ship the core library with zero MIB parsing.** Accept and return `1.3.6.1.2.1.1.3.0`.
If symbolic names are ever wanted, add a *separate optional* `snmp-mib` target that consumes
pre-compiled MIB data — `libsmi` is the mature C library for this, and `smidump` can emit
machine-readable forms so you never write an SMI parser. This is the single largest chunk of
net-snmp you get to not carry.

---

## Effort estimate and staged plan

Sizing anchors (all measured 2026-08-05): gosnmp USM = 1,079 lines Go; `snmp2` v3 = 1,229 lines Rust;
`async-snmp` v3 subsystem ≈ 5,400 lines Rust including docs and inline tests. C++ will be somewhat
more verbose but the algorithm count is fixed.

| Stage | Deliverable | Est. LOC (impl) | Est. effort (1 experienced dev) |
|---|---|---|---|
| **0** | CMake skeleton, OID/value types, BER encode/decode + fuzz target | 1,000–1,800 | 1–1.5 weeks |
| **1** | **v2c GET / GETNEXT / GETBULK / SET / WALK** over Asio UDP with full completion-token support | 800–1,200 | 1–1.5 weeks |
| **2** | v3 message framing, USM with **auth only** (MD5 + SHA-1 + SHA-2), password-to-key, key localization, RFC 3414 A.3 KAT tests | 900–1,400 | 1.5–2 weeks |
| **3** | **Async engine discovery + time sync + Report handling** — the hard part | 500–800 | 1–2 weeks |
| **4** | Privacy: AES-128-CFB (RFC 3826) first; then AES-192/256 with both key-extension variants; DES behind an opt-in flag | 500–900 | 1–1.5 weeks |
| **5** | Interop test matrix vs `snmpd`, plus real vendor gear | — | 1–2 weeks, ongoing |
| **6** | Polish: docs, cancellation semantics, error taxonomy, packaging | — | 1 week |
| | **Total to a solid v1** | **~4,000–6,000** | **~8–11 weeks** |

**Yes, do v2c first.** Stage 1 is ~85% of the code volume of a v3 client (BER, PDUs, varbinds,
transport, walk logic, completion tokens) with none of the crypto/state-machine risk. It gets you a
working, shippable library, an end-to-end test harness, and a validated public API shape before you
touch USM. Then v3 auth-only, then privacy — matching the securityLevel ladder
(`noAuthNoPriv` → `authNoPriv` → `authPriv`, RFC 3411 §3.4.3), which is also the natural order for
incremental interop testing against `snmpd`.

**Test strategy, in priority order:**
1. RFC 3414 Appendix A.3 password-to-key vectors and A.5 key-change vectors (unit, no I/O).
2. RFC 6234 §8.5 HMAC vectors, truncated per RFC 7860's lengths.
3. Byte-for-byte round-trip of captured real SNMPv3 packets (encode-then-compare against `tcpdump`
   captures from `snmpget`/`snmpwalk`).
4. Containerized `net-snmp` `snmpd` with a user per auth/priv combination — copy
   `async-snmp`'s [`tests/containers/snmpd/`](https://github.com/lukeod/async-snmp/tree/main/tests/containers/snmpd)
   setup wholesale, it's the fastest way to a real interop matrix.
5. Fuzz the BER decoder and message parser (`async-snmp` has three such targets; the same three apply).
6. Only then: real vendor hardware, where the AES-192/256 variant question gets settled empirically.

---

## Open questions / verify by experiment

1. **SNMP++'s actual current licence.** Third-party packaging says Apache-2.0 for 3.6.3; the source
   headers I read (v3.4 via the ClausKlein fork) carry a bespoke HP-derived grant. **Unverified.**
   Resolve against the upstream agentpp.com 3.6.x tarball before using or porting any of it.

2. ~~**`DES-EDE3-CBC` in OpenSSL 3.x** — legacy provider or default?~~ **RESOLVED 2026-08-05 by
   experiment** on OpenSSL 3.6.3: `DES-EDE3-CBC` is in the **default** provider; single `DES-CBC` is
   **legacy-only** (fails `inner_evp_generic_fetch:unsupported` with `-provider default`). Also
   confirmed: the legacy provider is *not* loaded by default on this system (`openssl list -providers`
   shows only `default`), so the opt-in `OSSL_PROVIDER_load(NULL, "legacy")` design for DES stands.

3. **SHA-2 password-to-key test vectors.** RFC 7860 specifies the algorithm by reference but I found
   no official vectors, and `async-snmp` says the same. Cross-validate against net-snmp's `snmpkey`
   output instead.

4. **Which AES-192/256 key extension real target devices use.** Cisco is generally Reeder-style;
   others vary. Cannot be settled from specs — needs hardware. Design the config to make it
   selectable and default to failing loudly rather than guessing.

5. **`snmp2`'s key-extension handling** — I read the algorithm dispatch and saw a
   `KeyExtensionRequired` error but did not trace whether it derives Blumenthal keys itself or
   requires the caller to supply them. **Partially verified.**

6. **`netsnmp-sys` crate** — not inspected. **Unverified** (and irrelevant if we don't wrap net-snmp).

7. **`rusticata/snmp-parser` licence** — GitHub reports NOASSERTION; the crate is conventionally
   dual MIT/Apache but I did not read the LICENSE file. **Unverified.** (Also irrelevant — it's a
   dissector, not a client.)

8. ~~**Whether a net-snmp-backed alternate backend is worth building**~~ **RESOLVED — no.** A net-snmp
   wrapper was prototyped before this research and abandoned on hitting the limits described above; it
   is retained privately for reference only. Shipping it as a second backend would pin the public API
   to the intersection of what both backends can express. See
   [ADR-0001](../adr/0001-implement-snmpv3-natively-rather-than-wrapping-net-snmp.md).

9. **IPv6 / TCP transport (RFC 3430) scope for v1.** Not researched here; UDP/IPv4 (RFC 3417 §3.2) is
   the baseline. Asio makes IPv6 nearly free, so probably just do it.

---

## Sources

**RFCs and drafts**
- RFC 3411 — Architecture for SNMP Management Frameworks: https://datatracker.ietf.org/doc/html/rfc3411
- RFC 3412 — Message Processing and Dispatching: https://datatracker.ietf.org/doc/html/rfc3412
- RFC 3414 — User-based Security Model (USM): https://datatracker.ietf.org/doc/html/rfc3414
- RFC 3416 — Protocol Operations for SNMPv2: https://datatracker.ietf.org/doc/html/rfc3416
- RFC 3417 — Transport Mappings: https://datatracker.ietf.org/doc/html/rfc3417
- RFC 3826 — AES Cipher Algorithm in the SNMP USM: https://datatracker.ietf.org/doc/html/rfc3826
- RFC 7860 — HMAC-SHA-2 Authentication Protocols in USM: https://datatracker.ietf.org/doc/html/rfc7860
- draft-blumenthal-aes-usm-04 (AES-192/256, Blumenthal key extension §3.1.2.1): https://www.ietf.org/archive/id/draft-blumenthal-aes-usm-04.txt
- draft-reeder-snmpv3-usm-3desede-00 (3DES-EDE, Reeder key extension §2.1): https://www.ietf.org/archive/id/draft-reeder-snmpv3-usm-3desede-00.txt
- draft-reeder-snmpv3-usm-3desede datatracker status (Expired, 1999-10-07): https://datatracker.ietf.org/doc/draft-reeder-snmpv3-usm-3desede/

**Rust**
- async-snmp: https://github.com/lukeod/async-snmp
  - README: https://github.com/lukeod/async-snmp/blob/main/README.md
  - Cargo.toml: https://github.com/lukeod/async-snmp/blob/main/Cargo.toml
  - src/v3/auth.rs, src/v3/privacy.rs, src/v3/engine.rs, src/v3/usm.rs, src/v3/crypto/
  - tests/kat.rs: https://github.com/lukeod/async-snmp/blob/main/tests/kat.rs
  - docs.rs: https://docs.rs/async-snmp
- snmp2: https://github.com/roboplc/snmp2 · src/v3.rs · src/asyncsession.rs · crates.io: https://crates.io/crates/snmp2
- modern_snmp / snmp_usm: https://github.com/davedufresne/modern_snmp · https://github.com/davedufresne/modern_snmp/blob/master/src/snmp_usm/README.md
- rasn-snmp: https://github.com/librasn/rasn/blob/main/standards/snmp/src/v3.rs · https://crates.io/crates/rasn-snmp
- csnmp: https://github.com/RavuAlHemio/csnmp
- rust-snmp (hroi): https://github.com/hroi/rust-snmp
- snmp-parser (rusticata): https://github.com/rusticata/snmp-parser

**Go**
- gosnmp: https://github.com/gosnmp/gosnmp
  - v3_usm.go: https://github.com/gosnmp/gosnmp/blob/master/v3_usm.go
  - v3.go: https://github.com/gosnmp/gosnmp/blob/master/v3.go
  - LICENSE (BSD-3-Clause): https://github.com/gosnmp/gosnmp/blob/master/LICENSE

**C / C++**
- net-snmp: https://github.com/net-snmp/net-snmp
  - snmplib/snmp_api.c (snmpv3_engineID_probe, snmpv3_probe_usm_pdu_create, snmpv3_build): https://github.com/net-snmp/net-snmp/blob/master/snmplib/snmp_api.c
  - snmplib/snmpusm.c (usm_discover_engineid): https://github.com/net-snmp/net-snmp/blob/master/snmplib/snmpusm.c
  - snmp_sess_api man page: https://netsnmp.org/man/snmp_sess_api.html
  - output options / numeric OIDs: https://net-snmp.sourceforge.io/tutorial/tutorial-5/commands/output-options.html
- SNMP++ / AGENT++: https://www.agentpp.com/
  - auth_priv.h (ClausKlein fork): https://github.com/ClausKlein/snmp_pp/blob/develop/include/snmp_pp/auth_priv.h
  - usm_v3.h (licence header): https://github.com/ClausKlein/snmp_pp/blob/develop/include/snmp_pp/usm_v3.h
  - agent_pp fork (Apache-2.0, CMake): https://github.com/ClausKlein/agent_pp
- lwIP SNMPv2c/v3 agent: https://www.nongnu.org/lwip/2_1_x/group__snmp.html
- choopm/snmppp (net-snmp C++ wrapper): https://github.com/choopm/snmppp

**Crypto and build tooling**
- OpenSSL 3.0 legacy provider (DES-CBC location): https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-legacy/
- OpenSSL 3.0 EVP_CIPHER-AES (AES-*-CFB availability): https://docs.openssl.org/3.0/man7/EVP_CIPHER-AES/
- OpenSSL 3.0 migration guide: https://docs.openssl.org/3.0/man7/migration_guide/
- Corrosion (Rust↔CMake): https://corrosion-rs.github.io/corrosion/introduction.html

**Practitioner accounts (secondary — corroborated against source above)**
- Vincent Bernat, "Integration of Net-SNMP into an event loop": https://vincent.bernat.ch/en/blog/2012-snmp-event-loop
