# snmpio safety and threat checklist: network, lifetime, testing, hardening

**Date:** 2026-10-03
**Code examined:** `main` at `898df30` (`include/snmpio/Client.hpp`, `src/Client.cpp`, `src/V3Message.cpp`,
`src/Usm.cpp`, `src/BerReader.cpp`, `fuzz/`, `CMakeLists.txt`, `CMakePresets.json`,
`.github/workflows/ci.yml`). All source checks and measurements were made on 2026-10-03.

**Question being answered:** snmpio is going into a control and management system that owns one or
more `io_context`s, possibly run by several threads, and polls one to many Agents on a schedule.
No snmpio call may block the caller's threads. The planned work is: make Client destruction safe
with Outstanding Requests (a shared implementation, `~Client` performs `stop()`, and every
Outstanding Request completes with `Errc::ClientStopped`), TSan and ASan/UBSan stress tests, a
stateful Client fuzzer, and a threat model document. **What must the Command Generator withstand,
where does snmpio stand today, and what should the tests and changes be?**

**Citation rule used here:** every claim links to the source that owns it: the RFC section, the
NVD record and the upstream fix, the Asio documentation or source, the sanitizer or OpenSSL
manual, the OpenSSF guide. snmpio claims cite `file:line` at `898df30`. Two findings were
reproduced in a scratch build outside the tree, and those are marked **reproduced**. Anything
inferred from reading the code without running it is marked **by inspection**.

**Status vocabulary:** **Exposed**: snmpio is vulnerable or non-compliant today. **Handled**:
the code already deals with it (with the citation). **Partly handled**: some of it is covered and
some is not. **N/A**: does not apply to a Command Generator, or to this code.

---

## TL;DR: the findings that matter most

1. **One forged datagram can disable an Engine for the rest of the Client's life (reproduced,
   High).** In Engine Discovery's time-sync phase, `discoverEngine` accepts an *unauthenticated*
   Report and uses its boots/time as the authenticated baseline (`src/Client.cpp:619-630`). It
   never checks `replyAuthenticated` or which counter the Report names. If the forged boots value
   is higher than the real one, every later request to that Engine fails with `NotInTimeWindow`.
   Recovery is impossible, because `observeEngineTime` refuses any lower boots value
   (`src/Client.cpp:333`), and the authenticated Report path never clears the cache
   (`src/Client.cpp:647-651`). The cache is keyed by engineID, so every Target behind that Engine
   is affected. RFC 3414 allows time synchronisation only from authenticated messages: §3.2 step 7
   applies "if the securityLevel indicates an authenticated message", and §11.1 says "an SNMP
   engine should perform time synchronization using authenticated messages". The existing test
   `ClientV3.AnUnauthenticatedReportNeverResynchronisesTheCache` (`tests/TestClientV3.cpp:467`) only
   covers the lie *after* discovery.
2. **The fuzzers' assertions are compiled out (reproduced).** The fuzz build inherits
   `RelWithDebInfo`, both from `CMakeLists.txt:43-45` and from the `fuzz` preset, which adds
   `-DNDEBUG`. All 42 `assert`s in `fuzz/*.cpp` therefore do nothing, including the
   round-trip and offset oracles. Only sanitizer crashes are reported. CI's fuzz job
   (`.github/workflows/ci.yml:68-74`) configures the same way.
3. **Destroying a Client with Outstanding Requests is undefined behaviour today.** The receive loop
   and Engine Discovery are `co_spawn`ed `detached` and use `this` (`src/Client.cpp:165`, `:515`),
   and so do the `spawn` initiation (`include/snmpio/Client.hpp:244`) and `stop()`
   (`src/Client.cpp:116`). `~Client` is defaulted (`Client.hpp:68`). The header warns about this
   (`Client.hpp:57-58`). The **Lifecycle** section of CONTEXT.md and ADR-0009, both written
   alongside this research, already say that destroying the Client stops it, so the documentation
   is ahead of the code. The planned work (#31) closes this gap; §3.1 lists the Asio rules the
   design must follow.
4. **The Message ID and request-id are predictable across Targets.** One sequential counter
   (`Client.hpp:362-365`, `Client.cpp:107-111`) feeds every Target through a single long-lived
   socket. Any Agent being polled can read the counter and predict the IDs used for every other
   Target. RFC 3412 §10 says msgIDs "do not need to be unpredictable", so this is compliant. But
   snmpio accepts unauthenticated Reports that fail a request or force rediscovery (ADR-0008), and
   finding 1 turns one such Report into a persistent outage. A keyed permutation of the counter
   removes the predictability without giving up the uniqueness RFC 3414 §11.1 requires.
5. **Master Key derivation blocks the strand for 4-16 ms for every new (Credentials, Engine)
   pair (measured).** All Targets share that strand. Only Localized Keys are cached
   (`Client.cpp:461-489`), so each new Engine pays the full megabyte hash again. The 64-octet
   `EVP_DigestUpdate` chunking (`src/Usm.cpp:336-345`) is about 3.6× slower than OpenSSL's raw
   throughput.
6. **The Engine and key caches grow without bound, and unauthenticated input can add to them.**
   Neither cache evicts anything (`Client.hpp:354-361`). engineID length is not bounded at all
   (`V3Message.cpp:222-225`, versus `SIZE(5..32)` in RFC 3411). Each new engineID can cost
   another key derivation.
7. **Secrets are never cleansed, and passwords live for the Client's whole life as cache-map
   keys** (`Client.cpp:465-466`, `:479-480`). Digest comparison is constant-time
   (`V3Message.cpp:314-315`), which is good.

The prioritised list is at the end (§6).

---

## 1. Network-facing threats

### 1.1 Spoofed and off-path replies

| # | Threat and owning source | snmpio today | Recommended test or change |
|---|---|---|---|
| 1.1.1 | **A v2c Response that matches no outstanding request.** RFC 3414 §11.1: "An SNMP Command Generator Application must discard any Response Class PDU for which there is no currently outstanding Confirmed Class PDU." RFC 3416 §4.1 correlates on `request-id`. | **Handled** to the limit of v2c. A Response must match the request-id, the source endpoint and the Community (`Client.cpp:201-205`). Non-Response PDUs are dropped (`:199`). The Community travels in cleartext (RFC 3417 §12), so an attacker on the path can forge anything. | Test exists for the wrong Community (`tests/TestClient.cpp:102`). **Add** `ClientGet.IgnoresAResponseFromAnotherAddress`: the right request-id and Community, sent from a second socket. No test covers the source-address check on its own. |
| 1.1.2 | **A v3 Response that is not authentic.** RFC 3414 §3.2 steps 6-8 (digest, then timeliness, then decryption). RFC 3412 §7.2 step 10 (match on msgID). | **Handled.** Two checks run first: the msgID and source address (`Client.cpp:221-224`). The digest is then verified before anything inside the message is read (`:237-244`). Decryption runs only after authentication (`:248-257`). Timeliness, engineID and request-id checks run on Responses (`:271-279`). Unusable replies are dropped, not failed (ADR-0008). | Covered by `ClientV3.DropsAReplyEncryptedWithAnotherKey`, `KeepsRetransmittingThroughRepliesItDrops` and others. |
| 1.1.3 | **Unauthenticated (noAuthNoPriv) Reports.** RFC 3412 §10: "Internal Class PDUs delivered at the security level of noAuthNoPriv open a window of opportunity for spoofing or replay attacks." RFC 3412 §7.2 step 11(b) allows an implementation to "retain the cached information about the outstanding Request message, in anticipation of the possibility that the Internal Class PDU received might be illegitimate". RFC 3414 §11.4. | **Partly handled.** These Reports are admitted on the msgID and source-address check alone (`Client.cpp:235-236`, `:259-265`). For counters that cannot be retried, the request **fails at once** (`:641`). This was accepted in ADR-0008 ("an unauthenticated Report clearing it *fails* the request outright"). For `notInTimeWindows` and `unknownEngineIDs` it only clears the endpoint index (`:647-649`), which forces one rediscovery. | Leave ADR-0008 as it is unless 1.2 is not fixed. If the fix is deferred, the RFC 3412 §7.2 step 11(b) option is the alternative: record unauthenticated non-retryable Reports as a drop reason, and fail at the deadline rather than immediately. **That would amend ADR-0008 and is flagged as such.** |
| 1.1.4 | **An unauthenticated Report during the time-sync phase of Engine Discovery.** RFC 3414 §4 expects an authenticated Report here. Under §3.2 step 7(a) the Report is "reported with a securityLevel of authNoPriv", and time synchronisation "happens automatically as part of the procedures in section 3.2 step 7b", which only runs for authenticated messages. §2.3 and §11.1 say the same. For comparison, net-snmp records unauthenticated time with `authenticated = FALSE` and uses it only as a guess ([snmpusm.c, `LCD_TIME_SYNC_OPT` block near line 3203](https://github.com/net-snmp/net-snmp/blob/acbccfd54e02ab07452201c6fd8d1b4efc7c62fd/snmplib/snmpusm.c)). | **Exposed (High, reproduced).** `sync->authRequired = true` (`Client.cpp:611`), but an unencrypted noAuth Report is exempt from the digest (`:235-237`). `discoverEngine` then writes `boots`/`time` and `timeSynced = true` (`:626-630`) without checking `sync->replyAuthenticated` or the Report's counter. A scratch gtest using `tests/ScriptedV3Agent.hpp` answers the boots=0 sync request once with an unsigned `notInTimeWindows` Report claiming boots 900000. After that, every one of three later requests failed with `NotInTimeWindow`. The cause is `observeEngineTime` refusing lower boots (`:333`) combined with `handleReport` never clearing the authenticated path (`:651`). | **Fix:** in `discoverEngine`, adopt the pair only when `sync->replyAuthenticated` is true **and** `usmStatsCounter(sync->response) == usmStatsNotInTimeWindows`. Otherwise return `reportError(counter)`, or treat the reply as dropped. **Test:** `ClientV3.AnUnauthenticatedReportNeverSynchronisesDiscovery`, built like `tests/TestClientV3.cpp:467` but lying at `usm.boots == 0`; expect success, or a clean failure followed by recovery. Also add a safety net: if an authenticated `notInTimeWindows` Report carries a *lower* boots value than the cache, the cache was poisoned. Clear the endpoint index and rediscover instead of failing forever. |
| 1.1.5 | **Response fields beyond msgID.** RFC 3412 §7.2 step 12(b): the snmpEngineID, securityModel, securityName, securityLevel, contextEngineID and contextName of the incoming message must match the cached request. Otherwise "the incoming message is discarded". | **Partly handled.** The engineID is checked (`Client.cpp:272`), and so is the security model (`V3Message.cpp:191`). **Not checked:** securityLevel, userName, contextEngineID and contextName. So an authPriv request can be answered with an authNoPriv (cleartext) Response, and the caller is never told the data crossed the wire unencrypted. Only the key holder can produce such a reply, so integrity is unaffected; confidentiality is lost silently. | **Change:** in `deliverV3`, drop a Response whose level is not the requested level, or whose userName, contextEngineID or contextName differ from the request. Reports stay exempt under RFC 3412 §7.2 step 11. **Test:** a Scripted Agent that answers authPriv with authNoPriv; expect a drop and then `Timeout`, or a new drop reason. |
| 1.1.6 | **Where the discovery answer comes from.** RFC 3414 §4: the first phase is noAuthNoPriv by design. RFC 5343 §5: "it is RECOMMENDED to protect the discovery exchange", and engineIDs are not secret. | **Inherent, partly handled.** The engineID in an unauthenticated identity reply is taken as given (`Client.cpp:566-576`). A wrong engineID costs one key derivation and is then corrected by the real Agent's `unknownEngineIDs` Report (`:647-649`). Whoever answers the identity phase also receives an HMAC under the user's key, localised to an engineID *they* chose. That is an offline password-guessing oracle common to every USM implementation. | **Change (optional):** let a caller pin the expected engineID for a Target. net-snmp's `-e engineID` does this ([snmpcmd(1)](https://github.com/net-snmp/net-snmp/blob/acbccfd54e02ab07452201c6fd8d1b4efc7c62fd/man/snmpcmd.1.def), lines 296-300). A pinned engineID skips the unauthenticated phase entirely. Pair this with 1.6.2 (minimum password length). |

### 1.2 Message ID and request-id predictability

The RFC requirement is **uniqueness, not unpredictability**:

- RFC 3414 §11.1: an engine "MUST use different msgIDs in all such Request messages that it sends
  out during a Time Window (150 seconds)". The same applies to request-ids. "Initializing them with
  an unpredictable number … and then incrementing by one would be acceptable."
- RFC 3412 §10: "The values do not need to be unpredictable; it is sufficient that they not
  repeat."
- RFC 3412 §6.2: "No assumption should be made that the value of the msgID and the value of the
  request-id are equivalent", and "a new msgID value SHOULD be used for each retransmission".
  RFC 3416 §4.1 likewise recommends a different request-id when a request is retransmitted.

| # | Item | snmpio today | Recommended test or change |
|---|---|---|---|
| 1.2.1 | Unique within 150 s, starting from an unpredictable value | **Handled.** The start value comes from `std::random_device` (`Client.cpp:93-100`). The counter wraps at INT32_MAX (`:107-111`). | None needed for compliance. |
| 1.2.2 | **Predictability across Targets.** In a poller that talks to many Agents, every Agent sees nearly consecutive IDs. snmpio uses **one** counter for every Target and both protocols (`Client.hpp:362-365`), and one long-lived socket per address family (`Client.cpp:152-166`), so its source port never changes. Any Agent being polled (a compromised one, or one under someone else's control) can therefore predict the msgIDs used toward every other Target, and knows the port. All a forger then needs is the ability to spoof the other Target's source address. The DNS analogue makes the same point: RFC 5452 §4.3 and §9.2 require an unpredictable query ID *and* an unpredictable source port. | **Exposed (Medium).** What a forger gains: at v2c or noAuthNoPriv, forged Response data; at authenticated levels, unauthenticated Reports (1.1.3) and the persistent outage in 1.1.4. For comparison, gosnmp also starts at a random value and counts up. But its counters belong to one `GoSNMP` value, normally one per Target, and it uses a connected socket per Target ([gosnmp.go:325-338](https://github.com/gosnmp/gosnmp/blob/d2a3184e8a0fc81909036472bff67492f7fd7eb8/gosnmp.go), [marshal.go:239-249](https://github.com/gosnmp/gosnmp/blob/d2a3184e8a0fc81909036472bff67492f7fd7eb8/marshal.go)). | **Change:** generate the ID as a *keyed 31-bit permutation of the counter*. A small Feistel network keyed from `random_device` at construction works. It keeps the single-sequence property that `Client.hpp:362-365` relies on (no v2c/v3 collision in `m_pending`), stays unique for 2^31 IDs (so RFC 3414 §11.1 is still met), and makes the next ID unguessable. Per-request source ports would contradict ADR-0003's "one client owns the shared UDP socket" and are **not** recommended without an ADR. **Test:** in a unit test, the gaps between 1,000 consecutive IDs are not constant, and no ID repeats in 2^20 draws. |
| 1.2.3 | Retransmission reuses the msgID | **Exposed (Low).** The same datagram is resent (`Client.cpp:363-366`), which goes against the RFC 3412 §6.2 SHOULD. | **Change:** re-encode each attempt with a fresh ID (and, at authPriv, a fresh salt). Register every attempt's ID in `m_pending` until the request completes, so a late reply to an earlier attempt still counts. **Test:** the reply arrives just after the first retransmission, quoting the *first* msgID, and the request still completes. |
| 1.2.4 | Retransmitting a SET. RFC 3414 §11.1: delay successive state-changing messages until the previous one is acknowledged or has expired; `snmpSetSerialNo` exists to enforce ordering. | **N/A for the library**; this is caller policy. snmpio serialises nothing across SETs and retransmits a SET like any other request. | Document it in the `asyncSet` comment: a retransmitted SET can be applied twice, and callers who need ordering should use `snmpSetSerialNo`. |

### 1.3 Amplification and reflection

| # | Item | snmpio today | Recommended test or change |
|---|---|---|---|
| 1.3.1 | **SNMP as a reflector.** [CISA alert TA14-017A](https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks) lists SNMPv2 with a bandwidth amplification factor of 6.3 through GetBulk. The reflectors are *Agents*. | **N/A / handled.** The Command Generator never replies to inbound traffic. The receive loop only matches Responses and Reports to Outstanding Requests (`Client.cpp:199`, `:274`) and sends nothing back. | None. |
| 1.3.2 | **snmpio amplifying its own traffic.** | **Partly handled.** Report-driven retries are capped at two attempts (`Client.cpp:668-671`). Engine Discovery is single-flight per endpoint (ADR-0003, `Client.cpp:500-517`). But `Target::retries` is an unbounded `int` (`include/snmpio/Target.hpp:170`), and `maxRepetitions` is whatever the caller passes. | Document the caller's responsibility, or clamp `retries` to a sane maximum. |

### 1.4 Resource exhaustion

| # | Item | snmpio today | Recommended test or change |
|---|---|---|---|
| 1.4.1 | **Unbounded Engine and key caches.** RFC 3411 bounds `SnmpEngineID` at `SIZE(5..32)`. RFC 3414 §3.2 step 3 says a "zero-length, or other illegally sized msgAuthoritativeEngineID" should be treated as unknown. | **Exposed (Medium).** `m_engines`, `m_engineAt` and `m_keys` are never pruned (`Client.hpp:354-361`). The decoder deliberately does not enforce the 5..32 bound (`V3Message.cpp:222-225`), so a single engineID can be about 64 KiB. Each unauthenticated identity reply can add an entry (`Client.cpp:568-571`). Each authenticated use of a new engineID derives and stores 1-3 keys (`:583-589`, `:686-695`). | **Change** at the point where the Client admits an entry to its cache, *not* in the codec. That keeps the codec posture (CLAUDE.md: moving that line is ADR-sized). Refuse to cache an engineID outside 5..32, failing discovery with `UnknownEngineId`. Drop an `m_engines` entry, and its `m_keys` rows, once no `m_engineAt` entry points to it. Cap the number of Engines, with a least-recently-used policy. **Test:** a Scripted Agent that answers each identity phase with a fresh engineID; after N rediscoveries the cache size stays bounded. This needs a test hook exposing the cache size. |
| 1.4.2 | **The table of Outstanding Requests** | **By design.** It is bounded only by the caller's concurrency (`Client.hpp:350`). Nothing applies backpressure. | Document it, or add an optional cap on Outstanding Requests that fails new ones with a dedicated `Errc`. |
| 1.4.3 | **Walks that never end or that loop** | **Partly handled.** A repeated or decreasing OID ends the Walk (`Client.cpp:801`, ADR-0004), as does leaving the Subtree (`:796`); net-snmp's `snmpwalk` makes the same "OID not increasing" check ([apps/snmpwalk.c:342-352](https://github.com/net-snmp/net-snmp/blob/acbccfd54e02ab07452201c6fd8d1b4efc7c62fd/apps/snmpwalk.c)). But a strictly increasing endless sequence (OIDs of up to 128 sub-identifiers, each up to 2^32) never terminates. `asyncWalkCollect` buffers it without limit (`:812-823`). Callers can stop a streaming Walk themselves (`examples/walk.cpp:38-49`), but `WalkOptions` has no limit of its own (`Target.hpp:184-188`). | **Change:** add `WalkOptions::maxRows` and/or a whole-Walk deadline. Either should end with `Errc::WalkIncomplete`, so a cut-short Walk never looks complete (ADR-0004). **Test:** a Scripted Agent that answers every GETNEXT with `current.1`. |
| 1.4.4 | **Very large Responses** | **Handled.** The receive buffer is a fixed 65535 octets (`Client.cpp:20`, `:173`). Every allocation during decode is bounded by the datagram's size. `verifyAuth` copies the datagram once (`V3Message.cpp:306`). | None. |
| 1.4.5 | **CPU spent on spoofed datagrams** | **Low.** Only a datagram that matches an Outstanding Request's msgID and source costs an HMAC or decryption (`Client.cpp:221-257`). Everything else costs one decode of at most 64 KiB. | None, beyond fixing 1.2.2. |
| 1.4.6 | **Key derivation forced by attacker-chosen engineIDs** | **Exposed.** This combines 1.4.1 with §5.4: each new engineID costs 4-16 ms on the strand. | See 1.4.1 and §5.4. |

### 1.5 Malformed BER

| # | Item | snmpio today | Recommended test or change |
|---|---|---|---|
| 1.5.1 | Overflowing or oversized length fields. This class recurs: gosnmp [#552](https://github.com/gosnmp/gosnmp/issues/552) (a negative index from a 9-octet length, 2026-01) and [#250](https://github.com/gosnmp/gosnmp/issues/250); net-snmp [CVE-2018-1000116](https://nvd.nist.gov/vuln/detail/CVE-2018-1000116). | **Handled.** Long-form lengths are capped at 4 octets, and every length is checked against the bytes remaining (`src/BerReader.cpp:55-72`). Indefinite lengths, high-tag-number form and the reserved `0xFF` are refused (`:37-52`). | Fuzzed already. See §4.3: the oracles are not live. |
| 1.5.2 | Truncated headers. gosnmp [#440](https://github.com/gosnmp/gosnmp/issues/440) (a 6-octet datagram, index out of range). | **Handled.** `remaining() < 2` makes the read fail and the error is sticky (`BerReader.cpp:31-34`, `:8-13`). | Covered by `V3Message.RejectsTruncatedInput`. |
| 1.5.3 | **A digest whose length the sender chooses: [CVE-2008-0960](https://nvd.nist.gov/vuln/detail/CVE-2008-0960)** ("relies on the client to specify the HMAC length, which makes it easier for remote attackers to bypass SNMP authentication via a length value of 1"; [CERT VU#878044](https://www.kb.cert.org/vuls/id/878044)). The out-of-bounds variant is gosnmp [#433](https://github.com/gosnmp/gosnmp/issues/433). | **Handled.** The width must equal `authParamsSize(auth)` exactly (`V3Message.cpp:296-299`). The offset is bounds-checked (`:301-304`). The comparison is constant-time (`:314-315`). | **Add a regression test** named after the CVE: a message with a 1-octet `msgAuthenticationParameters` equal to the true digest's first octet, and a 0-octet one. Both must fail `verifyAuth`. No such test exists in `tests/TestV3Message.cpp` today. |
| 1.5.4 | Cleanup after a partial parse: [CVE-2015-5621](https://nvd.nist.gov/vuln/detail/CVE-2015-5621) (`snmp_pdu_parse` left a varBind behind when parsing failed; [fix f23bcd3](https://sourceforge.net/p/net-snmp/code/ci/f23bcd3ac6ddee5d0a48f9703007ccc738914791/)). A double free in USM state, [CVE-2019-20892](https://nvd.nist.gov/vuln/detail/CVE-2019-20892) ([fix 5f881d3](https://github.com/net-snmp/net-snmp/commit/5f881d3bf24599b90d67a45cae7a3eb099cd71c9)). | **Handled by construction.** Decoders return `std::optional` values that own their data, and nothing is freed by hand. | ASan in CI already covers this class. |
| 1.5.5 | Bad decryption lengths: gosnmp [#250](https://github.com/gosnmp/gosnmp/issues/250) (a slice bounds panic in `decryptPacket`) | **Handled.** `privParams` must be 8 octets, and DES ciphertext must be a non-empty multiple of the block size (`src/Usm.cpp:455-468`). Garbage after decryption maps to `DecryptionFailed` (`V3Message.cpp:282-288`). | Fuzzed by `FuzzV3Message`. |
| 1.5.6 | OID sub-identifier overflow and length | **Handled.** Sub-identifiers above 2^32-1 are rejected (`BerReader.cpp:249-252`), as are OIDs with more than 128 sub-identifiers (`:280-283`). | None. |
| 1.5.7 | Type confusion driven by the MIB: [CVE-2014-3565](https://nvd.nist.gov/vuln/detail/CVE-2014-3565) | **N/A.** snmpio parses no MIBs (ADR-0001). | None. |

### 1.6 Engine identity, boots/time, credentials

| # | Item | snmpio today | Recommended test or change |
|---|---|---|---|
| 1.6.1 | A one-sided Time Window: replays rejected, restarts adopted (RFC 3414 §3.2 step 7(b)) | **Handled** for authenticated Responses (`Client.cpp:303-322`, `:324-339`). The boots ceiling is refused on both sides (`:312`, `:330`, `:621`). Tests cover replays, restarts and clock steps (`TestClientV3.cpp:258-281`). | Fix 1.1.4: that is the one path where an *unauthenticated* pair gets in. |
| 1.6.2 | **Minimum password length.** RFC 3414 §11.2: "SNMP implementations … must ensure that passwords are at least 8 characters in length." net-snmp enforces `USM_LENGTH_P_MIN 8` ([keytools.h:17](https://github.com/net-snmp/net-snmp/blob/acbccfd54e02ab07452201c6fd8d1b4efc7c62fd/include/net-snmp/library/keytools.h), [keytools.c:146-151](https://github.com/net-snmp/net-snmp/blob/acbccfd54e02ab07452201c6fd8d1b4efc7c62fd/snmplib/keytools.c)). | **Exposed (non-compliant).** Only empty passwords are refused (`Usm.cpp:326-329`). | **Change:** add `Errc::PasswordTooShort` for passwords under 8 characters. This is a behaviour break, although net-snmp-based Agents already refuse such users. **Test** in `TestUsm.cpp`. |
| 1.6.3 | **The same password for authentication and privacy.** RFC 3414 §11.2: "very poor security practice and should be strongly discouraged". | **Examples encourage it.** `examples/walk.cpp:84-86`, `set.cpp:34-36` and `walk-collect.cpp:50-52` set both passwords from the same `argv` entry, and take passwords on the command line, which net-snmp's man page calls insecure ([snmpcmd(1)](https://github.com/net-snmp/net-snmp/blob/acbccfd54e02ab07452201c6fd8d1b4efc7c62fd/man/snmpcmd.1.def), lines 290-294). | Change the examples: separate passwords, read from the environment or stdin. |
| 1.6.4 | Salt uniqueness: RFC 3826 §3.1.2.1 and RFC 3414 §8.1.1.1 | **Handled.** A 64-bit counter starts at a random value and is shared process-wide (`Usm.cpp:101-107`). DES uses boots plus the low 32 bits (`:431-435`). | None. |
| 1.6.5 | Transport confusion. RFC 5590 §7: "an engine that has multiple transports open might be 'tricked' into sending a message through the wrong transport". | **N/A.** The socket is chosen by the destination's address family (`Client.cpp:152-155`). There is no TSM or TLS. | None. |

---

## 2. Command Generator-side CVEs and recurring bug classes

**What the record shows (checked 2026-10-03):**

- The [OSV API](https://api.osv.dev/v1/query) has **no** advisories for `github.com/gosnmp/gosnmp`,
  `pysnmp`, `org.snmp4j:snmp4j`, `easysnmp`, or the `snmp` and `snmp2` crates. An NVD keyword
  search returns zero CVEs for "gosnmp", "pysnmp" and "SNMP++", and only an *agent* CVE for
  SNMP4J (CVE-2026-39006, SNMP4J-Agent). Bugs on the Command Generator side of these libraries are
  fixed through issue trackers, not CVEs. The trackers are therefore the primary source for bug
  classes.
- The famous SNMP CVEs are mostly agent-side, but several live in the shared library code that a
  Command Generator also runs: net-snmp's `snmplib`.

| Class | Evidence (primary) | Applies to snmpio? |
|---|---|---|
| A digest truncated to a length the sender chooses | [CVE-2008-0960](https://nvd.nist.gov/vuln/detail/CVE-2008-0960) (net-snmp, UCD-SNMP, Cisco and others) | Handled; regression test missing (1.5.3). |
| Length or index overflow in the BER decoder | gosnmp [#552](https://github.com/gosnmp/gosnmp/issues/552), [#440](https://github.com/gosnmp/gosnmp/issues/440), [#433](https://github.com/gosnmp/gosnmp/issues/433), [#381](https://github.com/gosnmp/gosnmp/issues/381) ("Malformed packet leads to potential DoS"), [#311](https://github.com/gosnmp/gosnmp/issues/311); net-snmp [CVE-2018-1000116](https://nvd.nist.gov/vuln/detail/CVE-2018-1000116) (heap corruption in the UDP handler) | Handled (1.5.1, 1.5.2). |
| State left behind by a parse error, or freed twice | [CVE-2015-5621](https://nvd.nist.gov/vuln/detail/CVE-2015-5621), [CVE-2019-20892](https://nvd.nist.gov/vuln/detail/CVE-2019-20892) | Handled by RAII (1.5.4). |
| NULL dereference on unexpected input | [CVE-2018-18066](https://nvd.nist.gov/vuln/detail/CVE-2018-18066) (`snmp_oid_compare`, unauthenticated; [fix 7ffb8e2](https://sourceforge.net/p/net-snmp/code/ci/7ffb8e25a0db851953155de91f0170e9bf8c457d/)) | Handled: there are no raw pointers in the decode path. |
| Decrypt or unmarshal panics with lengths the peer controls | gosnmp [#250](https://github.com/gosnmp/gosnmp/issues/250) | Handled (1.5.5). |
| Malformed-protocol test suites | PROTOS c06-snmpv1, [CVE-2002-0012](https://nvd.nist.gov/vuln/detail/CVE-2002-0012) and [CVE-2002-0013](https://nvd.nist.gov/vuln/detail/CVE-2002-0013), [CERT CA-2002-03](http://www.cert.org/advisories/CA-2002-03.html) | The codec fuzzers do this job. The PROTOS material is v1 and agent-facing, so it is of limited use as seed corpus. |
| Walks that never end | net-snmp's `snmpwalk` "OID not increasing" check | Partly handled (1.4.3). |
| Integer overflow with GETBULK | [CVE-2008-4309](https://nvd.nist.gov/vuln/detail/CVE-2008-4309) (agent-side `netsnmp_create_subtree_cache`) | N/A as a Command Generator. But `maxRepetitions` is caller-controlled, so 1.3.2 applies. |
| Credentials leaked through files or logs | [CVE-1999-1042](https://nvd.nist.gov/vuln/detail/CVE-1999-1042) and [CVE-1999-1126](https://nvd.nist.gov/vuln/detail/CVE-1999-1126) (Cisco Resource Manager wrote community strings to world-readable files) | snmpio logs nothing (good). See §5.3 on secrets in memory and 1.6.3 on examples. |
| Trap-listener type confusion | gosnmp [#274](https://github.com/gosnmp/gosnmp/issues/274), [#347](https://github.com/gosnmp/gosnmp/issues/347) and [#350](https://github.com/gosnmp/gosnmp/issues/350) | N/A: snmpio has no Notification Receiver. |
| Data races between global and per-request state | gosnmp [#28](https://github.com/gosnmp/gosnmp/issues/28) ("race issues with global logging vars") | snmpio keeps all state on the strand (ADR-0003). The salt counter is an atomic (`Usm.cpp:102`). A TSan stress test (§4.2) is what proves this. |

---

## 3. Asio: lifetime, strands, cancellation, coroutines, several io_contexts

### 3.1 Object lifetime and safe destruction with Outstanding Requests

**What Asio guarantees** (primary sources):

- I/O object destructors cancel and do not wait. The socket destructor "Destroys the socket,
  cancelling any outstanding asynchronous operations associated with the socket as if by calling
  `cancel`" ([basic_datagram_socket::~basic_datagram_socket](https://think-async.com/Asio/asio-1.30.2/doc/asio/reference/basic_datagram_socket/_basic_datagram_socket.html)).
  The cancelled handlers still run *later*, with `operation_aborted`. Anything they reference
  must still be alive then.
- The `io_context` destructor shuts its services down, then destroys "uninvoked handler objects
  that were scheduled for deferred invocation on the io_context, or any associated strand". The
  documentation says this order exists so that `shared_ptr`-owned state is released when its
  handlers are destroyed ([io_context::~io_context](https://www.boost.org/doc/libs/latest/doc/html/boost_asio/reference/io_context/_io_context.html)).
- A completion handler is "invoked, at most once" ([P2444R0, *The Asio asynchronous
  model*](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2444r0.pdf), Kohlhoff, §3.1).
  "At most" is the honest phrasing: a handler destroyed with its `io_context` is never invoked.

**snmpio today: Exposed (planned work).** `~Client` is defaulted (`Client.hpp:68`), and the header
says the Client must outlive its operations (`:57-58`, `:77-79`). Four things use `this`
directly: the `detached` receive loop (`Client.cpp:165`), detached discovery (`:515`), the
`spawn` initiation lambda (`Client.hpp:244`), and `stop()`'s dispatched lambda
(`Client.cpp:116`). Member coroutines all capture the implicit object parameter. This is the
coroutine version of [C++ Core Guidelines CP.53](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#rcoro-reference-parameters)
("Parameters to coroutines should not be passed by reference"): `this` is a reference to state
the coroutine does not own.

**Rules the shared-implementation design must follow:**

1. **Every coroutine owns a `std::shared_ptr<Impl>` by value**, as a parameter rather than
   through `this`. That applies to `receiveLoop`, `runDiscovery`, `doRequest*`, `doWalk*` and
   `transact`. CP.53 again: anything the coroutine reads after a suspension must be owned by its
   frame.
2. **`~Client` must neither block nor wait.** It posts or dispatches `stop()` to the strand,
   capturing a `shared_ptr<Impl>`. It must not join or wait: the destructor may itself be running
   on the strand (inside a completion handler, see rule 6), or while the `io_context` is not
   running. Either way, waiting would deadlock.
3. **Break the receive loop's ownership cycle.** A loop holding `shared_ptr<Impl>` keeps `Impl`
   alive until its socket closes. `stop()` must close both sockets (it already does,
   `Client.cpp:122-123`). Check with LSan that no `Impl` leaks after `~Client` followed by
   `io.run()`.
4. **"Completes exactly once" holds only while the executor runs.** If the user stops and
   destroys the `io_context` without draining it, Asio destroys the handlers instead of invoking
   them (see the destructor quote above). CONTEXT.md's **Outstanding Request** entry should say
   so.
5. **The `io_context` must outlive the Client and its `Impl`.** If the `io_context` is destroyed
   first, its handlers (and therefore the last `shared_ptr<Impl>`) are destroyed during step 2 of
   its destructor, while services still exist. That case is safe. If instead the user's `Client`
   holds the last reference *after* the `io_context` is gone, `~Impl` destroys sockets whose
   service has been deleted. State this precondition and test it under ASan.
6. **Completions can outlive the Client's owner.** Completion handlers deliver `ClientStopped`
   *after* `~Client` has returned. A handler that captures its owner's `this` (the common pattern
   when an owner holds the Client) becomes a use-after-free in user code. This is the same
   contract Asio gives for its own I/O objects (rule 1 of this list), and it should be documented
   in `Client.hpp` in those terms.
7. **Prompt completion on stop (by inspection).** Suppose `stop()` runs while a request is
   suspended in `async_send_to`, and the send had already completed. Then `transact` arms its
   timer *after* `stop()` cancelled it (`Client.cpp:364-373`), and `ClientStopped` arrives up to
   one `Target::timeout` late. **Change:** check `m_stopped` after the send and before
   `expires_after`.

**Tests (ASan + LSan, and TSan in §4.2):**

- `~Client` while requests are waiting for a reply, between retransmissions, and queued behind a
  discovery. Every handler completes once with `ClientStopped`.
- `~Client` from *inside* its own completion handler. By default a completion runs on the strand
  when the token has no associated executor (`Client.hpp:245`).
- `~Client` before `io.run()` was ever called, then `run()`.
- `~Client`, then `io.stop()` and the `io_context` destroyed without running. No handler runs,
  and LSan reports no leaks.
- `~Client` on thread A while four threads run the `io_context` and thread B initiates requests.

### 3.2 Strands and threads

| Item | Primary source | snmpio today | Recommendation |
|---|---|---|---|
| Thread safety of objects | "It is safe to make concurrent use of distinct objects, but unsafe to make concurrent use of a single object" ([Threads and Asio](https://think-async.com/Asio/asio-1.30.2/doc/asio/overview/core/threads.html)) | **Handled.** All state lives on `m_strand` (ADR-0003). Public calls only read `m_strand` and `co_spawn` onto it (`Client.hpp:241-263`). | A TSan stress test proves it (§4.2). |
| Thread safety of cancellation signals | "When emitting a cancellation signal, the thread safety rules apply as if calling a member function on the target operation's I/O object" ([Per-Operation Cancellation](https://think-async.com/Asio/asio-1.30.2/doc/asio/overview/core/cancellation.html)) | **Handled, and fragile.** `spawn` binds the handler to an executor (`Client.hpp:249-252`). That selects the version of `co_spawn_cancellation_handler` which *dispatches* `emit()` to the coroutine's executor. The version for handlers with no associated executor would emit inline on the caller's thread ([asio impl/co_spawn.hpp:245-296](https://github.com/chriskohlhoff/asio/blob/8806a6803cde7054c3049d3666d3ec36786568c5/include/asio/impl/co_spawn.hpp)). | Keep the `bind_executor`, and say why in a comment. A refactor that drops it reintroduces the race. TSan test: emit `terminal` and `total` from a foreign thread while the request is waiting. |
| Completions running on the strand | Same thread-safety page | **Exposed by default.** With a token that has no associated executor, completions and every `BatchHandler` run on the Client's strand (`Client.hpp:61-64`, `:245`). A slow user handler stalls every Target. | Document that callers should `bind_executor` their tokens to their own executor, and that a `BatchHandler` must not block. |
| Emitting cancellation during initiation | "Cancellation requests should not be emitted during an asynchronous operation's initiating function" (same page) | **Caller's responsibility.** | Document in `Client.hpp`, next to the cancellation paragraph (`:48-55`). |

### 3.3 Per-operation cancellation (terminal, partial, total)

Asio defines **terminal** ("only safe to close or destroy the I/O object"), **partial** ("well-defined
side effects … the completion handler … indicates what these side effects were") and **total**
("no side effects that are observable through the API")
([Per-Operation Cancellation](https://think-async.com/Asio/asio-1.30.2/doc/asio/overview/core/cancellation.html)).
A coroutine created by `co_spawn` "has a cancellation state that supports
`cancellation_type::terminal` values only", and by default any `co_await` after cancellation
throws ([C++20 Coroutines Support](https://think-async.com/Asio/asio-1.30.2/doc/asio/overview/composition/cpp20_coroutines.html)).

**snmpio: handled.** Each operation turns on total cancellation and turns off throwing
(`Client.cpp:428-431`). Terminal and total have documented meanings (`Client.hpp:48-55`, ADR-0004).
Partial falls through to total's behaviour (`Client.cpp:359-361`), which is acceptable because
total is the stronger guarantee. Discovery outlives a waiter that cancels (`Client.cpp:512-516`,
ADR-0003). Existing tests cover both types (`TestClient.cpp:385-438`,
`TestClientV3.cpp:538`). **Gap:** none of these tests emits the signal from another thread (§4.2).

### 3.4 Coroutines: lifetime and exception pitfalls

| Item | Primary source | snmpio today | Recommendation |
|---|---|---|---|
| Reference parameters and `this` | [CP.53](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#rcoro-reference-parameters) | **Partly handled.** Parameters are taken by value as a rule. `receiveLoop` takes a pointer and documents why (`Client.cpp:169-172`). Member coroutines still depend on `this` (§3.1). | Covered by the planned `shared_ptr<Impl>` work. |
| Lambdas that are coroutines | [CP.51](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#rcoro-capture), and [llvm#62609](https://github.com/llvm/llvm-project/issues/62609) (ASan stack-use-after-scope with a capturing lambda coroutine) | **Handled.** The lambda in `doWalkCollect` (`Client.cpp:816-819`) is not a coroutine, and is awaited inside the frame that owns `collected`. | Keep it that way. `.clang-tidy` already enables `cppcoreguidelines-*` (`.clang-tidy:18`), which includes `cppcoreguidelines-avoid-capturing-lambda-coroutines`, so a regression fails the build. |
| **Exceptions in `detached` coroutines** | `detached`'s handler is `void operator()(Args...) {}`. It drops the `exception_ptr` (Boost.Asio `impl/detached.hpp:39-41`). | **Exposed (Low likelihood, high impact).** If `receiveLoop` throws (for example `bad_alloc` in decode), the loop dies silently. The socket stays in its slot (`Client.cpp:155`), so no new loop is ever started, and every later request times out. If `runDiscovery` throws, `m_discovering` keeps its entry and the `done` timer never fires (it expires at `time_point::max()`, `:510`). Every queued request then waits forever, which breaks "every Outstanding Request completes exactly once" (CONTEXT.md). | Give both a completion that rethrows, matching `spawn`'s policy (`Client.hpp:254-258`). Or catch inside: the receive loop re-arms, and discovery always finishes with an `ErrorCode` (a scope guard setting `finished` and cancelling `done`). **Test:** inject a throw through a test hook, and check that queued requests still complete. |
| Compiler bugs that matter with several threads | [llvm#72006](https://github.com/llvm/llvm-project/issues/72006): clang "must not insert code that accesses the coroutine frame after it suspends, because this may introduce a data race" (closed 2024-03-11) | Relevant whenever the `io_context` runs on several threads. | Run the TSan job on a current clang. |
| Compiler fragility already seen | GCC 16 false `-Wmismatched-new-delete` inside Asio's frame allocator (`Client.cpp:395-398`) | Worked around. | Nothing new. |

### 3.5 Several io_contexts

- Asio's own examples show both patterns: "an io_context-per-CPU design" and "a single io_context
  and a thread pool calling io_context::run()" ([C++11 examples, HTTP Server 2 and 3](https://think-async.com/Asio/asio-1.30.2/doc/asio/examples/cpp11_examples.html)).
- **snmpio: handled for completion routing.** A completion goes to the handler's associated
  executor, falling back to the strand only when there is none (`Client.hpp:245`). `co_spawn`
  holds outstanding work on the handler's executor until it dispatches the result
  ([impl/co_spawn.hpp](https://github.com/chriskohlhoff/asio/blob/8806a6803cde7054c3049d3666d3ec36786568c5/include/asio/impl/co_spawn.hpp),
  `handler_work`). The caller's `io_context` therefore does not run out of work while a request
  is outstanding. It must still outlive the request.
- **Cost of one Client per io_context:** each Client has its own caches (ADR-0003), so N Clients
  derive the same keys N times per Engine. If the Master Key cache recommended in §5.4 is built,
  making it process-wide behind a mutex is a cheap way to share that work. It must not end up
  holding secrets longer than §5.3 allows.
- **Test:** the Client runs on context A with two threads, completions are bound to context B with
  one thread, and requests are cancelled from context C. Under TSan, every handler runs on its
  own executor (assert with `running_in_this_thread()`).

### 3.6 Blocking work on io threads

See §5.4 for the measurement and the fix. Two other blocking points exist on the strand:
`OSSL_PROVIDER_load(nullptr, "legacy")` (a module load from disk) on the first DES use
(`Usm.cpp:119-148`), and an implicit algorithm fetch on every crypt and HMAC call. OpenSSL
recommends fetching once and reusing the result: "If you perform the same operation many times
with the same algorithm then it is recommended to use a single explicit fetch"
([ossl-guide-libcrypto-introduction(7), Performance](https://github.com/openssl/openssl/blob/master/doc/man7/ossl-guide-libcrypto-introduction.pod)).

---

## 4. Testing practice

### 4.1 ASan and UBSan with Asio and C++20 coroutines

| Item | Primary source | snmpio today | Recommendation |
|---|---|---|---|
| Baseline | [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html): use-after-return detection is "already enabled on Linux" (`detect_stack_use_after_return`, runtime mode) | **Handled.** The `asan` preset and the clang/boost CI job use `-fsanitize=address,undefined -fno-sanitize-recover=undefined` (`CMakeLists.txt:156-161`, `ci.yml:24-28`). | Keep. |
| **Asio's recycling allocators hide use-after-free** | Asio reuses handler and coroutine-frame memory from a thread-local cache unless `ASIO_DISABLE_SMALL_BLOCK_RECYCLING` ([detail/recycling_allocator.hpp:52](https://github.com/chriskohlhoff/asio/blob/8806a6803cde7054c3049d3666d3ec36786568c5/include/asio/detail/recycling_allocator.hpp)) or `ASIO_DISABLE_AWAITABLE_FRAME_RECYCLING` ([impl/awaitable.hpp:100](https://github.com/chriskohlhoff/asio/blob/8806a6803cde7054c3049d3666d3ec36786568c5/include/asio/impl/awaitable.hpp)) is defined. The Boost.Asio spellings carry a `BOOST_` prefix. Neither macro is in the Asio docs' macro table; the source is the authority here. The small-block macro is in Asio 1.38.2 but absent in the 1.28.1 and 1.30.2 tags. The frame macro is in all three. | **Exposed.** A frame or handler freed into the cache and then touched is not reported. This is exactly the bug class the destruction work could introduce. CI's Ubuntu 24.04 ships Asio 1.28.1 and Boost 1.83 ([Launchpad: asio 1.28.1-0.2](https://launchpad.net/ubuntu/noble/+source/asio)). | Define `{BOOST_}ASIO_DISABLE_AWAITABLE_FRAME_RECYCLING` and `{BOOST_}ASIO_DISABLE_SMALL_BLOCK_RECYCLING` **in sanitizer builds only**, through the `snmpio_sanitizers` interface (`CMakeLists.txt:155-162`). Note that on Asio older than 1.38.2 the small-block macro has no effect. |
| Coroutine false positives and bugs in sanitizer builds | [llvm#124612](https://github.com/llvm/llvm-project/issues/124612) (stack-use-after-scope while constructing a coroutine frame with a stateful allocator, from clang 19, closed 2025-06-03); [llvm#62609](https://github.com/llvm/llvm-project/issues/62609) | Not seen so far. | If ASan flags a frame-construction site in a clang 19 build, check #124612 before assuming a real bug. Add no blanket suppressions. |
| `_GLIBCXX_ASSERTIONS` in test builds | Current libstdc++ defines it "by default when compiling with no optimization" ([Using Macros](https://gcc.gnu.org/onlinedocs/libstdc++/manual/using_macros.html)) | On in Debug and `asan` with a recent GCC. **Off** in `RelWithDebInfo`, which includes `default` and the fuzz builds. | Define it explicitly for tests and fuzzers (§5.2). |

### 4.2 TSan

| Item | Primary source | Implication for snmpio |
|---|---|---|
| Everything must be instrumented | "ThreadSanitizer generally requires all code to be compiled with -fsanitize=thread … TSan may fail to detect races or may report false positives" ([ThreadSanitizer](https://clang.llvm.org/docs/ThreadSanitizer.html)) | Asio is header-only, so it is instrumented. OpenSSL is not: if OpenSSL internals produce reports, use `TSAN_OPTIONS=ignore_noninstrumented_modules=1`. Statically linking libc or libstdc++ is unsupported (same page). |
| Fences are not modelled | GCC `-Wtsan`: "ThreadSanitizer does not support std::atomic_thread_fence and can report false positives" ([GCC Warning Options](https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html)) | Asio uses `std::atomic_thread_fence` in `std_fenced_block`. With `SNMPIO_WERROR=ON`, GCC with TSan breaks the build. Asio switched to TSan annotations in [39278c4 "Fix thread sanitizer warnings due to atomic thread fences"](https://github.com/chriskohlhoff/asio/commit/39278c4b00), which first shipped in **asio-1-38-2** and is absent from 1.38.1 and from CI's 1.28.1. **Recommendation:** a `tsan` preset on clang. With Asio older than 1.38.2, define `{BOOST_}ASIO_DISABLE_FENCED_BLOCK` (present in 1.28.1, `detail/fenced_block.hpp:21`) in the TSan build only. |
| Memory cost | "5x plus 1Mb per each thread" (same page) | Keep the stress tests modest: 4-8 threads. |

**Stress test design** (one gtest binary, built under both TSan and ASan):

- One `io_context` run by 4 threads. A Scripted Agent with its own `io_context` on its own thread.
- 4 "caller" threads each issue v2c and v3 requests at random, mixing Walks and GETs and using
  several Credentials. 10-20 % of requests are cancelled `terminal` or `total` from the caller
  thread. To follow the Asio thread-safety rule, the signal is posted to the token's executor.
- One thread calls `stop()`, or destroys the Client, at a random point. Repeat about 200 times with
  different seeds.
- **Oracles:** every handler is invoked exactly once, counted with atomics. Results are either
  success or one of {`ClientStopped`, `operation_aborted`, `WalkIncomplete`, `Timeout`}. No handler
  runs after its executor's `io_context` is destroyed. TSan, ASan and LSan stay clean. The Agent
  side records which request-ids it saw, which shows that every request leaves on the wire at most
  `retries + 1` times.

### 4.3 Stateful and structure-aware fuzzing of the Client

**State of play (reproduced):**

- The five fuzzers cover only the codec. `snmpio_fuzzed` deliberately leaves out `Client.cpp`
  (`fuzz/CMakeLists.txt:15-23`).
- **Their 42 `assert` oracles are compiled out.** Configuring as CI does (`ci.yml:70-73`) gives
  `-O2 … -DNDEBUG … -O1` for `FuzzV3Message.cpp` (checked in a scratch build directory). The
  cause is `CMakeLists.txt:43-45`, which forces `RelWithDebInfo`, and the `fuzz` preset, which
  inherits it. **Fix:** add `-UNDEBUG` to `snmpio_fuzz_options` (`fuzz/CMakeLists.txt:8-12`), or
  turn the oracles into `if (!cond) __builtin_trap();`. Prefer the trap, because OSS-Fuzz will
  set its own flags (§4.4).

**Primary guidance:**

- A fuzz target must be deterministic: "should not use `rand()` or any other source of
  randomness". It should run at about 1000 executions per second or more, and use no disk or
  console I/O ([google/fuzzing: What makes a good fuzz target](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)).
  Splitting one input into several sub-inputs is covered in
  [split-inputs.md](https://github.com/google/fuzzing/blob/master/docs/split-inputs.md).
- Structure-aware fuzzing, using a custom mutator or protobuf
  ([structure-aware-fuzzing.md](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md)).
- A precedent for a protocol *client*: curl's fuzzers drive libcurl transfers from a TLV script,
  and from protobuf "scenarios with target-specific policies and in-process protocol peers"
  ([curl-fuzzer README](https://github.com/curl/curl-fuzzer/blob/master/README.md)).

**Proposed `FuzzClient` harness:**

1. **Seams.** A *datagram transport* the Client sends through and receives from, implemented
   in-memory by the harness. A *clock*, either through Asio's `basic_waitable_timer<Clock>` with a
   manual clock, or a timer adapter. An *ID and salt source* that replaces `std::random_device`
   (`Client.cpp:97`, `Usm.cpp:103`), so the harness is deterministic. All three seams also serve
   the unit and TSan tests.
2. **The input is an action script** read with `FuzzedDataProvider`: issue a request (kind,
   Target index, Credentials index, Security Level); deliver a datagram (bytes, or a structured
   reply); advance the clock; cancel an operation (terminal or total); `stop()`; destroy the
   Client.
3. **Structured replies get past the msgID check.** If the fuzzer had to guess msgIDs and digests,
   coverage would stop at `Client.cpp:222`. The harness therefore offers "reply to Outstanding
   Request k". It fills in the msgID, and optionally the request-id, and can **sign or encrypt the
   reply with the correct Localized Key**, which the harness knows. The fuzzer chooses the PDU
   type, the counter, engineID, boots/time, level flags and varbinds. This is the only way
   coverage reaches timeliness, Report handling, discovery and the Walk loop. It also would have
   found 1.1.4: the action "reply to sync with an unsigned Report", followed by "a correct
   authenticated Report", trips the "eventually succeeds" oracle.
4. **Oracles:** every handler is invoked exactly once; after the final `stop()` and drain,
   `m_pending` and `m_discovering` are empty; when the script ends with a compliant Agent, the
   final request succeeds; the cache sizes stay under their bounds (1.4.1); the sanitizers stay
   clean.
5. **Cost:** derivation takes several milliseconds (§5.4), which would wreck throughput. The
   harness should inject pre-derived keys through the same seam that §5.4 recommends, giving
   Credentials that already carry their Master Key.

### 4.4 OSS-Fuzz expectations

From [Ideal integration with OSS-Fuzz](https://github.com/google/oss-fuzz/blob/master/docs/advanced-topics/ideal_integration.md):

| Expectation | snmpio today | Change |
|---|---|---|
| Fuzz targets live in the project's repository | Yes, in `fuzz/` | None. |
| "There is no point in hardcoding the exact compiler flags in the build system". Build with `$CXX`, `$CXXFLAGS` and `$LIB_FUZZING_ENGINE` | Flags are hardcoded (`fuzz/CMakeLists.txt:8-12`) | Add an `SNMPIO_FUZZ_ENGINE` option, or honour `LIB_FUZZING_ENGINE` when it is set. |
| A seed corpus *per target* | One shared `fuzz/corpus/` for five targets. CI also uses one shared `.fuzz-work` directory (`ci.yml:80-84`) | Split it into `fuzz/corpus/<Target>/`. |
| A dictionary | None | Add `snmp.dict`: BER tags `\x30`, `\xa2`, `\xa8`, the usmStats prefix `\x2b\x06\x01\x06\x03\x0f\x01\x01`, and the version integers. |
| "Continuously tested on the seed corpus" with sanitizers | Corpus replay is not in `ctest` | Add a `ctest` that runs each fuzzer over its corpus with `-runs=0`. |
| Acceptance: "must have a significant user base and/or be critical to the global IT infrastructure" ([Accepting new projects](https://github.com/google/oss-fuzz/blob/master/docs/getting-started/accepting_new_projects.md)) | Probably premature | Use ClusterFuzzLite or a scheduled CI job for long campaigns until then. MSan (also on OSS-Fuzz's list) needs instrumented OpenSSL and libc++. Defer it. |

---

## 5. C++ hardening

### 5.1 The OpenSSF Compiler Options Hardening Guide

The [Compiler Options Hardening Guide for C and C++](https://github.com/ossf/wg-best-practices-os-developers/blob/main/docs/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.md)
(OpenSSF, 2026-08-20 revision) gives this TL;DR set:

```
-O2 -Wall -Wformat -Wformat=2 -Wconversion -Wimplicit-fallthrough -Werror=format-security
-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS
-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST -fstrict-flex-arrays=3
-fstack-clash-protection -fstack-protector-strong -Wl,-z,nodlopen -Wl,-z,noexecstack
-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,--no-copy-dt-needed-entries
```

It adds `-fcf-protection=full` on x86_64, and for production code
`-fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing
-ftrivial-auto-var-init=zero`. The guide also says "consider it a bug if the program cannot be
compiled with these options."

**snmpio today: Exposed in CI coverage only.** The build sets warnings
(`CMakeLists.txt:142-153`) and none of the run-time hardening. As a library, most of these flags
belong to the *consumer's* build. Adding them PUBLIC would impose them on every user.

**Recommendation:** add a CI job, or a `hardened` preset, that builds and tests with the full
TL;DR set plus the x86_64 and production rows, applied PRIVATE through an opt-in
`SNMPIO_HARDENING` option. Then say in the README that snmpio is tested with them. The warnings in
the set already overlap what the project enables.

### 5.2 `_GLIBCXX_ASSERTIONS` and the libc++ hardening modes

- libstdc++: "When defined, enables extra error checking in the form of precondition assertions,
  such as bounds checking in strings" ([Using Macros](https://gcc.gnu.org/onlinedocs/libstdc++/manual/using_macros.html)).
  The OpenSSF guide says it "does not affect the ABI" and recommends it "for most C++ applications
  in their production configuration".
- libc++: fast mode is "intended to be used in production. We recommend most projects adopt
  this". Extensive and debug modes add more checks ([libc++ Hardening Modes](https://libcxx.llvm.org/Hardening.html)).
- **snmpio: partly handled.** These are only on implicitly, at `-O0` with a recent GCC. Code that
  relies on an earlier size check would benefit, for example `makeIv` indexing `privKey[desKeySize
  + i]` (`Usm.cpp:213-217`), which is guarded by `Usm.cpp:425` and `:455`. **Recommendation:**
  `-D_GLIBCXX_ASSERTIONS` in every test, fuzz and sanitizer build. Add a clang + libc++ job with
  `_LIBCPP_HARDENING_MODE_DEBUG`. Both are ABI-neutral as the guide describes them.

### 5.3 Secret handling

**Requirements.** RFC 3414 §11.3: an implementation "MUST … to the maximum extent possible,
prohibit access to the secret(s) of each user … except as required to generate and/or validate
SNMP messages". RFC 3411 §9 item 4: "the implementation protects configuration secrets from
inadvertent disclosure". RFC 5590 §7: the cache of security parameters "SHOULD" be stored "in a
manner to protect it from unauthorized disclosure".

**Tools.** `OPENSSL_cleanse()` fills memory with zeros in a way that "is not optimised out by
compiler optimisations such as dead store elimination (as memset(3) may be)"
([OPENSSL_malloc(3)](https://github.com/openssl/openssl/blob/master/doc/man3/OPENSSL_malloc.pod)).
`CRYPTO_memcmp` "takes an amount of time dependent on len, but independent of the contents"
([CRYPTO_memcmp(3)](https://github.com/openssl/openssl/blob/master/doc/man3/CRYPTO_memcmp.pod)).
OpenSSL's secure heap serialises every allocation behind "a single read/write lock"
([OPENSSL_secure_malloc(3)](https://github.com/openssl/openssl/blob/master/doc/man3/OPENSSL_secure_malloc.pod)),
which is a poor fit for a high-rate poller.

| Where secrets live | Citation | Status |
|---|---|---|
| Digest comparison | `V3Message.cpp:314-315` (`CRYPTO_memcmp`) | **Handled.** |
| Passwords, copied by value into each coroutine frame | `Client.hpp:158-205` (`Credentials` by value) → `doRequestV3` → `ensureEngine` → `runDiscovery` → `discoverEngine` (`Client.cpp:491`, `:534`, `:546`) | **Exposed.** Several plaintext copies per request are freed without being cleansed. Asio's frame recycling (§4.1) keeps the freed memory in a thread-local cache. |
| **Passwords used as cache-map keys for the Client's lifetime** | `Client.cpp:465-466`, `:479-480`; `Client.hpp:357-361` | **Exposed.** |
| A Localized Key copied into each Pending | `Client.hpp:276-277`; `Client.cpp:614-615`, `:724-725` | **Exposed.** Not cleansed when freed. |
| Master Key temporaries; the password's 64-octet chunk on the stack; the digest output array | `Usm.cpp:374`, `:388`, `:334`, `:70` | **Exposed.** |
| Passwords in the examples | `examples/*.cpp` take them from `argv` | Document it (1.6.3). |

**Recommendations, in order of value:**

1. **Stop keeping passwords at all after first use.** Derive the Master Key once (§5.4) and drop
   the password. The key cache then becomes (engineID, Master Key, protocol), which is what
   ADR-0003's consequences literally say ("the localized-key cache on (master key, engineID)").
   The comment at `Client.hpp:357-358` explains that passwords were used so that a lookup never
   has to derive anything. Credentials that arrive carrying a pre-derived Master Key remove that
   cost. net-snmp offers the same thing as `-3m`/`-3k` ([snmpcmd(1)](https://github.com/net-snmp/net-snmp/blob/acbccfd54e02ab07452201c6fd8d1b4efc7c62fd/man/snmpcmd.1.def),
   lines 267-279). **This changes a public type and the substance of an ADR-0003 consequence. It
   needs an ADR.**
2. **Add a `SecretOctets` type**: a `std::vector<std::byte>` whose allocator calls
   `OPENSSL_cleanse` before deallocating. Use it for every key and every Pending copy. Because the
   allocator cleanses, the buffer left behind when a vector grows and reallocates is wiped too,
   which a cleanse in a destructor would miss.
3. Call `OPENSSL_cleanse` on the stack buffers in `passwordToKey` and `finish`, and on Master Key
   temporaries.
4. Be honest in the threat model: `std::string` small-string storage and moved-from strings cannot
   be reliably cleansed. Zeroization is best-effort hygiene against core dumps and memory
   disclosure. It is not a guarantee. `-ftrivial-auto-var-init=zero` initialises stack memory; it
   does not wipe it on exit.

### 5.4 Blocking work on io threads: Master Key derivation

**Measured** on 2026-10-03 (AMD Ryzen AI 9 HX 370, OpenSSL 3.6.5, `build/default`, which is
RelWithDebInfo). Each row is the time for `localizedAuthKey`, plus `localizedPrivKey` where a
privacy protocol is shown, for **one new Engine**. That is the work done on the strand the first
time a pair of Credentials meets an Engine:

| Credentials | Strand time per new Engine |
|---|---|
| SHA-1, authNoPriv | 3.7 ms |
| SHA-256, authNoPriv | 4.0 ms |
| SHA-512, authNoPriv | 5.7 ms |
| MD5, authNoPriv | 6.1 ms |
| SHA-256 + AES-128 | 7.9 ms |
| SHA-1 + AES-256C (Reeder) | 11.1 ms |
| MD5 + AES-256C (Reeder) | 16.1 ms |

`openssl speed -bytes 1048576` measures SHA-256 at 972 MB/s on the same machine, so one MiB
should hash in about 1.08 ms. The 4.0 ms observed is roughly **3.6×** that. The cause is the
16,384 calls to `EVP_DigestUpdate` with 64-octet chunks (`Usm.cpp:336-345`).

At first contact with 1,000 Engines under SHA-256 + AES-128, the strand is blocked for about
**8 s**, serialised, and every other Target's replies wait behind it. Today the cost is paid
again for every new Engine, because only Localized Keys are cached (`Client.cpp:461-489`), even
though RFC 3414 §2.6 makes localisation a single short hash over the Master Key.

**Recommendations:**

1. **Cache the Master Key per (hash, password)**, or accept it pre-derived (§5.3 item 1). The
   per-Engine cost then falls to one short hash, measured in microseconds. The exception is
   Reeder, whose key extension runs password-to-key again over the Localized Key
   (`Usm.cpp:399-405`) and so costs one MiB hash per Engine regardless.
2. **Feed `EVP_DigestUpdate` larger blocks**, for example by filling a 4 KiB buffer with the
   repeated password. Use the RFC 3414 Appendix A.3 vectors already pinned in `TestUsm.cpp` to
   show the output is unchanged.
3. **Move whatever derivation remains off the strand.** `co_await` a `post` to a dedicated
   `asio::thread_pool`, or to an executor the caller supplies, keyed single-flight so that
   concurrent requests for the same key wait on one derivation. Resume on the strand to write the
   cache. This is what the "never block the caller's threads" requirement asks for.
4. **Test:** a latency assertion. While an Engine Discovery for Target B is deriving its keys,
   a v2c request to a responsive Target A must complete within about 2 ms of A replying. Run it
   under TSan once the derivation is offloaded.

---

## 6. Prioritised list

**P0: fix before the planned work lands, or as part of it**

1. **Time-sync poisoning (1.1.4).** Require `replyAuthenticated` and the `notInTimeWindows`
   counter before adopting the pair in `discoverEngine` (`Client.cpp:619-630`). Add the test
   `ClientV3.AnUnauthenticatedReportNeverSynchronisesDiscovery`. Add a recovery path for an
   authenticated `notInTimeWindows` Report whose boots value is lower than the cache's.
   *Added 2026-10-03, after this snapshot: fixed by #25, with the test named
   `ClientV3.AnUnauthenticatedReportNeverSetsTheDiscoveredClock`, and with one deliberate
   relaxation: the `notInTimeWindows` counter is not required. Any signed reply is accepted. An
   Engine that has just booted finds boots and time zero timely and answers with a Response, and
   the `simulator` image CI pins answers with a signed `unknownEngineIDs` Report. RFC 3414 §3.2
   step 7(b) learns the pair from any authenticated message newer than the local notion, and at
   discovery there is no local notion yet, so the signature is the whole bar. The recovery path
   is #40.*
   *Added 2026-10-03: the recovery path is fixed by #40, with the test
   `ClientV3.RediscoversAnEngineWhoseBootsWentBackwards`. It clears the Engine's `timeSynced`
   rather than the endpoint index the row above suggests: an Engine already marked synced skips
   the time-sync phase on rediscovery, so clearing the index alone would retry with the same
   stale pair. `ClientV3.AForcedResyncHappensAtMostOncePerRequest` pins the one-resync bound.*
2. **Turn the fuzz oracles back on (4.3).** Use `-UNDEBUG` or `__builtin_trap()` in the fuzzers.
   Re-run the existing corpus: an oracle that has been dead may have been hiding failures.
3. **Safe `~Client` (3.1)**, following the seven rules there. In the same change, fix the late
   `ClientStopped` after a completed send (3.1 rule 7). Write the ASan and LSan destruction tests
   in 3.1 *before* the TSan stress test.
4. **Exceptions in `detached` coroutines (3.4).** If the receive loop or discovery dies, the
   Client fails silently and Outstanding Requests are stranded. This belongs in the same change as
   item 3, because it touches the same `co_spawn` calls.

**P1: security and operability for a long-running poller**

5. **Unpredictable Message IDs (1.2.2)** using a keyed 31-bit permutation, plus a fresh ID on
   each retransmission (1.2.3).
6. **Move derivation off the strand (5.4):** a Master Key cache, larger digest chunks, and a
   thread-pool offload with single-flight.
7. **Bounded caches (1.4.1):** an engineID 5..32 admission check in the Client (not in the
   codec), eviction of unreferenced Engines and their keys, and a cap.
8. **Full RFC 3412 §7.2 step 12 matching (1.1.5):** securityLevel, userName, contextEngineID and
   contextName.
9. **A TSan preset and the stress test (4.2)**, using clang. Use Asio ≥ 1.38.2, or define
   `ASIO_DISABLE_FENCED_BLOCK` in the TSan build. Define the Asio recycling-disable macros in
   every sanitizer build (4.1).

**P2: hygiene, compliance and longer-term**

10. **The stateful `FuzzClient` (4.3)**, with transport, clock and RNG seams and a harness that
    signs replies.
11. **Secret handling (5.3):** a `SecretOctets` type with cleanse-on-free and cleansed stack
    buffers. Then an ADR to stop keying caches on passwords: Credentials that carry a Master Key,
    as ADR-0003's consequence wording already describes.
12. **A minimum password length of 8 (1.6.2)**, and examples with distinct passwords that do not
    come from `argv` (1.6.3).
13. **`WalkOptions::maxRows` and a Walk deadline (1.4.3).**
14. **A hardened CI job (5.1)** with the OpenSSF TL;DR flags, plus `_GLIBCXX_ASSERTIONS` in all
    test and fuzz builds and a libc++ debug-mode job (5.2).
15. **OSS-Fuzz readiness (4.4):** honour `LIB_FUZZING_ENGINE`, a corpus per target, a
    dictionary, and corpus replay in `ctest`. ClusterFuzzLite in the meantime.
16. **Missing regression tests:** a 1-octet digest (CVE-2008-0960, 1.5.3), and a v2c Response
    from the wrong source address (1.1.1).
17. **Optional engineID pinning per Target (1.1.6).**
18. **Documentation:** completion handlers outlive `~Client` (3.1 rule 6); bind tokens to your
    own executor (3.2); exactly-once holds only while the executor runs (3.1 rule 4); SET
    retransmission (1.2.4).

**Changes that touch an ADR, flagged as CLAUDE.md asks:**

- Item 11 rewrites how the key cache is keyed, which is ADR-0003's consequence. It would bring
  the code *closer* to that ADR's wording, but it changes `Credentials`.
- 1.1.3's alternative (failing on an unauthenticated non-retryable Report only at the deadline)
  would amend ADR-0008. It is **not** recommended if item 1 lands.
- Per-request source ports (1.2.2) would contradict ADR-0003's single shared socket. **Not
  recommended.**
- Enforcing engineID length *in the codec* would move the codec posture, which is ADR-sized. Item
  7 deliberately enforces it at the Client instead.

---

## Sources

**RFCs**
- RFC 3411, Architecture (§9 Security Considerations; `SnmpEngineID SIZE(5..32)`): https://www.rfc-editor.org/rfc/rfc3411
- RFC 3412, Message Processing and Dispatching (§6.2 msgID; §7.2 steps 10-12; §10): https://www.rfc-editor.org/rfc/rfc3412
- RFC 3414, USM (§2.3, §3.2 steps 3 and 7, §4, §8.1.1.1, §11.1-11.4): https://www.rfc-editor.org/rfc/rfc3414
- RFC 3416, Protocol Operations (§4.1 request-id; §7): https://www.rfc-editor.org/rfc/rfc3416
- RFC 3417, Transport Mappings (§12): https://www.rfc-editor.org/rfc/rfc3417
- RFC 3826, AES for USM (§3.1.2.1 salt): https://www.rfc-editor.org/rfc/rfc3826
- RFC 5343, Context EngineID Discovery (§5): https://www.rfc-editor.org/rfc/rfc5343
- RFC 5590, Transport Subsystem (§7): https://www.rfc-editor.org/rfc/rfc5590
- RFC 5452, DNS forgery resilience (§4.3, §9.2), as the ID and port analogue: https://www.rfc-editor.org/rfc/rfc5452

**CVEs, advisories and upstream fixes**
- CVE-2008-0960: https://nvd.nist.gov/vuln/detail/CVE-2008-0960 · CERT VU#878044: https://www.kb.cert.org/vuls/id/878044
- CVE-2015-5621: https://nvd.nist.gov/vuln/detail/CVE-2015-5621 · fix: https://sourceforge.net/p/net-snmp/code/ci/f23bcd3ac6ddee5d0a48f9703007ccc738914791/
- CVE-2018-18066: https://nvd.nist.gov/vuln/detail/CVE-2018-18066 · fix: https://sourceforge.net/p/net-snmp/code/ci/7ffb8e25a0db851953155de91f0170e9bf8c457d/
- CVE-2019-20892: https://nvd.nist.gov/vuln/detail/CVE-2019-20892 · fix: https://github.com/net-snmp/net-snmp/commit/5f881d3bf24599b90d67a45cae7a3eb099cd71c9
- CVE-2018-1000116: https://nvd.nist.gov/vuln/detail/CVE-2018-1000116 · https://sourceforge.net/p/net-snmp/bugs/2821/
- CVE-2014-3565: https://nvd.nist.gov/vuln/detail/CVE-2014-3565
- CVE-2008-4309: https://nvd.nist.gov/vuln/detail/CVE-2008-4309
- CVE-2002-0012 / CVE-2002-0013 (PROTOS c06): https://nvd.nist.gov/vuln/detail/CVE-2002-0012 · https://nvd.nist.gov/vuln/detail/CVE-2002-0013
- CVE-1999-1042 / CVE-1999-1126: https://nvd.nist.gov/vuln/detail/CVE-1999-1042 · https://nvd.nist.gov/vuln/detail/CVE-1999-1126
- CISA TA14-017A, UDP-based amplification: https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks
- OSV query API (no records for gosnmp, pysnmp, SNMP4J): https://api.osv.dev/v1/query
- gosnmp issues: #552, #440, #433, #381, #350, #311, #274, #347, #250, #28 at https://github.com/gosnmp/gosnmp/issues

**Reference implementations (pinned commits)**
- net-snmp `acbccfd`: snmplib/snmpusm.c, snmplib/keytools.c, include/net-snmp/library/keytools.h, apps/snmpwalk.c, man/snmpcmd.1.def: https://github.com/net-snmp/net-snmp/tree/acbccfd54e02ab07452201c6fd8d1b4efc7c62fd
- gosnmp `d2a3184`: gosnmp.go, marshal.go: https://github.com/gosnmp/gosnmp/tree/d2a3184e8a0fc81909036472bff67492f7fd7eb8

**Asio (Kohlhoff)**
- P2444R0, The Asio asynchronous model: https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2444r0.pdf
- Per-Operation Cancellation: https://think-async.com/Asio/asio-1.30.2/doc/asio/overview/core/cancellation.html
- Threads and Asio: https://think-async.com/Asio/asio-1.30.2/doc/asio/overview/core/threads.html
- C++20 Coroutines Support: https://think-async.com/Asio/asio-1.30.2/doc/asio/overview/composition/cpp20_coroutines.html
- basic_datagram_socket destructor: https://think-async.com/Asio/asio-1.30.2/doc/asio/reference/basic_datagram_socket/_basic_datagram_socket.html
- io_context destructor: https://www.boost.org/doc/libs/latest/doc/html/boost_asio/reference/io_context/_io_context.html
- C++11 examples (io_context per CPU; thread pool): https://think-async.com/Asio/asio-1.30.2/doc/asio/examples/cpp11_examples.html
- Source at `8806a68`: impl/co_spawn.hpp, detail/recycling_allocator.hpp, impl/awaitable.hpp: https://github.com/chriskohlhoff/asio/tree/8806a6803cde7054c3049d3666d3ec36786568c5/include/asio
- TSan fence fix, commit 39278c4 (first in asio-1-38-2): https://github.com/chriskohlhoff/asio/commit/39278c4b00
- Ubuntu 24.04 asio package (1.28.1): https://launchpad.net/ubuntu/noble/+source/asio

**C++ guidelines and compiler and sanitizer documentation**
- C++ Core Guidelines CP.51, CP.53: https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#rcoro-capture
- Clang AddressSanitizer: https://clang.llvm.org/docs/AddressSanitizer.html
- Clang ThreadSanitizer: https://clang.llvm.org/docs/ThreadSanitizer.html
- GCC Warning Options (`-Wtsan`): https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
- LLVM issues #124612, #72006, #62609: https://github.com/llvm/llvm-project/issues/124612 · https://github.com/llvm/llvm-project/issues/72006 · https://github.com/llvm/llvm-project/issues/62609
- libstdc++ macros: https://gcc.gnu.org/onlinedocs/libstdc++/manual/using_macros.html
- libc++ Hardening Modes: https://libcxx.llvm.org/Hardening.html
- OpenSSF Compiler Options Hardening Guide for C and C++: https://github.com/ossf/wg-best-practices-os-developers/blob/main/docs/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.md

**OpenSSL**
- OPENSSL_malloc(3) (`OPENSSL_cleanse`): https://github.com/openssl/openssl/blob/master/doc/man3/OPENSSL_malloc.pod
- CRYPTO_memcmp(3): https://github.com/openssl/openssl/blob/master/doc/man3/CRYPTO_memcmp.pod
- OPENSSL_secure_malloc(3): https://github.com/openssl/openssl/blob/master/doc/man3/OPENSSL_secure_malloc.pod
- ossl-guide-libcrypto-introduction(7), Performance: https://github.com/openssl/openssl/blob/master/doc/man7/ossl-guide-libcrypto-introduction.pod

**Fuzzing**
- OSS-Fuzz ideal integration: https://github.com/google/oss-fuzz/blob/master/docs/advanced-topics/ideal_integration.md
- OSS-Fuzz accepting new projects: https://github.com/google/oss-fuzz/blob/master/docs/getting-started/accepting_new_projects.md
- What makes a good fuzz target: https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md
- Structure-aware fuzzing: https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md
- Splitting inputs: https://github.com/google/fuzzing/blob/master/docs/split-inputs.md
- curl-fuzzer: https://github.com/curl/curl-fuzzer
