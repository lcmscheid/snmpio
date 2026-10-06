# Threat model

What snmpio defends against, what it does not, and the invariants it keeps. Each invariant names
the test or fuzzer that holds it, or says **not yet held** and names the stage 6 ticket that will.
This page is what "snmpio is safe to depend on" is checked against: an invariant without a test is
a claim, and a change that breaks one should fail the test this page names.

The evidence is [`docs/research/snmpio-safety-threats.md`](research/snmpio-safety-threats.md),
cited below as "research §n". It gives the RFC section, CVE or upstream source behind every item,
and says where the code stood when it was written. The plan for the gaps is the stage 6 spec, #26.

## What is being protected

snmpio is a Command Generator embedded in a control and management system. That system owns the
`io_context`s, runs them on a thread pool, adds and removes Targets at runtime, and polls them from
wherever it happens to be. In priority order, it relies on snmpio for:

1. **Its own process.** No datagram, from anyone, may crash it, corrupt its memory, or block its
   threads.
2. **The truth of what it is told.** A Response it acts on came from the Target it asked, at the
   Security Level it asked for.
3. **Its availability.** Every Outstanding Request completes, exactly once, and within bounds the
   caller sets. One Target's misbehaviour cannot take the others down with it.
4. **Its secrets.** Passwords, Master Keys and Localized Keys leak through neither the wire nor
   memory snmpio has finished with.

## The attacker

**Anyone who can send a UDP datagram to the Client's source port.** The Client owns the socket its
Targets share (ADR-0003). In the code that is one long-lived socket per address family, so the port
does not change for the Client's life, and every Target polled through the Client sees it. The
attacker comes in three positions:

- **Off-path.** Can send datagrams with a forged source address, and cannot see the Client's
  traffic. To get a forgery past the first check, they must guess an outstanding Message ID (v3) or
  `request-id` (v2c) and know which Target it was sent to.
- **On-path.** Can read, drop, delay, reorder and replay the Client's traffic, and inject their
  own.
- **A polled Agent.** Any Agent the Client polls, whether compromised or run by someone else. It
  sees every request the Client sends to it, and so the Client's Message IDs, and it controls its
  own replies completely. Towards every *other* Target it is an off-path attacker who has been
  told the source port and a stream of recent Message IDs.

**Out of scope:**

- An attacker who can execute code in the process or read its memory. See [Secrets](#secrets) for
  what wiping does and does not change.
- Flooding the link or the socket's receive buffer. Genuine replies are then lost, and their
  requests time out. That is a correct outcome; nothing in a Command Generator can prevent it.
- An authenticated Agent lying about its own data. Authentication proves who sent a reply, not
  whether it is true.
- How many requests are outstanding at once. Nothing applies backpressure: the table of
  Outstanding Requests grows with the caller's concurrency, by design, and bounding it is the
  caller's job (research §1.4.2).
- A retransmitted SET being applied twice. Ordering SETs is the caller's policy, through
  `snmpSetSerialNo` (RFC 3414 §11.1; research §1.2.4). That, and the other rules only the caller
  can keep, such as binding completion tokens to their own executor, are to be documented: #48.
- OSS-Fuzz integration (research §4.4), which the stage 6 spec leaves out.
- Callers breaking the API's preconditions, such as destroying the `io_context` while it still
  has work for a Client.

## What the attacker can reach

Every datagram that reaches the socket is decoded: at most 65535 octets, by a decoder that is
fuzzed under ASan and UBSan (research §1.5). The Client sends nothing in reply to anything it
receives, so it cannot be used as a reflector (research §1.3.1). After decoding, a datagram is
matched against an Outstanding Request, and the bar it must clear depends on the version and the
Security Level:

| | **Off-path** attacker | **On-path** attacker |
|---|---|---|
| **v2c** | Guess the `request-id`, spoof the Target's address, and know the Community; then forge any Response. | Everything. The Community is in cleartext, so they can read it and then forge any Response. |
| **v3 `noAuthNoPriv`** | Guess the Message ID and spoof the Target's address; then forge any Response. | Everything. |
| **v3 `authNoPriv`** | Guess the Message ID and spoof the Target's address. Then only the two unauthenticated replies R6 lists get through: an unsigned Report, and the answer to Engine Discovery's identity phase (see below). Either can fail requests before their deadline. Neither can forge a Response or set the Engine's clock. | Reads every Varbind. Can drop or delay replies, and can replay them while the Message ID is still outstanding and the Time Window allows. Cannot forge. A captured digest is an offline password-guessing oracle. |
| **v3 `authPriv`** | As `authNoPriv`. | Sees the header fields only: the Message ID, the engineID, the user name, boots and time, and sizes. Cannot read the Scoped PDU. Otherwise as `authNoPriv`. |

Two further surfaces are inherent to USM, and no Command Generator closes them:

- **Engine Discovery's identity phase is unauthenticated by design** (RFC 3414 §4). Whoever
  answers it first chooses the engineID that the Client caches. At `noAuthNoPriv` the real Engine's
  `unknownEngineIDs` Report to the first request forces one more Engine Discovery, which corrects
  it. At `authNoPriv` and `authPriv` nothing corrects it within that Engine Discovery. The
  time-sync phase goes out under the wrong engineID, and the real Engine's unsigned
  `unknownEngineIDs` Report then ends that Engine Discovery with `UnknownEngineId`, failing every
  request queued behind it before its deadline (R6). The next request rediscovers. Each wrong
  engineID also costs a key derivation (B7) and a cache entry (B2). No test pins this path yet.

  Whoever answers the identity phase also receives a digest under the user's key, localised to an
  engineID *they* chose, which is an offline password-guessing oracle. A password's strength is the
  only defence there (research §1.1.6). Pinning an engineID per Target would remove the phase; it
  is out of scope for stage 6.
- **Credentials shared between Agents are one secret.** Key localisation means an Agent that holds
  only its Localized Key cannot impersonate another Engine. An Agent that was configured with the
  password can derive every other Engine's key for that user.

### What v2c can promise

Nothing against an on-path attacker. SNMPv2c has no authentication and no privacy: the Community is
a cleartext token, and anyone who can see one request can read it and forge every later reply. Every
v2c invariant below holds only against an **off-path** attacker, and those that rest on the
Community (R1) only against one who has never seen it. That is why each of them is narrower than its
v3 counterpart, and why none of them claims integrity or confidentiality. Use v3 at `authPriv`
wherever the network is not trusted.

## Invariants

The status words are this page's own; the research note grades the code as Exposed, Partly handled
or Handled instead. **Held** means a test or fuzzer named in the row fails if the invariant breaks.
**Partly held** names what is tested and the ticket for the rest. **Not yet held** names the ticket,
and says when the code breaks the invariant today. Tests are named as gtest prints them
(`Suite.Name`) and fuzzers by their harness's name. Since #28, CI runs every test under both
ASan+UBSan and TSan, and runs the interop suite against `snmpd` under ASan+UBSan. snmpio's own
libraries, tests and fuzzers build with the standard library's assertions on; libc++'s mode is set
too, but no CI cell compiles against libc++ yet (#44). The wider OpenSSF hardening flags are not yet
applied: #46.

Each row's letter is its section's: **L**ifecycle, **C**oncurrency, **R**eplies, **E**ngine state,
**W**ire confidentiality, resource **B**ounds, the codec (**K**, since C is taken) and **S**ecrets.
#30 is the stateful Client fuzzer. Where a row calls something "#30's oracle", that row's rule is
what the fuzzer will check every completion against.

### Lifecycle

| # | Invariant | Status | Held by |
|---|---|---|---|
| L1 | Every Outstanding Request completes **exactly once**, whatever ends it: a reply, its deadline, a cancellation or Stopping. | **Partly held.** Each ending is tested for the code it produces. Nothing yet counts the invocations or checks the executor they run on. | `ClientGet.RetransmitsAndThenTimesOut`, `ClientV3.TimesOutAgainstASilentTarget`, `Client.FailsOutstandingRequestsWhenItStops`, `ClientV3.StoppingDuringDiscoveryFailsTheQueuedRequests`. The counting oracle and the disruption matrix: #29. Under concurrency: #32. Against hostile replies: #30. |
| L2 | A cancellation keeps `Client.hpp`'s rule. **Terminal** completes at once with `operation_aborted`. **Total** completes with `operation_aborted` unless a reply was already on its way, which it then delivers. A cancelled Walk is `WalkIncomplete`, never `Timeout`, and a total cancellation keeps the batch in hand (ADR-0004). | **Partly held.** Pinned one wait at a time; the full set of waits and disruptions is #29. | `ClientCancel.ATerminalSignalAbortsARequestWaitingForAReply`, `ClientCancel.ATotalSignalAgainstASilentTargetIsAbortedNotTimedOut`, `ClientCancel.ATotalSignalStillTakesTheReplyAlreadyOnItsWay`, `ClientWalk.ATerminalCancellationDropsTheWalkImmediately`, `ClientWalk.ATotalCancellationFinishesTheBatchAndKeepsWhatItGot`, `ClientWalk.ACancelledWalkAgainstASilentTargetIsIncompleteNotTimedOut`, `ClientV3/QueuedBehindDiscovery.IsAbortedAndLeavesTheDiscoveryRunning/*` |
| L3 | Cancelling a request never cancels the Engine Discovery that other requests are queued behind (ADR-0003). | **Held.** | `ClientV3.CancellingTheRequestThatStartedDiscoveryLeavesTheQueueIntact`, `ClientV3/QueuedBehindDiscovery.IsAbortedAndLeavesTheDiscoveryRunning/*` |
| L4 | **Destroying a Client stops it** (ADR-0009). Its Outstanding Requests complete with `ClientStopped` on the caller's executor, and nothing touches freed memory. That holds when it is destroyed from any thread, including from inside one of its own completion handlers: a commitment #31 adds, which ADR-0009 does not state. | **Not yet held: #31.** Broken today: destroying a Client with an Outstanding Request is a use-after-free (research §3.1). | — |
| L5 | `stop()` is idempotent and can be combined with destruction, in either order. A request initiated after Stopping completes with `ClientStopped`. A request that has already completed never reports `ClientStopped` afterwards. | **Not yet held: #31.** | — |
| L6 | A streaming Walk's batch handler is never called once Stopping has begun. | **Not yet held: #31.** | — |
| L7 | An exception escaping the receive loop or an Engine Discovery is rethrown. It never strands Outstanding Requests in silence. | **Not yet held: #31.** Broken today: both are `detached`, which discards the exception, so the requests wait forever (research §3.4). | — |
| L8 | The receive loop ends only when its socket closes. Any other receive error re-arms it, so one failed receive cannot cut a Client off from every Target in that address family. | **Not yet held: #49.** Broken today: any receive error ends the loop for good, and every later request there times out. Linux reports only transient errors here. On Windows, which snmpio does not build on yet, an ICMP port-unreachable from one Target with no Agent would be enough. | — |

### Concurrency

| # | Invariant | Status | Held by |
|---|---|---|---|
| C1 | Initiating an operation, emitting its cancellation, and calling `stop()` are safe from any thread, on an `io_context` run by several threads. ADR-0003 decides this only for initiating; cancellation and `stop()` are this page's own commitment, which #32 holds the code to. | **Not yet held: #32.** The TSan cell (#28) runs today's tests, all single-threaded. The soak is what puts several threads on one Client. | — |
| C2 | Completions run on the caller's associated executor, even when that executor belongs to another `io_context`. | **Not yet held: #29** (the counting oracle checks the executor) **and #32** (callers on a second `io_context`). | — |
| C3 | Clients that share an `io_context` are independent. Stopping, destroying or attacking one does not affect another. | **Not yet held: #32.** | — |

### Replies: who may complete a request

| # | Invariant | Status | Held by |
|---|---|---|---|
| R1 | A v2c Response completes or fails a request only if its `request-id`, its source address and its Community all match; anything else is dropped. An off-path attacker who lacks the Community cannot complete one. | **Partly held.** The Community check is pinned; the source-address check, on its own, is #34. | `ClientGet.IgnoresAResponseQuotingTheWrongCommunity` |
| R2 | At `authNoPriv` and `authPriv`, a v3 reply other than an exempt Report counts only if its digest verifies under the Localized Key. It is decrypted only after its digest has verified. | **Partly held.** A wrong key and a tampered digest are pinned; every other unauthenticated reply is #30's oracle (R6). | `ClientV3.DropsAReplyEncryptedWithAnotherKey`, `ClientV3.KeepsRetransmittingThroughRepliesItDrops`, `V3Message.RejectsATamperedMessage`, `V3Message.RejectsTheWrongKey`, `V3Message.AuthenticationCoversTheCiphertext`, `V3Message.AVerifiedMessageIsNotSelfAuthenticating` |
| R3 | A digest whose width is not exactly the protocol's is rejected, including a 1-octet and an empty one (the CVE-2008-0960 class). | **Not yet held: #34.** The check exists (research §1.5.3), but no test pins it. | — |
| R4 | A v3 reply counts only if its Security Level, user name, `contextEngineID` and `contextName` match the request (RFC 3412 §7.2 step 12). A mismatch is a silent drop. | **Not yet held: #34.** Broken today: an `authPriv` request accepts an `authNoPriv` reply, so its data crossed the wire unencrypted and the caller is never told (research §1.1.5). | — |
| R5 | **No reply that snmpio drops fails a request before its deadline.** Every retransmission still goes out. At the deadline the request reports the last named reason it dropped a reply, or `Timeout` if it named none (ADR-0008). | **Held** by tests; the fuzzer is #30. Retransmitting through drops is pinned at v3; at v2c, the drop and the `Timeout`. | `ClientGet.IgnoresAResponseQuotingTheWrongCommunity`, `ClientV3.KeepsRetransmittingThroughRepliesItDrops`, `ClientV3.TimesOutAgainstASilentTarget`, `ClientV3.DropsAReplyEncryptedWithAnotherKey`, `ClientV3.DropsAResponseFromOutsideTheTimeWindow`, `ClientV3.AnUnsignedNotInTimeWindowsAloneFailsTheTimeSyncAtItsDeadline`, `InteropFaults.DropsMalformedBerAndTimesOut` |
| R6 | **At `authNoPriv` and `authPriv`, no unauthenticated datagram completes or fails a request before its deadline, except the two RFC 3414 makes unavoidable.** Both must first clear the Message ID and source-address check. (1) **An unsigned Report**, because an Engine that does not know the user, the key or the engineID has nothing to sign with (RFC 3414 §3.2; ADR-0008). For a request it either fails the request with the error its counter names (`UnexpectedReport` when it names none, or one the Client does not know), or forces one Engine Discovery (`unknownEngineIDs`, or `notInTimeWindows`). In Engine Discovery's time-sync phase it ends that Engine Discovery with its error, and with it every request queued behind it, except an unsigned `notInTimeWindows`, which is dropped (ADR-0008's amendment). (2) **The answer to Engine Discovery's identity phase**, Response or Report, which is unauthenticated by design (RFC 3414 §4; E1). It is read only for its engineID, and one that carries none fails that Engine Discovery with `UnknownEngineId`. A wrong engineID can fail it too, through exception (1) (see the identity phase above). Every other unauthenticated datagram is dropped. | **Partly held.** Exception (1) and its limits are pinned. Exception (2)'s empty-engineID and wrong-engineID failures have no test, and the rule that everything else is dropped is #30's oracle. | `ClientV3.SurfacesAnUnknownUserName`, `ClientV3.SurfacesAWrongDigestReport`, `ClientV3.RediscoversWhenTheEngineIdChanges`, `ClientV3.AnUnsignedLowerBootsReportNeverClearsTheCachedClock`, `ClientV3.AnUnauthenticatedReportDuringTimeSyncEndsDiscoveryWithItsError`, `ClientV3.AnUnsignedNotInTimeWindowsAloneFailsTheTimeSyncAtItsDeadline`. The fuzzer: #30. |
| R7 | **Message IDs and `request-id`s are unpredictable**, never collide with an Outstanding Request, and are fresh for each retransmission. A reply to any of a request's transmissions still counts. | **Not yet held: #33.** Broken today: one sequential counter serves every Target, so any polled Agent can predict the IDs in use for every other Target, and a retransmission reuses its ID (research §1.2). The counter does keep IDs unique for 2^31 requests. | — |
| R8 | **At v2c and `noAuthNoPriv`, where nothing is authenticated, only a datagram that matches the request completes or fails it.** At v2c that is R1. At `noAuthNoPriv` every reply must match the Message ID and source address, and a Response must also match the request's engineID and `request-id`. A matching Report fails the request or forces one Engine Discovery, as in R6 (1); Engine Discovery's identity phase is as in R6 (2). Anything else is dropped. These are the only oracles #30 can hold at these levels; they bound an off-path attacker, not an on-path one. | **Partly held.** At v2c, as R1. At `noAuthNoPriv`, the whole rule is #30's oracle. | The fuzzer: #30. |

### Engine state

| # | Invariant | Status | Held by |
|---|---|---|---|
| E1 | **No reply changes an Engine's boots and time unless it is authenticated** (RFC 3414 §3.2 step 7(b)). An unauthenticated reply can at most make the Client forget which Engine is at an address, which costs one Engine Discovery. The identity phase's unsigned engineID is the only unauthenticated value the Client trusts, as RFC 3414 §4 requires. The boots and time it carries are cached but never judged against until a signed pair replaces them. | **Held.** | `ClientV3.AnUnauthenticatedReportNeverResynchronisesTheCache`, `ClientV3.AnUnauthenticatedReportNeverSetsTheDiscoveredClock`, `ClientV3.AnUnsignedLowerBootsReportNeverClearsTheCachedClock`, `ClientV3.ASignedButDroppedReplyDoesNotVouchForTheNextOne`, `ClientV3.TheIdentityPhasesClockIsNotABaseline` |
| E2 | The Time Window is one-sided. A reply older than the pair the Client holds is dropped as a replay, and a restarted Engine or a clock stepped forward is adopted. | **Held.** | `ClientV3.DropsAReplyClaimingAnOlderBootsCount`, `ClientV3.DropsAResponseFromOutsideTheTimeWindow`, `ClientV3.AcceptsAReplyFromAnEngineThatRestartedSinceWeCachedIt`, `ClientV3.AcceptsAReplyWhoseClockSteppedForwardWithinOneBoot`, `ClientV3.ASignedHigherBootsReportIsAdoptedWithoutRediscovery`, `InteropFaults.RefusesABootsRegression`, `InteropFaults.RefusesATimeRegressionWithinOneBoot`, `InteropFaults.RecoversFromAnEngineRestart` |
| E3 | A signed Report naming a lower boots rediscovers the Engine, at most once per request (ADR-0010). A poisoned or regressed clock therefore never locks an Engine out for the rest of the Client's life. | **Held.** | `ClientV3.RediscoversAnEngineWhoseBootsWentBackwards`, `ClientV3.AForcedResyncHappensAtMostOncePerRequest`, `InteropFaults.RediscoversAnEngineWhoseBootsWentBackwards` |
| E4 | A changed engineID at a Target is rediscovered, not failed on. | **Held.** | `ClientV3.RediscoversWhenTheEngineIdChanges`, `InteropFaults.RediscoversAnEngineThatChangesItsIdentity` |
| E5 | A forced rediscovery (E3) always runs its time-sync phase. A late signed Response at the old boots cannot mark the Engine synced while that rediscovery is owed, so two Outstanding Requests to a regressed Engine both succeed. | **Not yet held: #43.** Broken today, within one round trip: the request whose Report forced the rediscovery fails with `NotInTimeWindow`, and the next request heals it. ADR-0010's Consequences accept that failure; #43 is to amend them when it lands. | — |

### Confidentiality on the wire

| # | Invariant | Status | Held by |
|---|---|---|---|
| W1 | At `authPriv`, nothing in the Scoped PDU is readable on the wire, Engine Discovery's encrypted phase included. | **Held.** | `ClientV3.AuthPrivPutsNothingReadableOnTheWire`, `ClientV3.AuthPrivDiscoversBeforeItAsks` |
| W2 | Every encryption uses fresh Privacy Parameters. | **Held.** | `PrivEncrypt.ChoosesAFreshSaltEachTime`, `PrivEncrypt.DesSaltCarriesTheBootsCount` |
| W3 | The Security Level is required, never inferred. `authPriv` without a privacy protocol is refused, never downgraded. | **Held.** | `ClientV3.RefusesAuthPrivWithoutAPrivacyProtocol`, `V3Message.RefusesToClaimPrivacyWithoutAProtocol` |

### Resource bounds

| # | Invariant | Status | Held by |
|---|---|---|---|
| B1 | Engine Discovery is single-flight per Engine, and Report-driven retries are bounded: one forced rediscovery per request, and a Time Window the Engine never agrees on fails. | **Held.** | `ClientV3.ConcurrentRequestsShareOneDiscovery`, `ClientV3.ASecondRequestSendsNoProbe`, `ClientV3.AForcedResyncHappensAtMostOncePerRequest`, `ClientV3.FailsWhenTheEngineNeverAgreesOnTheTimeWindow` |
| B2 | **The Engine and key caches stay bounded.** An engineID outside 5..32 octets is never cached. When the Engine at a Target changes, the old Engine and its keys are evicted unless another Target still maps to it. | **Not yet held: #35.** Broken today: neither cache ever evicts, an engineID can be about 64 KiB, and an Agent that keeps changing its engineID grows both caches without limit (research §1.4.1). | — |
| B3 | A Walk ends on a repeated or decreasing OID, and on leaving its Subtree (ADR-0004). | **Held.** | `ClientWalk.RejectsANonIncreasingOid`, `ClientWalk.StopsAtTheSubtreeBoundary`, `InteropFaults.FailsAWalkOnANonIncreasingOid` |
| B4 | **No Walk runs forever**, and a collecting Walk never buffers without limit. A row limit or a whole-Walk deadline ends it with `WalkIncomplete`. | **Not yet held: #36.** Broken today: an Agent returning strictly increasing OIDs is walked forever, and `asyncWalkCollect` buffers all of it (research §1.4.3). | — |
| B5 | Out-of-range `retries` and `maxRepetitions` are refused with an argument error, never clamped. | **Not yet held: #36.** | — |
| B6 | `tooBig` shrinks `maxRepetitions`, and gives up rather than looping once it cannot shrink further. | **Held.** | `ClientWalk.HalvesMaxRepetitionsWhenTheAgentSaysTooBig`, `ClientWalk.GivesUpWhenTooBigSurvivesEveryReduction`, `InteropFaults.DegradesMaxRepetitionsWhenTheAgentSaysTooBig` |
| B7 | **Key derivation does not block the caller's threads per Engine.** A password costs one Master Key derivation per Client, and none when the caller supplies the Master Key. | **Not yet held: #37.** Broken today: the megabyte hash runs on the Client's strand once per new Engine, 4 to 16 ms each (research §5.4). The legacy provider load and the per-call algorithm fetches also run on the strand: #47 (research §3.6). | — |

### The codec

| # | Invariant | Status | Held by |
|---|---|---|---|
| K1 | No input crashes the decoder, reads outside the datagram, or trips a sanitizer. | **Held** by the fuzzers, under ASan and UBSan with their assertions live since #28, and by the unit tests. | `FuzzBerValue`, `FuzzBerVarbindList`, `FuzzOidText`, `FuzzV2cMessage`, `FuzzV3Message`, `ReaderHeader.RejectsLengthBeyondInput`, `ReaderHeader.RejectsOverwideLengthField`, `ReaderHeader.RejectsHeaderCutInHalf`, `V2cMessage.RejectsTruncationAtEveryOffset`, `V3Message.RejectsTruncatedInput` |
| K2 | Whatever the decoder accepts, the encoder can express, and it decodes back identically. | **Held.** | `FuzzBerValue`, `FuzzBerVarbindList`, `FuzzOidText`, `FuzzV2cMessage`, `FuzzV3Message`, `RoundTrip.RandomisedSweep` |
| K3 | The decoder is strict where leniency would be ambiguous: indefinite lengths, the high-tag-number form, the reserved length octet, sub-identifier overflow, and OIDs over 128 sub-identifiers are all refused (CLAUDE.md, *Codec posture*; research §1.5.1 for the reserved octet and §1.5.6 for the 128 limit). | **Held.** | `ReaderHeader.RejectsIndefiniteLength`, `ReaderHeader.RejectsHighTagNumberForm`, `ReaderHeader.RejectsReservedLengthOctet`, `ReaderOid.RejectsSubidentifierOverflow`, `ReaderOid.RejectsMoreThan128Subidentifiers` |
| K4 | The digest's offset, derived from length fields the sender chooses, always lies inside the datagram. | **Held.** | `FuzzV3Message`, `V3Message.PlacesTheDigestCorrectlyUnderLongFormLengths` |
| K5 | Decryption refuses lengths the peer chooses badly: a short salt, DES ciphertext that is not whole blocks, a key too short for the protocol, and a ciphertext the key does not open. | **Held.** | `PrivDecrypt.RejectsAShortSalt`, `PrivDecrypt.RejectsDesCiphertextThatIsNotWholeBlocks`, `PrivDecrypt.RejectsAKeyTooShortForTheProtocol`, `V3Message.RefusesAnEncryptedPduTheKeyDoesNotOpen`, `FuzzV3Message` |

### Secrets

| # | Invariant | Status | Held by |
|---|---|---|---|
| S1 | Keys are derived exactly as RFC 3414 specifies, so a derivation change cannot silently weaken them. | **Held**, by the RFC's own MD5 and SHA-1 vectors, and by pinned SHA-2 and privacy rows (CLAUDE.md, *Crypto*). | `PasswordToKey.MatchesTheKnownVectors`, `LocalizeKey.MatchesTheKnownVectors`, `LocalizedPrivKey.MatchesTheVectors` |
| S2 | A password shorter than 8 characters is refused (RFC 3414 §11.2). | **Not yet held: #38.** Broken today: only an empty password is refused. | — |
| S3 | A Master Key whose length does not match its authentication protocol is refused with the argument error, never used. | **Not yet held: #37.** Master Keys cannot be supplied today. | — |
| S4 | No cache is keyed by a plaintext password. A password lives no longer than the Credentials the caller passed in. | **Not yet held: #37.** Broken today: passwords are cache keys for the Client's whole life (research §5.3). | — |
| S5 | Passwords, Master Keys and Localized Keys are wiped when snmpio is done with them, along with the stack buffers that derivation uses. | **Not yet held: #38.** Broken today: nothing is wiped. | — |

Two properties hold by construction and have no test, because no test can observe them: digests
are compared in constant time (`CRYPTO_memcmp`), and snmpio logs nothing, so it writes no secret
anywhere.

**What wiping protects against, and what it does not.** Wiping (S5) narrows what can be recovered
*after* snmpio is done with a secret. A core dump taken after the Client is destroyed, or an
allocation that reuses memory a key lived in, then finds zeros. It does **not** protect a secret
while snmpio is using it. An attacker who can read the live process's memory, through a debugger,
`/proc/<pid>/mem`, or a core dump taken mid-request, reads every password, Master Key and Localized
Key the Client holds at that moment, and nothing can stop that. It is also best effort even then: it
cannot reach copies outside snmpio's own storage, such as the `std::string`s in the caller's
Credentials, temporaries the compiler spilled, or pages the kernel swapped out. Wiping is hygiene,
not a boundary. A caller who wants passwords never to enter the I/O process at all can supply a
Master Key instead (#37). The examples will take their passwords from the environment, never `argv`,
and never one password for both keys (#37; research §1.6.3).

## Keeping this page true

- A change that adds an invariant, or a ticket that holds one, updates its row here: the status
  becomes **Held** and the test is named in full.
- A row that names a test which no longer exists is a bug in this page.
- A finding in the research note that is fixed, or newly found, changes this page in the same PR.
