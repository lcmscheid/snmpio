# One client owns transport and caches; there is no session type

Every other SNMP library has a session type, so its absence here needs explaining. A single `client`
owns the shared UDP socket, the engine cache and the localized-key cache; callers get a lightweight
bound view over (target, credentials) for ergonomics, but it holds no state of its own.

The reason is that "session" conflates three things the domain keeps separate — see `CONTEXT.md`:
the **Target** (a transport endpoint), the **Credentials** (a USM user and its keys), and the
**Engine** (an engineID with its own boots and time). One Engine can sit behind several Targets, and
one Target can be addressed with several Credentials. A session type forces a false 1:1:1 binding, so
two sessions pointing at the same device rediscover the same Engine independently and repeat the
password-to-key derivation — which deliberately hashes about a megabyte — for no reason.

## Consequences

The engine cache is keyed on **engineID** with a separate endpoint→engineID index, and the
localized-key cache on (master key, engineID). Engine Discovery is single-flight per Engine and
outlives any individual waiter, so cancelling a queued request never cancels the discovery others are
waiting on. All of this state is confined to the client's own internal strand — initiating an
operation from any thread is safe, and internal state is only ever touched on that strand — so none
of the caches need locking. "Same device, two users" and "same engine, two addresses" both fall out
for free instead of being special cases.

## Amendment, 2026-10-08: one atomic outside the strand

_Narrowed by the amendment "a second atomic, for Batch delivery", below: there are now two._

All of the state is still confined to the strand but one flag: the one Stopping sets, an atomic
written on whichever thread calls `stop()` or destroys the Client, so that Stopping takes effect at
once. ADR-0009's amendment of the same date says why.

## Amendment, 2026-10-08: the strand writes the flag too

_Narrowed by the amendment "a second atomic, for Batch delivery", below: there are now two._

A receive loop that throws stops the Client from its completion, which runs on the strand, so the
flag now has a writer there as well as the threads above. It is still the one atomic and nothing
else leaves the strand. ADR-0009's amendment on the receive loop says why.

## Amendment, 2026-10-08: a second atomic, for Batch delivery

This narrows the two amendments above, which say the flag is the one atomic. A second atomic now
sits beside the flag: the id of the thread delivering a Batch, written on the strand around each
handler call and read by `stop()` and `~Client`, which wait for the handler when another thread is
running it. Nothing else leaves the strand. ADR-0009's amendment on Batch delivery says why.

## Amendment, 2026-10-24: one Client per Target is the recommended deployment

_Narrowed by the amendment "the key caches are keyed by Master Key, and the caller may supply
one", below: a Master Key the caller supplies costs no Client a derivation._

The README now recommends one Client per Target on a shared `io_context` (#32), which reads like
the opposite of a Client that owns the caches for every Target. It is not a session type: a Client
still binds nothing to a Target, and any one of them can address any Target with any Credentials.
What changes is how many Clients an application makes, and that trades this ADR's sharing against
the strand. One Client does all its work on one strand, so every Target's replies are decoded,
authenticated and decrypted one after another, however many threads run the `io_context`; a Client
per Target spreads that across them and keeps a misbehaving Agent's traffic on its own Client's
strand. The price is the one this ADR names: Clients share no Engine or key cache, so an Engine
behind two Targets polled by different Clients is discovered twice, and each Client derives the
Master Key for its own Credentials.

So the recommendation is per Target for Targets that are Engines of their own, which is most of
them, and one Client for Targets that front the same Engine. The decision above, one Client that
owns transport and caches with no session type, is unchanged.

## Amendment, 2026-10-25: the key caches are keyed by Master Key, and the caller may supply one

_Narrowed by the amendment "password-to-key runs on a private thread", below: no megabyte hash is
left on the strand._

The consequence above names the localized-key cache "(master key, engineID)". Until now it was
keyed by the password the Master Key is derived from, so that a lookup never had to derive
anything, and the Master Key itself was never kept: every new Engine paid the megabyte hash again.
The cache is now keyed as written, and a second cache sits in front of it, of Master Keys per
(hash, password), with the password held only as a keyed digest (#37). A password costs one
derivation per Client, however many Engines it meets.

Credentials may also carry the Master Key in place of the password, derived by the caller once, on
a thread of their choosing. That narrows the trade the amendment of 2026-10-24 names: Clients still
share no cache, but a Master Key handed to every Client costs none of them a Master Key derivation.
One megabyte hash is left on the strand whatever the caller supplies: a Reeder privacy key
(`Aes192C`, `Aes256C`), whose Key Extension reruns password-to-key over the Localized Key, costs one
per Engine. Moving it, and a password's derivation, off the strand is #80. Both caches stay the
Client's own and on its strand, so nothing else here changes.

## Amendment, 2026-11-03: an Engine no Target maps to is evicted

The caches above were append-only, so an Agent that named a fresh engineID at every Engine
Discovery grew them without limit, a localising hash per secret each time (#35, threat model B2).
They now keep an Engine only while some Target maps to it. When a discovery maps a Target to an
engineID other than the one it last did, the old Engine goes, with its Localized Keys, unless
another Target still maps to it. One Engine at two Targets is still one entry, which is this ADR's
point, and it lasts as long as either Target names it. Master Keys are per password, not per Engine,
and stay. An engineID outside RFC 3411's `SnmpEngineID` size, 5 to 32 octets, fails its discovery
with `UnknownEngineId` and is never cached; RFC 3414 section 3.2 step 3 treats it as unknown. The
codec still decodes one, so its posture is unchanged.

net-snmp is no precedent here. Its Command Generator adds a user row per engineID a session meets,
accepts engineIDs of up to 1024 octets (`USM_MAX_ID_LENGTH`), and removes neither the row nor the
Engine's boots and time when a session's engineID changes. The bound is RFC 3411's, and the
eviction this ADR's own: the cache keys on engineID, and an engineID nobody addresses is dead
weight.

Two costs follow, and the threat model's B2 and E1 rows carry them. The identity phase is
unauthenticated by design (RFC 3414 section 4), so a forged answer that names another engineID now
evicts the real Engine's synchronised clock and Localized Keys. It used to cost an Engine Discovery
and a localising hash for the forged engineID, and leave the real Engine cached; now the real
Engine's next request pays a time-sync phase and a localising hash per secret as well. And a Target that really fronts several Engines in turn (CONTEXT.md) pays the same
at each change, where the cache used to remember every one of them. Neither cost is unbounded, and
the first was already the attacker's to impose at the price of a discovery.

A Target forgotten on an unsigned `unknownEngineIDs` Report is not unmapped: it names no Engine
until it is rediscovered, but still holds its old one, so forgetting evicts nothing and the
rediscovery can still evict what it replaces. The cache is still the Client's own and on its
strand; nothing else in this ADR changes.

## Amendment, 2026-11-19: password-to-key runs on a private thread

The amendment of 2026-10-25 left two megabyte hashes on the strand: a password's Master Key, once
per Client, and a Reeder privacy key's Key Extension, once per Engine. Everything else queued on
the strand waited behind each (threat model B7). Both now run on a private thread each Client
starts the first time it needs one, the deriver, and nothing else does: a localising hash is short
and stays where it was (#80).

The precedent is Asio's own resolver, which runs the blocking `getaddrinfo` on a private thread its
service starts on first use; the caller passes no executor for it and gets the completion on their
own. Password-to-key is the same kind of work, blocking and occasional, so the Client takes no
executor for it either. A constructor argument naming one was the alternative, and it can still be
added without breaking anyone; no Asio I/O object asks for one today.

The caches stay the strand's. A derivation is spawned on the strand, hands the deriver a job that
owns copies of everything it reads -- the password, or the Master Key and engineID -- and resumes
on the strand to write the cache. Nothing the strand owns is touched off it, so nothing gains a
lock, and the two atomics of the amendments above are still the only state outside the strand.

Derivations are single-flight per key, as Engine Discovery is per Target, and for the same reason:
a derivation belongs to the key, not to the request that happened to need it first. Requests that
need a key already being derived wait on that derivation, and cancelling one of them ends that
request alone, with the rules for a request queued behind a discovery. A Reeder key derived for an
Engine evicted meanwhile is handed to its waiters but not cached, so the eviction of 2026-11-03
still bounds the cache.

The deriver is one thread, so derivations of different keys queue one behind another on it. Each
is occasional, and a request queued behind them can still be cancelled or stopped at once, so a
second thread would buy little.

Stopping wakes every request waiting on a derivation with `ClientStopped` and does not wait for the
derivation itself (ADR-0009: never for anything that has not already started, and a megabyte hash
that has started may not finish soon enough). The derivation is not detached: it finishes against
the shared state it co-owns, writes its result, and lets the state go. The deriver is joined when
the state is destroyed, which cannot happen while a derivation is in flight, so the join never
waits on one. #80's triage asked for the join at Stopping; this overrides it, because a join at
Stopping either waits on a derivation in progress or cannot happen until one ends, and the state
going is exactly that moment. The cost is an idle thread from Stopping until the state goes.

A derivation in flight is outstanding work on the `io_context`, and the caller's rule that the
`io_context` outlive its work covers it, but it is not like a pending timer. Destroying an
`io_context` with a timer pending destroys the timer's handler; a derivation is held by the
deriver, which hands its result to the strand of whatever `io_context` it was started on. So a
caller who stops and destroys the `io_context` with one in flight breaks the rule, and the handoff
then reaches a destroyed `io_context`. Within the rule, the result is always handed to a live one,
and the state is never let go on the deriver's own thread. `Client.hpp` says so beside the rule.
