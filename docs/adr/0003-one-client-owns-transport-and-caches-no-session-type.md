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
