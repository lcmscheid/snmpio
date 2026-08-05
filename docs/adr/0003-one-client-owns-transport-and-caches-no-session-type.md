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
