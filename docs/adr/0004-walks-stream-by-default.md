# Walks stream by default; collecting is the wrapper

`async_walk` delivers each batch as it arrives; `async_walk_collect` is a thin convenience built on
top. The obvious API is the reverse — return a vector — and that is why this is recorded.

A Walk has no bounded size. The library targets thousands of concurrent Targets, so a buffering core
commits unbounded memory multiplied by concurrency, and the failure only appears in production
against the one device with a large table. Streaming can always be wrapped into collecting; a
buffering core cannot be unwrapped into streaming without rewriting it.

## Consequences

Two behaviours are mandatory in the walk loop regardless of delivery mode: terminate at the Subtree
boundary, and reject a non-increasing OID. The second is not defensive paranoia — a buggy Agent that
repeats an OID will otherwise walk forever, it is common enough that every mature implementation
carries the check, and it can only be tested against a deliberately misbehaving Simulator (ADR-0006).

Cancellation is correspondingly split: `total` finishes the in-flight batch and stops cleanly, with
the caller keeping what they received plus an explicit incomplete signal; `terminal` drops everything
immediately. A partially-consumed Walk must never look like a complete one.

## Amendment, 2026-10-25: a collecting Walk has a limit by default

The two mandatory checks do not end every Walk. OIDs may have up to 128 sub-identifiers of up to
2^32 each, so a faulty or hostile Agent that answers with ever-longer OIDs inside the Subtree passes
both and never stops (issue #36). Streaming leaves that to the caller, whose Batch handler already
decides when to stop, so `asyncWalk` still has no limit unless `WalkOptions` sets one. But in
`asyncWalkCollect` it is the unbounded buffer this ADR exists to avoid, so the wrapper is no longer
quite thin: unless told otherwise it stops at `defaultCollectLimit` (100,000) Varbinds. That covers
the large tables a collecting caller typically asks for — interfaces, ARP, a switch's forwarding
database — and a caller after something bigger, such as a full routing table, raises it or streams.
A Walk ended by its limit says `WalkIncomplete` and keeps what it gathered, as a `total`
cancellation does: cut short, never looking complete. net-snmp's `snmpwalk` has no such limit and
relies on the operator's Ctrl-C; a library running thousands of Walks has no operator to rely on.
