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
quite thin: unless told otherwise it stops at `defaultCollectLimit` Varbinds. That covers
the large tables a collecting caller typically asks for — interfaces, ARP, a switch's forwarding
database — and a caller after something bigger, such as a full routing table, raises it or streams.
A Walk ended by its limit says `WalkIncomplete` and keeps what it gathered, as a `total`
cancellation does: cut short, never looking complete. net-snmp's `snmpwalk` has no such limit and
relies on the operator's Ctrl-C; a library running thousands of Walks has no operator to rely on.

Issue #36 asked for "a row limit and a deadline". The limit counts Varbinds, `maxVarbinds`, because
a Walk delivers Varbinds in Batches and has no rows (CONTEXT.md); for the one-column GETNEXT Walk
the issue had in mind the two are the same. The whole-Walk bound is `timeLimit`, not a deadline,
because a deadline is already each Outstanding Request's own, set by `Target::timeout`.

Adding the limits made `WalkOptions` a class with a constructor rather than an aggregate, a source
break the issue did not ask for. As an aggregate, the `WalkOptions{2}` most callers write would
trip `-Wmissing-field-initializers` under GCC and Clang for every field after `maxRepetitions`.
`WalkOptions{}` and `WalkOptions{n}` still compile, but a designated
`WalkOptions{.maxRepetitions = n}` no longer does, and is written `WalkOptions{n}`.
