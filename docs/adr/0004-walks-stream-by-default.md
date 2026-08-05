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
