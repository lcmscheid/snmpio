# Apache-2.0, matching the simulator

The library is licensed Apache-2.0, with a `NOTICE` file crediting the reference implementations
we read while building it. This is recorded because it had already been settled in conversation and
then could not be found: the decision lived in a project note, the ADRs said nothing, and the repo
carried no `LICENSE` at all — which silently means all rights reserved, the opposite of what was
intended.

Apache-2.0 rather than MIT for two reasons. It carries an **explicit patent grant**, which matters
more than usual here: this is a protocol library implementing cryptographic algorithms, and the
whole point of the exercise is other people running it against their infrastructure. And it matches
[`snmp-fault-agent`](https://github.com/lcmscheid/snmp-fault-agent), which is already public under
Apache-2.0 — two halves of one toolkit under two different licences is a question every consumer
would have to answer for themselves.

`NOTICE` is Apache-2.0's own attribution mechanism, which is where the reference implementations
belong: gosnmp is BSD-3-Clause and async-snmp is MIT OR Apache-2.0, both attribution-only. Nothing
has been copied from either — the BER codec was written against X.690 and RFC 3416 directly — but
later stages will port algorithm *shape* for engine discovery and the interop workarounds that no
RFC describes, and the credit belongs there before that happens rather than after.

## Consequences

No per-file copyright headers. Copyright is automatic under Berne and a notice has not been
required since 1989, so a boilerplate block on every file buys nothing and has to survive every
rename. `snmp-fault-agent` already works this way. If a per-file marker is ever wanted, it is one
`// SPDX-License-Identifier: Apache-2.0` line, not the appendix boilerplate.

Anything ported from a reference implementation in a later stage gets an attribution comment at the
site *and* an entry in `NOTICE`. "We only read it" stops being true the moment a workaround is
transcribed.
