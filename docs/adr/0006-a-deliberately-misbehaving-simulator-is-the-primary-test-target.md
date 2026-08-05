# A deliberately misbehaving simulator is the primary test target

CI runs against our own SNMP agent simulator (Go, published as a container image from its own repo)
alongside a containerized `net-snmp` `snmpd`. The simulator — not `snmpd`, and not real hardware — is
the primary target, because it is the only one that can be told to **misbehave**.

Several of the client's most important code paths exist solely to survive broken Agents: the
non-increasing-OID guard in Walk, `tooBig` degradation of `max-repetitions`, engine restart and
boots/time regression handling, Report PDU routing, and BER decoding of malformed input. **A correct
Agent will never produce any of these conditions**, so testing exclusively against `snmpd` and real
devices leaves exactly the defensive code untested — the code that only ever runs when something has
already gone wrong.

The simulator also settles a question we expected to need hardware for: it speaks `AES192`/`AES256`
(Blumenthal) *and* `AES192C`/`AES256C` (Reeder), so both Key Extension schemes are verified on every
commit rather than at pre-release against a borrowed switch.

## Consequences

Two repositories, not a monorepo or a submodule — different languages and cadences — with the
simulator consumed by CI as a published container image. The simulator is made public: it is useful
to anyone testing an SNMP client in any language, independent of this library.

The simulator **infers** security level from which protocols are set, while the client **requires** it
explicitly (a client that silently downgrades `authPriv` to `authNoPriv` has a security hole; a test
agent that accepts whatever arrives is just convenient). This divergence is intentional and is noted
in both READMEs so it is not mistaken for an inconsistency to be fixed.

Real hardware — iLO 5, iLO 6, Cisco switches, Meinberg NTP servers — remains a manual pre-release
checklist, recorded in the README with firmware versions. Cisco covers the Reeder path and iLO 6
covers 3DES and the full protocol range.
