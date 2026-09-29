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

## Amendment, 2026-09-29: the checklist has two rows, not four

The simulator settling both Key Extensions per commit proves the Command Generator agrees with
*our* reading of each scheme, and the simulator is ours too. Whether a vendor read the expired
Reeder draft the same way is a question only hardware answers, so Cisco's row stands for that
independent check rather than for coverage the simulator lacks.

A device earns a row only by closing a gap the automated matrix leaves, since a row that closes
none is one nobody re-runs. iLO 5 and Meinberg NTP servers were named in the fleet above without a
gap assigned, so the README checklist carries no row for either. iLO 6 keeps its row for the widest
vendor protocol range; its 3DES waits on the library, which no stage yet carries (ADR-0005).

## Amendment, 2026-09-29: `snmpd` reads both Key Extensions too

The README, CI and the v3 interop suite's comments carried a premise that net-snmp needs a build
flag Debian does not carry, and it was wrong. Debian has built net-snmp with
`--enable-blumenthal-aes` since `5.9.1+dfsg-1`, Arch's `5.9.5.2` PKGBUILD passes the same flag,
and the one flag enables both Blumenthal (`AES192`, `AES256`) and Reeder (`AES192C`, `AES256C`).
The stock Ubuntu 24.04 `snmpd` (`5.9.4`) that CI already runs speaks all four; the users were
simply never created.

So both Key Extensions are now checked per commit against an implementation that is not ours as
well as against the simulator, which is. That settles whether an independent open-source reading
agrees with ours. It does not settle whether a vendor's does, so Cisco's row stands for the same
reason as before, iLO 6's stands for the widest vendor protocol range even though `snmpd` now reads
all of that range but 3DES, and the simulator stays the primary target for the reason this ADR
opens with.
