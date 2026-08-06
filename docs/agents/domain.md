# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root — the domain glossary. It carries explicit _Avoid:_ lists; those are binding, not advisory.
- **`docs/adr/`** — read the ADRs that touch the area you're about to work in.

If any of these files don't exist, **proceed silently**. Don't flag their absence; don't suggest creating them upfront. The `/domain-modeling` skill (reached via `/grill-with-docs` and `/improve-codebase-architecture`) creates them lazily when terms or decisions actually get resolved.

## File structure

Single-context. This repo has no `CONTEXT-MAP.md` and does not need one.

```
/
├── CONTEXT.md                 ← domain glossary (roles, operations, security, testing)
├── docs/adr/
│   ├── 0001-implement-snmpv3-natively-rather-than-wrapping-net-snmp.md
│   ├── 0002-support-both-boost-asio-and-standalone-asio.md
│   ├── 0003-one-client-owns-transport-and-caches-no-session-type.md
│   ├── 0004-walks-stream-by-default.md
│   ├── 0005-support-obsolete-crypto-including-des-and-the-reeder-draft.md
│   ├── 0006-a-deliberately-misbehaving-simulator-is-the-primary-test-target.md
│   └── 0007-apache-2-0-matching-the-simulator.md
├── docs/research/             ← the sizing and prior-art note behind the staged plan
├── include/snmpio/ · src/ · tests/ · fuzz/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0004 (walks stream by default) — but worth reopening because…_
