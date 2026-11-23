# Security policy

snmpio parses datagrams from the network and holds SNMPv3 secrets, so a flaw in it can matter to
whatever embeds it. What it defends against, and the invariants it keeps, are in
[`docs/threat-model.md`](docs/threat-model.md).

## Supported versions

snmpio is pre-1.0. Fixes land on `main` only; there are no maintained release branches yet.

## Reporting a vulnerability

Please **do not open a public issue.** Report it privately through GitHub instead:
[**Report a vulnerability**](https://github.com/lcmscheid/snmpio/security/advisories/new)
(the repository's _Security_ tab → _Report a vulnerability_).

A useful report says which invariant in the threat model it breaks, if any, and includes the
smallest input that shows it — for a decoder bug, the datagram bytes; for anything else, the
calls and the Target's behaviour.

You should hear back within a week. Once a fix is ready, it is published together with a GitHub
Security Advisory that credits you, unless you would rather not be named.

## In scope

Anything that breaks the threat model: a datagram that crashes the process, corrupts memory or
hangs a thread; a Response accepted from the wrong Target or at the wrong Security Level; an
Outstanding Request that never completes; a secret that leaks to the wire or survives in memory
after use.

Weak protocols the caller asked for (MD5, DES, SNMPv2c communities) are not vulnerabilities in
themselves: snmpio supports them because deployed Targets still need them.
