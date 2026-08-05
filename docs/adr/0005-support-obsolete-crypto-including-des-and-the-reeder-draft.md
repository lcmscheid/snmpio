# Support obsolete crypto, including DES and the expired Reeder draft

A library written in 2026 that implements MD5, SHA-1, DES and 3DES — the last two via an expired
Internet-Draft — looks like an oversight, so the reasoning is recorded here. We support the full
range from MD5/SHA-1 auth and DES privacy up through SHA-512 and AES-256, including AES-192/256 under
**both** the Blumenthal and Reeder key extensions, with no protocol gated behind a build flag.

The deciding argument is that refusing obsolete protocols does not remove them from the network. The
deployed devices this library exists to talk to require them: HPE iLO 6 alone offers MD5, SHA-1,
SHA-256/384/512, DES, 3DES and AES-128/192/256. A library that refuses the weak half of that list is
not usable on a real network, and users would fork it to add them back — a worse security outcome
than supporting them, since the fork gets none of our review. We steer through API ergonomics
instead: SHA-256 with AES-128 is the shortest thing to type.

The one exclusion is **IDEA**. SNMP++ implements it, but we found no evidence of any deployed device
using it, so it would be legacy support for its own sake.

## Consequences

Single DES-CBC lives in OpenSSL 3.x's **legacy provider**, which is not loaded by default (verified
on OpenSSL 3.6.3; `DES-EDE3-CBC`, by contrast, is in the default provider). The legacy provider is
therefore loaded lazily on first DES use, and its absence fails *that operation* with an error naming
the provider — not the build, and not client construction. A user whose OpenSSL lacks legacy must
still be able to use AES against every other device in their fleet.

Key Extension is never inferred. Blumenthal and Reeder are mutually incompatible and Targets differ
in which they expect, so it is a required field whenever the privacy protocol is AES-192/256 and
construction fails if it is unset. Both are exercised in CI against the Simulator, which speaks both.
We spell Reeder with a `C` suffix (`AES192C`, `AES256C`), following net-snmp, gosnmp and the
Simulator rather than inventing a fourth naming convention.

On sequencing: our own production use is SNMPv3 authPriv with **AES-128**, which uses no Key
Extension at all. The Blumenthal/Reeder split is therefore a correctness requirement for other
users' Cisco gear, not a blocker for ours, and it stays in its planned late stage rather than being
pulled forward.
