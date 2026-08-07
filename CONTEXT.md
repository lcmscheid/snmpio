# SNMP Client

An async C++20 library for SNMPv2c and SNMPv3 command generation — GET, GETNEXT, GETBULK, SET and
subtree walks — built directly on Asio with no net-snmp dependency. Manager side only.

## Language

### Roles and participants

**Command Generator**:
The role this library implements: it originates requests and consumes responses. It is never the
authoritative engine for a request it sends.
_Avoid_: manager, client-side, NMS

**Target**:
A transport endpoint (address + port) that we send requests to.
_Avoid_: agent, device, host, node

**Agent**:
Reserved for its precise meaning — a command responder, i.e. the SNMP software running on a managed
device. Never used loosely for "the thing we are talking to"; that is a Target.

**Engine**:
An SNMP protocol engine, identified by its engineID. The engine that authorizes a request is the
**Authoritative Engine**, and it owns the boots/time pair that all timeliness checks are made
against. One Engine may be reachable at several Targets, and one Target may front several Engines.
_Avoid_: device identity, remote

**Credentials**:
Whatever authenticates a request against a Target — a Community for v2c, or a USM user name plus auth
and privacy protocols and their secret material for v3. Independent of Target: the same Credentials
may be used against many Targets, and one Target may be addressed with several different Credentials.
_Avoid_: auth config, user config, login

**Community**:
The shared string that authorizes an SNMPv2c request. Sent in cleartext and offers no real security;
supported because v2c is the scaffold the v3 stack is built and tested on, not because it is safe.
_Avoid_: community string, password, v2c credentials

### Protocol operations

**Walk**:
A traversal of a Subtree, built from repeated GETNEXT or GETBULK requests. There is no WALK PDU — a
Walk is a composed operation, not a protocol primitive.
_Avoid_: snmpwalk, bulkwalk, tree walk

**Subtree**:
The set of OIDs lexicographically at or beneath a given base OID. Defines a Walk's extent and its
termination condition.

**Varbind**:
A pairing of an OID with a value or with one of the three exception markers (`noSuchObject`,
`noSuchInstance`, `endOfMibView`). The unit that requests and responses carry lists of.
_Avoid_: variable binding, binding, name/value pair

**Scoped PDU**:
A PDU together with its `contextEngineID` and `contextName`. The unit that SNMPv3 privacy encrypts.

**Report**:
A control-plane PDU returned in place of a Response, carrying a `usmStats` counter OID that explains
why the request was rejected. Expected traffic, not an error — Reports drive discovery and
resynchronisation and are handled internally rather than surfaced to callers.
_Avoid_: error response, failure PDU

**Message ID**:
The engine-level `msgID` from the v3 message header, which identifies an outstanding request. It is
distinct from the PDU's `request-id` and is what outstanding requests are keyed on, because a message
whose decryption fails must still be attributable.
_Avoid_: request id, transaction id, sequence number

### Security

**Security Level**:
One of `noAuthNoPriv`, `authNoPriv`, `authPriv` — whether a message is authenticated, and whether it
is additionally encrypted.
_Avoid_: security mode, auth level

**Engine Discovery**:
The exchange that learns an Authoritative Engine's engineID and then its boots/time pair. Two phases,
and asynchronous — requests issued against an undiscovered Engine queue behind it.
_Avoid_: probe, handshake, engine negotiation

**Time Window**:
The 150-second interval outside which a message's boots/time pair is rejected as untimely. It is
one-sided on the Command Generator's side of the exchange: a pair *behind* the one cached for that
Engine is a replay, while a later boots count or a later time is the Engine saying it restarted or
that its clock was stepped, and is adopted (RFC 3414 section 3.2 step 7b).

**Master Key**:
The Credentials' secret material expanded by the password-to-key algorithm, before it is bound to any
particular Engine.
_Avoid_: password hash, derived key

**Localized Key**:
A Master Key bound to one Engine's engineID, so that a key compromised on one Engine is useless
against another. Derived per (Master Key, engineID) pair and cached, because the derivation is
deliberately expensive.
_Avoid_: engine key, session key

**Privacy Parameters**:
The salt that travels in `msgPrivacyParameters`, from which both sides rebuild the cipher's IV. Ours
to choose and never to repeat under one key; for DES it also carries the boots count.
_Avoid_: nonce, IV — the IV is derived from this, and is not this.

**Key Extension**:
The scheme used to stretch a Localized Key when the privacy protocol needs more key material than the
hash produces — either **Blumenthal** or **Reeder**. Neither is standardised, the two are mutually
incompatible, and Targets differ in which they expect, so it is always chosen explicitly and never
guessed. Both schemes are exercised in CI against the Simulator. AES-128 uses no Key Extension at
all, so the distinction only arises at 192 and 256 bits. Reeder is spelled with a **`C` suffix**
(`AES192C`, `AES256C`) — the convention net-snmp, gosnmp and the Simulator all independently settled
on; we follow it rather than invent a fourth spelling.
_Avoid_: key expansion, key stretching, "Cisco AES" as a protocol name

### Testing

**Simulator**:
Our own configurable SNMP agent, used as the primary interop target in CI. Distinct from a real Agent
in that it can be told to **misbehave** — returning `tooBig`, non-increasing OIDs, stale boots/time,
or malformed messages — which is the only way to reach the client's defensive paths, since no correct
Agent will ever produce them.
_Avoid_: mock, fake agent, test server

**Scripted Agent**:
The in-process command responder the unit tests build a Target on, whose every Response is written
by the test that needs it. Distinct from the Simulator: same purpose — reaching the paths a correct
Agent never produces — but it lives in `tests/`, speaks only what one test scripts, and is never an
interop target. Naming it separately keeps *Simulator* meaning the one published container.
_Avoid_: mock, stub agent, test double
