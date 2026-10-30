# Message IDs are FF1, implemented here over OpenSSL's AES

#33 asks for Message IDs no Agent can predict, fresh for each retransmission. RFC 3412 section 6.2
asks for the same two things: values generated "in a manner that avoids re-use of any outstanding
values", and "a new msgID value SHOULD be used for each retransmission". Meeting both takes a
keyed permutation of 0..2^31-1 run over a counter. A permutation repeats nothing until the counter
has gone all the way round, and the key keeps the output unpredictable.

OpenSSL has no small-domain permutation, and no library snmpio already depends on has one.
ADR-0001 puts the crypto on OpenSSL EVP, and CLAUDE.md's rule reads "OpenSSL EVP, never our own".
So something has to be written here, and this record says what may be.

**snmpio implements FF1, NIST SP 800-38G Rev. 1, at radix 2 over 31 numerals with an empty tweak,
around OpenSSL's AES-128.** The key comes from OpenSSL's CSPRNG (`RAND_bytes_ex`), once per
Client. The algorithm is the SP's, step for step and under the SP's own names. AES and the key are
OpenSSL's, and the rest is written here. This is the footing snmpio already stands on for RFC
3414's password-to-key, and for the Blumenthal and Reeder key extensions, which are IETF drafts
rather than RFCs but are what every implementation follows. Each is a published algorithm
written out here over OpenSSL primitives, not a construction designed here. The crypto rule
therefore reads: **OpenSSL for every primitive (EVP for ciphers and digests, RAND for keys), a
published specification for every construction around one, and nothing of our own design.**

## Considered options

- **A random starting point and a counter**, as net-snmp (`snmp_get_next_msgid`) and gosnmp do.
  One ID seen and the rest are known, Agents at other Targets included. Fixing that is #33's
  whole reason for existing.
- **A fresh CSPRNG draw for each ID**, rejecting any still outstanding. It is unpredictable and
  needs nothing but `RAND_bytes`, but nothing stops it reusing a *completed* request's ID. A signed
  Report or Response recorded earlier in the Client's life could then match a request still
  waiting, and `handleReport`'s replay argument rests on that being impossible short of 2^31
  transmissions. The permutation keeps that guarantee. Random draws would trade it away.
- **A Feistel network of our own in FF1's shape**, which was #33's first cut. It had FF1's halves
  and rounds, but its own round function: one AES block of the round number and B, cut from the
  front of the output. That is a construction of our own, with no specification to check it
  against and no published analysis. It was rejected on review.
- **A format-preserving-encryption library.** None is packaged widely enough to be a dependency
  snmpio would accept for some sixty lines, and none is in OpenSSL.
- **FF3-1**, FF1's sibling in the same SP. It has a history of published attacks that FF1 does not
  have.

## Consequences

**Pinned against drift, as the SHA-2 key-derivation rows are.** No standard publishes radix-2 FF1
vectors. The known-answer rows in `TestMessageIdGenerator.cpp` were computed with an independent
FF1: Python, any radix, written from the SP's Algorithms 7 and 8 over pyca/cryptography's AES.
Before producing them, it reproduces NIST's published FF1 samples 1 to 3, in both directions. The
domain, 2^31, is far above the SP's minimum of one million.

**Seams, for the tests only.** `MessageIdGenerator` takes an OpenSSL library context, as
OpenSSL's own `_ex` functions do, so that a test can hand it one with no provider and see
`CryptoFailure`. It also takes a known key and starting counter, for the known-answer rows. The
Client uses neither. `detail::MessageIdView`, beside `detail::CacheView` and like it test-only,
steps a Client's generator back so that an ID still outstanding comes round again without 2^31
draws, and counts the IDs a Client still holds.

**Never 0, and never an ID still outstanding.** net-snmp never sends 0, and snmpio's counter never
did either. An ID that is still outstanding is skipped in favour of the next one, as RFC 3412 asks.
The permutation can reach one only after the counter has gone all the way round.

**Cost:** one AES block per round, ten per draw, since P's block is encrypted once at keying. An ID
is one draw, and two in the rare case that one is skipped. Next to the USM work around every v3
message, it is nothing.

**A transmission that cannot be built ends its request.** Each transmission is drawn and encoded
afresh, so a `CryptoFailure` or an encoding error on a retransmission now fails the request at once
with that error, as one on the first transmission always did. It does not wait out the deadline on
the transmissions already sent. Neither failure is one a retransmission can meet when the first
transmission did not, short of OpenSSL failing mid-run.

**What this does not permit.** It does not make room for a construction because it seems simple
or because no library offers it. A future case like this one needs a published specification to
implement. Failing that, it needs an ADR of its own.
