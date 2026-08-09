# A discarded reply reports why, at the deadline

A v3 reply this client cannot use is **dropped**, not failed: the request stays outstanding and its
retransmission timer keeps running. That is deliberate and is not changing. UDP is spoofable and the
`msgID` is guessable, so a client whose request could be failed by an unusable reply would be a
client anyone on the path could cancel at will.

The cost was that the *reason* went with the datagram. A request against a Target that is answering,
but whose every reply we refuse, completed with `Errc::Timeout` — the same code a caller gets when
the Target is unplugged. "Wrong password", "replayed boots/time" and "nobody home" were
indistinguishable from the outside, and three enumerations that already existed —
`Errc::AuthFailed`, `Errc::DecryptionFailed`, `Errc::NotInTimeWindow` — were unreachable from this
path for exactly that reason.

So: record why a datagram was dropped against the outstanding request as it happens, and consult
that at expiry instead of reporting `Timeout` unconditionally. Nothing about *when* a request
completes moves — only what it says when it does.

Three drops are named, and they are the ones a caller can act on: a digest that does not verify, an
`encryptedPDU` we cannot open, and a reply that fails our own timeliness check. Every other drop —
a datagram that does not decode, a `request-id` that does not match, a Response from the wrong
Engine — stays silent and still reports `Timeout`. Those say nothing about the Target beyond "this
was not the reply we were waiting for", which is what `Timeout` already means. The useful
distinction is between a Target that said nothing and a Target that said something we refused, not
one enumerator per branch.

## Consequences

**A behaviour break for callers.** Code that treated `Errc::Timeout` as "the Target is unreachable"
will now see `AuthFailed`, `DecryptionFailed` or `NotInTimeWindow` for a Target that is very much
reachable. It is worth the break: the old behaviour told operators to check cabling for what was a
credentials problem, and a code that means two unrelated things is one no caller can branch on. The
codes were always the ones these conditions mean — they were simply unreachable.

`Timeout` narrows to what it should have meant all along: the Target said nothing. That is testable
in a way it was not before, and `ClientV3.TimesOutAgainstASilentTarget` is what pins it.

A dropped reply still cannot fail a request before its deadline, and retransmission is untouched —
recording a reason is not acting on one. `ClientV3.KeepsRetransmittingThroughRepliesItDrops` is the
test that would catch the two drifting apart.

Engine Discovery goes through the same `transact`, so it reports the same codes: an authenticated
time-sync phase whose replies we refuse now says so rather than timing out. That is the same
improvement and wanted for the same reason -- a discovery that cannot be authenticated is the
commonest way a wrong password shows itself.

A datagram clears only the `msgID` and source-address bar before its digest is checked, so someone
who can guess a `msgID` and reach this client can turn a genuinely silent Target's `Timeout` into
`AuthFailed`. Accepted: that is strictly less than what the same bar already buys them, since an
unauthenticated Report clearing it *fails* the request outright (RFC 3414 section 3.2, and the note
in `deliverV3`). The invariant that matters -- no reply fails a request before its deadline -- is
untouched, and the cost of closing this one is checking a `request-id` we cannot read, because a
reply whose digest failed is a reply we will not decrypt.

The last reason wins where several replies were dropped for different reasons. Nothing is lost that
a caller could have used: the alternative is a list, and a caller that must act on a list of
refusals has a packet capture problem, not an error-code problem.
