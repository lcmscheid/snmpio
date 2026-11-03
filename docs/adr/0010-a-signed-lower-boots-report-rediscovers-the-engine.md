# A signed lower-boots Report rediscovers the Engine

RFC 3414 never lets a non-authoritative engine's notion of an Engine's boots go down. Section 3.2
step 7(b) deems any authenticated message carrying a lower `msgAuthoritativeEngineBoots` outside the
Time Window, and section 2.2.2 says an Engine that cannot recover its boots count must latch it at
2147483647 rather than start again from a lower one. Against a compliant Engine, then, a lower boots
is always a replay. Real Engines are not all compliant: a factory reset, a replaced line card, or
firmware that loses `snmpEngineBoots` brings an Engine back with a lower count under the same
engineID and the same users. Followed to the letter, the RFC leaves a long-lived Command Generator
locked out of that Engine until it is restarted, since no message the Engine can send is ever
timely again.

So when a **signed** `notInTimeWindows` Report answers a request with a boots lower than the one
cached, the Client forgets its notion of that Engine's clock and rediscovers it, time-sync phase
included (issue #40). The Report's own pair is still never written; step 7(b) holds for it. The
Client acts only on what its signature establishes, that the Engine holding our key says our notion
is wrong, and lets a fresh Engine Discovery establish the baseline. Rediscovering is one more round
of RFC 3414 section 4. The RFC does not say when a non-authoritative engine may drop what it holds
about an Engine, and only a restart drops it today.

## Considered options

**Follow the RFC and stay locked out.** That is what net-snmp does. `usm_check_and_update_timeliness`
(`snmplib/snmpusm.c`) refuses a lower boots from a remote Engine with `SNMPERR_USM_NOTINTIMEWINDOW`,
so the signed Report fails to parse. `usm_handle_report` answers nothing for an incoming Report, and
`_sess_process_packet_parse_pdu` (`snmplib/snmp_api.c`) frees it. The request is left to retransmit
with the same stale pair until it times out. Its command-line tools never show the lockout, because
each invocation starts with nothing cached: rediscovering on every run is the recovery. A
long-running process holding the cache has no such recovery, and a library is that process.

**Adopt the Report's pair directly.** This saves a round trip, but it writes a pair step 7(b)
forbids, from a message that may be a replay. Rediscovering writes only the Engine's answer to a
request we have just made.

## Consequences

An unsigned Report never triggers it. Anyone can forge one, and a forger could then make the Client
forget a clock at will.

A request gets at most one forced rediscovery, because only its first attempt may retry. An Engine
that keeps sending signed lower-boots Reports after rediscovery fails that request with
`Errc::NotInTimeWindow`, as before.

The flag that is cleared belongs to the Engine, so every Target reaching it stops judging timeliness
until the rediscovery completes. That is the same window the first discovery opens. Only Engine
Discovery's time-sync phase marks an Engine synced again. A signed Response arriving late at the
old pair is still adopted, as step 7(b)(1) allows, but it cannot stand in for the rediscovery. An
earlier version let it, which failed the request whose Report had forced the rediscovery (#43). The
same Response arriving *after* the rediscovery answers its request but no longer moves the clock:
see the amendment below.

A captured Report is useful to an attacker only if its `msgID` matches a request still waiting for
an answer, and `msgID`s do not repeat within one Client. A recording from an earlier process costs
one rediscovery. It can set the new baseline only if it is joined by a second recording that matches
the time-sync phase's own `msgID`, which is the exposure every first discovery already has.

Within one boot, a time that has gone backwards is not covered. An Engine whose clock was stepped
back without a boots increment breaks section 2.2.2 the same way, but the Report it signs names the
cached boots. The Client refuses that pair until the Engine's clock passes the last time it saw,
so the lockout lasts about as long as the step and then heals. Recovering sooner was declined
(#42): it would act on a same-boots pair step 7(b) deems untimely, for a case that already fixes
itself and that only an Engine breaking the RFC can cause.

`InteropFaults.RediscoversAnEngineWhoseBootsWentBackwards` runs this path against the Simulator
release, which signs the Report. `InteropFaults.RefusesABootsRegression` keeps pinning the refusal
of a lower-boots *Response*, against the older image that sends one.

## Amendment, 2026-11-03: a reply from before the rediscovery keeps its answer and loses its clock

Two requests go out at the cached boots N. The Engine signs a Response to one, then resets to
boots M < N. The other meets a signed lower-boots Report and its retry rediscovers the Engine at M.
If the held Response lands after that, step 7(b)(1) reads its boots N as a restart, and section
2.2.3 adopts it. The cache is back at N, the boots the Engine was rediscovered for abandoning. The
retry's answer at M is now behind the cache and is dropped, and a request on its second attempt
that reads N fails with `Errc::NotInTimeWindow` (#84).

So each time Engine Discovery's time-sync phase sets a pair, it starts a new **Baseline**, numbered
from a counter the Client keeps across Engines. Each request records the baseline
it was sent under. A signed reply to a request sent under an earlier baseline still answers that
request, and still has to be timely to do so. Only its clock is dropped, and it never reaches the
cache.

Step 7(b) still holds for every message, so this rule is stricter than the RFC, not looser. The
RFC has the non-authoritative engine adopt a later pair because that is the only evidence it has
of where the Engine's clock has got to. Here it has better evidence: a time-sync phase answered
after the request went out. From the message alone, a reply the Engine signed before its boots went
backwards looks the same as one from an Engine that has since restarted. What separates them is when
the request was sent, so that is what the rule asks. Section 2.2.3 does not cover this case at all:
it assumes boots never goes down, and the Engine that ADR-0010 is about broke that assumption.

The rule keys on when the request was sent, not on when the reply was signed, and those can differ.
A request delayed on its way out can reach the Engine after the time-sync phase. Its reply's clock is
then genuinely newer, and it is dropped all the same. Nothing is lost unless the Engine also
restarted in that gap. If it did, the next request goes out at the Baseline's boots and meets a
signed higher-boots Report, which is adopted, so the request costs one retry. It fails only if it
was already on its second attempt.

A signed Report to a request from an earlier Baseline can still force a rediscovery, if it names a
boots below the current one. That takes the Engine's boots going backwards twice in a row. It costs
one more time-sync phase, bounded as before by the one forced resync a request may have, and fails
nothing, so the Report path is left as it was.

Numbered across the Client rather than per Engine, so that an Engine evicted and discovered again
(threat model B2) never repeats a baseline a request from before the eviction still holds.

**Refuse the abandoned boots itself.** This was the other option. When a Report forces the
resync from N down to M, it would record N, and refuse every pair at boots ≤ N until the Engine is
seen above N. The rule keys on the value rather than on when the request was sent, so it also
refuses a genuine restart that lands between M and N. After a reset from 9 to 3, an Engine that
restarts to 4 is refused. Its Reports name a higher boots, not a lower one, so none of them forces
the resync that would lift the rule, and the Engine is locked out. Threat model E2 forbids that.
The baseline rule refuses nothing a request sent under the current baseline sees.

`ClientV3.ALateSignedResponseAfterARediscoveryDoesNotFailTheRetry` and
`ClientV3.ALateSignedResponseAfterARediscoveryCostsTheNextRequestNothing` pin the two places the
held Response can land. `ClientV3.AdoptsARestartSeenInAReplyToARequestSentUnderTheCurrentBaseline`
pins what the rule must not refuse.
