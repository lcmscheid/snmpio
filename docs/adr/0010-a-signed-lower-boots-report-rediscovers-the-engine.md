# A signed lower-boots Report rediscovers the Engine

RFC 3414 never lets a non-authoritative engine's notion of an Engine's boots go down. Section 3.2
step 7(b) deems any message carrying a lower `msgAuthoritativeEngineBoots` outside the Time Window,
signed or not, and section 2.2.2 says an Engine that cannot recover its boots count must latch it at
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

## Considered Options

**Follow the RFC and stay locked out.** That is what net-snmp does. `usm_check_and_update_timeliness`
(`snmplib/snmpusm.c`) refuses a lower boots from a remote Engine with `SNMPERR_USM_NOTINTIMEWINDOW`.
`_sess_process_packet` (`snmplib/snmp_api.c`) answers a `notInTimeWindow` Report by resending the
request with its retries counted, and with the same stale pair. Its command-line tools never show
the lockout, because each invocation starts with nothing cached: rediscovering on every run is the
recovery. A long-running process holding the cache has no such recovery, and a library is that
process.

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
until the rediscovery completes. That is the same window the first discovery opens. A signed
Response arriving late at the old pair can mark the Engine synced again before the rediscovery runs.
That fails one request, and the next one recovers (#43).

A captured Report is useful to an attacker only if its `msgID` matches a request still waiting for
an answer, and `msgID`s do not repeat within one Client. A recording from an earlier process costs
one rediscovery. It can set the new baseline only if it is joined by a second recording that matches
the time-sync phase's own `msgID`, which is the exposure every first discovery already has.

Within one boot, a time that has gone backwards is not covered. An Engine whose clock was stepped
back without a boots increment breaks section 2.2.2 the same way, but the Report it signs names the
cached boots, and the Client still refuses it. Whether to extend this decision to that case is
#42.

`InteropFaults.RediscoversAnEngineWhoseBootsWentBackwards` runs this path against the Simulator
release, which signs the Report. `InteropFaults.RefusesABootsRegression` keeps pinning the refusal
of a lower-boots *Response*, against the older image that sends one.
