#!/bin/sh
# Starts one interop Agent in a container on the loopback port, waits until it answers, and prints
# the environment the interop suite needs for it, to stdout.
#
#   tests/interop/start-agent.sh snmpd | simulator | simulator-release
#
# CI's interop jobs and a workstation run exactly this, so a CI failure is one command away from
# being reproduced. The output is `NAME=value` lines -- what $GITHUB_ENV takes as-is. On a
# workstation, write it to a file and export that, which bash, zsh and fish all take:
#
#   tests/interop/start-agent.sh snmpd > /tmp/snmpio-interop.env \
#     && export $(cat /tmp/snmpio-interop.env)
#
# not `export $(tests/interop/start-agent.sh snmpd)`, which exports nothing from a failed start and
# reports success -- and the suite then skips every test and goes green. Everything else, the
# container runtime's included, goes to stderr.
#
# The capability flags below say what each Agent is, not what it should be, since nothing on the
# wire announces either -- and this is the one place they are said. Every flag is printed for every
# Agent, empty where the Agent lacks it, because empty reads as unset (tests/InteropTarget.hpp):
# so applying the output after a run against another Agent leaves nothing of that one behind.
#
# The password comes from SNMPIO_INTEROP_V3_PASSWORD when it is set. It is not a secret: it
# authorizes a loopback Agent this script starts. One value configures the Agent and drives the
# suite, so the two cannot drift.
#
# One Agent at a time, in a container called `snmpio-interop`, replaced by the next run.
# `docker logs snmpio-interop` is its log, and `docker rm -f snmpio-interop` stops it.
set -eu

usage() {
  echo "usage: $0 snmpd | simulator | simulator-release" >&2
  exit 2
}
[ $# -eq 1 ] || usage
agent=$1

here=$(cd "$(dirname "$0")" && pwd)
container=snmpio-interop
port=16161
password=${SNMPIO_INTEROP_V3_PASSWORD:-snmpio-interop}
# The Simulator's control UI listens on 8080 inside its image; faultsPort is where it is published.
simulatorUiPort=8080
faultsPort=8080

# Only `snmpd` answers a bad digest with the usmStats Report RFC 3414 leaves optional. Every Agent
# here speaks AES-192/256 under both Key Extensions, so that flag does not tell them apart, but it
# is set on each: it says what an Agent is, and a Target outside CI may not be one.
usmReports='' keyExtensions=1 faults='' faultsEngineId=''
# Both Simulator images answer a GETNEXT carrying several Varbinds from the wrong requested OIDs
# (lcmscheid/snmp-fault-agent#11); tests/InteropOperations.hpp says what the flag gates and why it
# names the defect. Unset it here when a fixed image is pinned.
brokenGetNext=''
# The error-status each Agent refuses the suite's read-only SET with, spelled as RFC 3416 spells
# it; tests/InteropSet.hpp says what the SET is. Empty would accept any refusal.
setRefusal=''

# The Writer Credentials, the only identities the SET tests write sysContact.0 with. They are
# printed here, for the Agents we configure, and nowhere else: a Target outside CI writes nothing
# unless whoever runs the suite names a writer for it. The users are named alike on every Agent
# here; the Community is not, since the Simulator has only the one.
writerCommunity=snmpio-writer
writerNoAuth=writer-noauth writerAuth=writer-authsha256 writerPriv=writer-privsha256aes

# Every Agent here is pinned, so a push to an image nobody here controls cannot change what this
# library was tested against between two runs of the same commit. Moving a pin is a commit here,
# which is where an Agent change that breaks us becomes visible. The Simulators are pinned by
# digest below -- `docker buildx imagetools inspect ghcr.io/lcmscheid/snmp-fault-agent:latest`
# prints the current one -- and `snmpd` by snmpd.Dockerfile, beside this.
#
# Two Simulators, and the older one is not redundant. `simulator` answers a request whose
# boots/time it disagrees with by stamping its own pair into an ordinary Response;
# `simulator-release` grew the authoritative-side check and sends the usmStats Report instead,
# which is what a compliant Agent does. Only the first shape reaches the Command Generator's own
# timeliness comparison -- it was a Response of exactly that kind that caught this Client reading
# RFC 3414 section 3.2 step 7a where 7b applies, and the release image passes that bug in silence.
# The release is pinned because it is what anyone else will run; the older image because it is the
# only Agent that makes the comparison observable at all.
#
# Each Agent says here how it is fetched, how its configuration is written and where that is
# mounted, and how to tell it is answering. `mounts` lists where each configuration file goes in
# the container, and `configure` writes each into $configDir under the same base name.
useSimulator() {
  image=$1
  mounts='/etc/snmpfault/auth.json /etc/snmpfault/values.json'
  configure() {
    "$here/fault-agent-auth.sh" > "$configDir/auth.json"
    "$here/fault-agent-values.sh" > "$configDir/values.json"
  }
  faults=$faultsPort
  brokenGetNext=1
  # readOnly, which RFC 3416 section 4.2.5 says an SNMPv2 entity never sends -- notWritable is the
  # status for a read-only object (lcmscheid/snmp-fault-agent#10). The suite asserts what the
  # Agent does and says on every row that it is non-compliant. Make it notWritable when an image
  # fixing that is pinned. Both images also blame Varbind 0 where RFC 3416 names the one sent
  # (lcmscheid/snmp-fault-agent#12); no flag gates that, and the rows note it until it is fixed.
  setRefusal=readOnly
  writerCommunity=public
  fetch() { docker pull -q "$image"; }
  # The control UI and the SNMP socket come up in the same process, and the UI answers over TCP --
  # so a connection to it is the readiness check.
  answers() { curl -fsS -o /dev/null "http://127.0.0.1:$faultsPort/"; }
}
case $agent in
  snmpd)
    image=snmpio-interop-snmpd
    mounts=/etc/snmpio/snmpd.conf
    # `default` is any source. A request through the published port arrives from the runtime's
    # gateway rather than from 127.0.0.1, and the port is published on the loopback alone, which is
    # the restriction.
    configure() { "$here/snmpd-conf.sh" default > "$configDir/snmpd.conf"; }
    usmReports=1
    # Its access control refuses a user or Community that only reads before it looks at the
    # object, so the read-only SET is noAccess whether or not the object is writable.
    setRefusal=noAccess
    fetch() { docker build -q -t "$image" -f "$here/snmpd.Dockerfile" "$here"; }
    # A real request, through the published port, from the same image so the workstation needs no
    # SNMP tools. The port alone proves nothing: the runtime listens on it from the moment it
    # publishes it, whether the Agent behind it is up or not.
    answers() {
      docker run --rm --network host --entrypoint snmpget "$image" \
        -v2c -c public -r 0 -t 1 "127.0.0.1:$port" 1.3.6.1.2.1.1.1.0
    }
    ;;
  simulator)  # sha-b300f60: no authoritative-side timeliness check
    useSimulator ghcr.io/lcmscheid/snmp-fault-agent@sha256:f66982cf07e3290d3a9e054e60539a2d82810648f11fd94e48cf5ee8eb89a158
    ;;
  simulator-release)  # 0.1.0
    useSimulator ghcr.io/lcmscheid/snmp-fault-agent@sha256:78d0abcd7eeba46fd5f7fbef987208ff745f63a72cd416289d8316bf60a6a144
    faultsEngineId=1
    ;;
  *) usage ;;
esac

# Whatever stops this script short of an answering Agent -- a failed build or pull, a port already
# taken, an Agent that never answers -- ends here with the Agent's log, or with the reason there is
# none. Docker's own error, if it had one, is already on stderr above. A container the runtime
# created but could not start, as over a port already taken, has run nothing and logged nothing.
failed() {
  case $(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null) in
    '' | created) echo "$agent never started, so it has no log" >&2 ;;
    *)
      echo "$agent is not answering; its log follows" >&2
      docker logs "$container" >&2
      ;;
  esac
}
trap 'status=$?; [ $status -eq 0 ] || failed' EXIT

# The configuration is generated on every start, into a directory the container mounts, because
# the password is only known now. It is rewritten each time rather than cleaned up: the container
# reads it for as long as it runs.
configDir=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/snmpio-interop
mkdir -p "$configDir"

docker rm -f "$container" >/dev/null 2>&1 || true
fetch >&2
(export SNMPIO_INTEROP_V3_PASSWORD="$password"; configure)
# The Simulator's image carries its own example configuration; ours is mounted over it so the
# suite's `auth<hash>` / `priv<hash><cipher>` convention holds against every Agent here and there
# is no second table saying the same thing, and so it serves the Subtree the Walk tests need.
# `z` relabels each file for an SELinux host, and is ignored elsewhere. The -v options are built
# up in the positional parameters, the one array POSIX sh has -- `set --` clears the script's own
# argument, which is safe only because it was read into $agent above.
set --
for mount in $mounts; do
  set -- "$@" -v "$configDir/${mount##*/}:$mount:ro,z"
done
docker run -d --name "$container" -p "127.0.0.1:$port:1161/udp" \
  ${faults:+-p "127.0.0.1:$faultsPort:$simulatorUiPort"} \
  "$@" "$image" >&2

# Up to 30 seconds, or not at all once the Agent has exited. A deadline rather than a count of
# tries, because one `snmpget` readiness check is itself a container start.
deadline=$(($(date +%s) + 30))
until answers >/dev/null 2>&1; do
  [ "$(date +%s)" -lt "$deadline" ] || exit 1
  [ "$(docker inspect -f '{{.State.Running}}' "$container")" = true ] || exit 1
  sleep 0.5
done

echo "$agent is answering on 127.0.0.1:$port" >&2
cat <<ENV
SNMPIO_INTEROP_TARGET=127.0.0.1
SNMPIO_INTEROP_PORT=$port
SNMPIO_INTEROP_V3_PASSWORD=$password
SNMPIO_INTEROP_V3_USM_REPORTS=$usmReports
SNMPIO_INTEROP_V3_KEY_EXTENSIONS=$keyExtensions
SNMPIO_INTEROP_FAULTS=$faults
SNMPIO_INTEROP_FAULTS_ENGINE_ID=$faultsEngineId
SNMPIO_INTEROP_BROKEN_GETNEXT=$brokenGetNext
SNMPIO_INTEROP_SET_REFUSAL=$setRefusal
SNMPIO_INTEROP_WRITER_COMMUNITY=$writerCommunity
SNMPIO_INTEROP_WRITER_NOAUTHNOPRIV=$writerNoAuth
SNMPIO_INTEROP_WRITER_AUTHNOPRIV=$writerAuth
SNMPIO_INTEROP_WRITER_AUTHPRIV=$writerPriv
ENV
