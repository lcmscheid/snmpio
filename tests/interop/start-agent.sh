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
export SNMPIO_INTEROP_V3_PASSWORD="${SNMPIO_INTEROP_V3_PASSWORD:-snmpio-interop}"
# The Simulator's control UI listens on 8080 inside its image; faultsPort is where it is published.
simulatorUiPort=8080
faultsPort=8080

# Only `snmpd` answers a bad digest with the usmStats Report RFC 3414 leaves optional. Every Agent
# here speaks AES-192/256 under both Key Extensions, so that flag does not tell them apart, but it
# is set on each: it says what an Agent is, and a Target outside CI may not be one.
usmReports='' keyExtensions=1 faults='' faultsEngineId=''

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
# mounted, and how to tell it is answering.
useSimulator() {
  image=$1
  mount=/etc/snmpfault/auth.json
  configure() { "$here/fault-agent-auth.sh"; }
  faults=$faultsPort
  fetch() { docker pull -q "$image"; }
  # The control UI and the SNMP socket come up in the same process, and the UI answers over TCP --
  # so a connection to it is the readiness check.
  answers() { curl -fsS -o /dev/null "http://127.0.0.1:$faultsPort/"; }
}
case $agent in
  snmpd)
    image=snmpio-interop-snmpd
    mount=/etc/snmpio/snmpd.conf
    # `default` is any source. A request through the published port arrives from the runtime's
    # gateway rather than from 127.0.0.1, and the port is published on the loopback alone, which is
    # the restriction.
    configure() { "$here/snmpd-conf.sh" default; }
    usmReports=1
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
# none. Docker's own error, if it had one, is already on stderr above.
failed() {
  if docker inspect "$container" >/dev/null 2>&1; then
    echo "$agent is not answering; its log follows" >&2
    docker logs "$container" >&2
  else
    echo "$agent never started, so it has no log" >&2
  fi
}
trap 'status=$?; [ $status -eq 0 ] || failed' EXIT

# The configuration is generated on every start, into a directory the container mounts, because
# the password is only known now. It is rewritten each time rather than cleaned up: the container
# reads it for as long as it runs.
configDir=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/snmpio-interop
mkdir -p "$configDir"
configFile=$configDir/${mount##*/}

docker rm -f "$container" >/dev/null 2>&1 || true
fetch >&2
configure > "$configFile"
# The Simulator's image carries its own example configuration; ours is mounted over it so the
# suite's `auth<hash>` / `priv<hash><cipher>` convention holds against every Agent here and there
# is no second table saying the same thing. `z` relabels it for an SELinux host, and is ignored
# elsewhere.
docker run -d --name "$container" -p "127.0.0.1:$port:1161/udp" \
  ${faults:+-p "127.0.0.1:$faults:$simulatorUiPort"} \
  -v "$configFile:$mount:ro,z" "$image" >&2

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
SNMPIO_INTEROP_V3_PASSWORD=$SNMPIO_INTEROP_V3_PASSWORD
SNMPIO_INTEROP_V3_USM_REPORTS=$usmReports
SNMPIO_INTEROP_V3_KEY_EXTENSIONS=$keyExtensions
SNMPIO_INTEROP_FAULTS=$faults
SNMPIO_INTEROP_FAULTS_ENGINE_ID=$faultsEngineId
ENV
