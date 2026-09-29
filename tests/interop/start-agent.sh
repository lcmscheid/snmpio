#!/bin/sh
# Starts one interop Agent in a container on the loopback port, waits until it answers, and prints
# the environment the interop suite needs for it, to stdout.
#
#   tests/interop/start-agent.sh snmpd | simulator | simulator-release
#
# CI's interop jobs and a workstation run exactly this, so a CI failure is one command away from
# being reproduced. The output is `NAME=value` lines -- what $GITHUB_ENV takes as-is, and what
# `export $(tests/interop/start-agent.sh snmpd)` applies in bash, zsh and fish alike. Everything
# else, the container runtime's included, goes to stderr.
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
faultsPort=8080
password=${SNMPIO_INTEROP_V3_PASSWORD:-snmpio-interop}

# Only `snmpd` answers a bad digest with the usmStats Report RFC 3414 leaves optional. Every Agent
# here speaks AES-192/256 under both Key Extensions, so that flag does not tell them apart, but it
# is set on each: it says what an Agent is, and a Target outside CI may not be one.
usmReports='' keyExtensions=1 faults='' faultsEngineId=''

# The Simulators are pinned by digest rather than by tag, so a push to the Simulator's own repo
# cannot change what this library was tested against between two runs of the same commit. Moving a
# pin is a commit here, which is where a Simulator change that breaks us becomes visible.
# `docker buildx imagetools inspect ghcr.io/lcmscheid/snmp-fault-agent:latest` prints the current
# one. `snmpd`'s pins are in snmpd.Dockerfile, beside this.
#
# Two Simulators, and the older one is not redundant. `simulator` answers a request whose
# boots/time it disagrees with by stamping its own pair into an ordinary Response;
# `simulator-release` grew the authoritative-side check and sends the usmStats Report instead,
# which is what a compliant Agent does. Only the first shape reaches the Command Generator's own
# timeliness comparison -- it was a Response of exactly that kind that caught this Client reading
# RFC 3414 section 3.2 step 7a where 7b applies, and the release image passes that bug in silence.
case $agent in
  snmpd)
    image=snmpio-interop-snmpd
    usmReports=1
    ;;
  simulator)  # sha-b300f60: no authoritative-side timeliness check
    image=ghcr.io/lcmscheid/snmp-fault-agent@sha256:f66982cf07e3290d3a9e054e60539a2d82810648f11fd94e48cf5ee8eb89a158
    faults=$faultsPort
    ;;
  simulator-release)  # 0.1.0
    image=ghcr.io/lcmscheid/snmp-fault-agent@sha256:78d0abcd7eeba46fd5f7fbef987208ff745f63a72cd416289d8316bf60a6a144
    faults=$faultsPort
    faultsEngineId=1
    ;;
  *) usage ;;
esac

# The configuration is generated on every start, into a directory the container mounts, because
# the password is only known now. It is rewritten each time rather than cleaned up: the container
# reads it for as long as it runs.
config=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/snmpio-interop
mkdir -p "$config"

docker rm -f "$container" >/dev/null 2>&1 || true

# Waits up to 30 seconds for `$1` to succeed, and fails with the Agent's log if it never does -- or
# at once, if the Agent has already exited. A deadline rather than a count of tries, because one
# `snmpget` readiness check is itself a container start.
waitFor() {
  deadline=$(($(date +%s) + 30))
  until sh -c "$1" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ] \
      || [ "$(docker inspect -f '{{.State.Running}}' "$container")" != true ]
    then
      echo "$agent never answered; its log follows" >&2
      docker logs "$container" >&2
      exit 1
    fi
    sleep 0.5
  done
}

if [ "$agent" = snmpd ]; then
  docker build -q -t "$image" -f "$here/snmpd.Dockerfile" "$here" >&2
  SNMPIO_INTEROP_V3_PASSWORD=$password "$here/snmpd-conf.sh" > "$config/snmpd.conf"
  docker run -d --name "$container" -p "127.0.0.1:$port:1161/udp" \
    -v "$config/snmpd.conf:/etc/snmpio/snmpd.conf:ro" "$image" >&2
  # A real request, through the published port, from the same image so the workstation needs no SNMP
  # tools. The port alone proves nothing: the runtime listens on it from the moment it publishes
  # it, whether the Agent behind it is up or not.
  waitFor "docker run --rm --network host --entrypoint snmpget $image \
    -v2c -c public -r 0 -t 1 127.0.0.1:$port 1.3.6.1.2.1.1.1.0"
else
  # The image carries its own example configuration, whose users are named for the Simulator's
  # purposes. Ours is mounted over it so the suite's `auth<hash>` / `priv<hash><cipher>` convention
  # holds against every Agent here and there is no second table saying the same thing.
  docker pull -q "$image" >&2
  SNMPIO_INTEROP_V3_PASSWORD=$password "$here/fault-agent-auth.sh" > "$config/auth.json"
  docker run -d --name "$container" \
    -p "127.0.0.1:$port:1161/udp" -p "127.0.0.1:$faultsPort:8080" \
    -v "$config/auth.json:/etc/snmpfault/auth.json:ro" "$image" >&2
  # The control UI and the SNMP socket come up in the same process, and the UI answers over TCP --
  # so a connection to it is the readiness check.
  waitFor "curl -fsS -o /dev/null http://127.0.0.1:$faultsPort/"
fi

echo "$agent is answering on 127.0.0.1:$port" >&2
cat <<ENV
SNMPIO_INTEROP_TARGET=127.0.0.1
SNMPIO_INTEROP_PORT=$port
SNMPIO_INTEROP_V3_PASSWORD=$password
SNMPIO_INTEROP_V3_USM_REPORTS=$usmReports
SNMPIO_INTEROP_V3_KEY_EXTENSIONS=$keyExtensions
SNMPIO_INTEROP_FAULTS=$faults
SNMPIO_INTEROP_FAULTS_ENGINE_ID=$faultsEngineId
ENV
