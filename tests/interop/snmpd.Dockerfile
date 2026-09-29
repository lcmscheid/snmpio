# The interop suite's `snmpd`: the distribution's own package, not one built here, since the point
# of this Agent is a reading of the protocol nobody here made. Ubuntu's is built with
# `--enable-blumenthal-aes`, so it speaks both Key Extensions (ADR-0006).
#
# Both pins are what fixes the `snmpd` version: the base by digest, and the archive by snapshot, so
# a security update to noble cannot change what a commit was tested against between two runs of
# it. Moving either is a commit here. `docker buildx imagetools inspect ubuntu:24.04` prints the
# current base; any later timestamp is a valid snapshot.
#
# The configuration is not baked in. tests/interop/start-agent.sh generates it with the password
# from the environment and mounts it, the same way it hands the Simulator its auth.json.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

# The snapshot archive is HTTPS only, and the base carries no certificates, so those come first and
# from the live archive: they are a trust store, not a part of what is under test. `--error-on=any`
# because apt otherwise warns about an unreachable snapshot and installs from whatever lists it
# has, which is a build that looks pinned and is not.
#
# `snmp` is the client tools: the start-up script's readiness check is an `snmpget` from this image,
# so a workstation needs nothing installed but a container runtime.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && apt-get update --snapshot 20260929T000000Z --error-on=any \
    && apt-get install -y --no-install-recommends snmpd snmp \
    && rm -rf /var/lib/apt/lists/*

# 1161 inside, as the Simulator uses, so both publish the same way.
EXPOSE 1161/udp
ENTRYPOINT ["/usr/sbin/snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmpio/snmpd.conf", "udp:1161"]
