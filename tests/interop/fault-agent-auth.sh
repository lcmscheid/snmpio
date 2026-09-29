#!/bin/sh
# Prints the Simulator's auth.json for the interop suite, to stdout.
#
# Mounted over /etc/snmpfault/auth.json so the users are ours to name, the same convention
# tests/interop/snmpd-conf.sh and tests/TestInteropV3.cpp share: `noauth`, `auth<hash>` per
# authentication protocol, and `priv<hash><cipher>` per pair. The Simulator's own example
# configuration names them differently, and a suite that followed it would need a second table
# saying the same thing twice.
#
# The password arrives in the environment rather than in this file: one value configures the Agent
# and drives the suite, so the two cannot drift.
set -eu

: "${SNMPIO_INTEROP_V3_PASSWORD:?set it to the password every interop user gets (8+ characters)}"

user() {  # user <name> <authProtocol> [privProtocol]
  printf ',\n    {"username": "%s", "authProtocol": "%s", "authPassphrase": "%s"' \
    "$1" "$2" "$SNMPIO_INTEROP_V3_PASSWORD"
  [ $# -eq 3 ] && printf ', "privProtocol": "%s", "privPassphrase": "%s"' \
    "$3" "$SNMPIO_INTEROP_V3_PASSWORD"
  printf '}'
}

# `community` is the v2c community, and `public` is what the v2c half of the suite sends.
printf '{\n  "community": "public",\n  "users": [\n    {"username": "noauth"}'

# The Simulator's spelling on the left of each pair, ours on the right.
for pair in MD5:md5 SHA:sha1 SHA224:sha224 SHA256:sha256 SHA384:sha384 SHA512:sha512; do
  theirs=${pair%:*}
  ours=${pair#*:}
  user "auth$ours" "$theirs"
  user "priv${ours}des" "$theirs" DES
  user "priv${ours}aes" "$theirs" AES
done

# The Key Extension users. SHA-1 for all four, for the reason tests/TestInteropV3.cpp's
# CoversBothKeyExtensions states. Ours is the Simulator's spelling in lower case.
for theirs in AES192 AES256 AES192C AES256C; do
  ours=$(printf %s "$theirs" | tr '[:upper:]' '[:lower:]')
  user "privsha1${ours}" SHA "$theirs"
done

# The writers, named as tests/interop/snmpd-conf.sh names its own so one set of names addresses
# both Agents. The Simulator has no per-user access control, so these are ordinary users -- any
# user here can write sysContact.0, the one entry tests/interop/fault-agent-values.sh leaves
# writable -- but it infers the Security Level from the protocols a user carries (ADR-0006), so
# each carries exactly the level its name says, or the test that names that level would not be
# testing it. The v2c writer is `public`: the Simulator has one Community.
printf ',\n    {"username": "writer-noauth"}'
user writer-authsha256 SHA256
user writer-privsha256aes SHA256 AES

printf '\n  ]\n}\n'
