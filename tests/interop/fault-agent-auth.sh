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
  netsnmp=${pair%:*}
  ours=${pair#*:}
  user "auth$ours" "$netsnmp"
  user "priv${ours}des" "$netsnmp" DES
  user "priv${ours}aes" "$netsnmp" AES
done

# The Key Extension users. SHA-1 for all four, for the reason tests/TestInteropV3.cpp's
# CoversBothKeyExtensions states.
for pair in aes192:AES192 aes256:AES256 aes192c:AES192C aes256c:AES256C; do
  user "privsha1${pair%:*}" SHA "${pair#*:}"
done

printf '\n  ]\n}\n'
