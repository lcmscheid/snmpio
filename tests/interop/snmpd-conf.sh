#!/bin/sh
# Prints the snmpd configuration the interop suite expects, to stdout.
#
# The v3 users are a convention shared with tests/TestInteropV3.cpp: one per auth protocol at
# authNoPriv, one per (auth, privacy) pair at authPriv, and the four Key Extension users, all
# named after what they carry. They are ours to create, which is why the suite can name them. An
# Agent running someone else's configuration is addressed the other way in --
# SNMPIO_INTEROP_V3_USER names the one user it has, and the matrix covers the pair that user
# serves.
#
# `netops-legacy` below is that second way in, made reachable without a switch on the bench: one
# user whose name says nothing about what it carries, which is what a Target we did not configure
# looks like. No run addresses it unless SNMPIO_INTEROP_V3_USER asks for it by name, so the
# convention path over this Agent is the run it always was. `netops-ro` is the same for v2c: a
# Community other than `public`, used only when SNMPIO_INTEROP_COMMUNITY names it.
#
# The password arrives in the environment rather than in this file: one value configures the Agent
# and drives the suite, so the two cannot drift.
set -eu

: "${SNMPIO_INTEROP_V3_PASSWORD:?set it to the password every interop user gets (8+ characters)}"

cat <<CONF
rocommunity public 127.0.0.1
rocommunity netops-ro 127.0.0.1
sysDescr snmpio interop Agent

createUser noauth
rouser noauth noauth

createUser netops-legacy SHA-256 "$SNMPIO_INTEROP_V3_PASSWORD" AES "$SNMPIO_INTEROP_V3_PASSWORD"
rouser netops-legacy priv
CONF

# net-snmp's spelling on the left of each pair, ours on the right. SHA-1 is plain "SHA" to
# net-snmp; everything else differs only by the hyphen it does not use in a user name.
for pair in MD5:md5 SHA:sha1 SHA-224:sha224 SHA-256:sha256 SHA-384:sha384 SHA-512:sha512; do
  netsnmp=${pair%:*}
  ours=${pair#*:}
  cat <<CONF
createUser auth$ours $netsnmp "$SNMPIO_INTEROP_V3_PASSWORD"
rouser auth$ours auth
createUser priv${ours}des $netsnmp "$SNMPIO_INTEROP_V3_PASSWORD" DES "$SNMPIO_INTEROP_V3_PASSWORD"
rouser priv${ours}des priv
createUser priv${ours}aes $netsnmp "$SNMPIO_INTEROP_V3_PASSWORD" AES "$SNMPIO_INTEROP_V3_PASSWORD"
rouser priv${ours}aes priv
CONF
done

# The Key Extension users, named and paired exactly as tests/interop/fault-agent-auth.sh names the
# Simulator's: SHA-1 for all four, for the reason tests/TestInteropV3.cpp's CoversBothKeyExtensions
# states. Debian's net-snmp speaks both schemes (ADR-0006), under the same `C` suffix for Reeder.
for pair in aes192:AES192 aes256:AES256 aes192c:AES192C aes256c:AES256C; do
  ours=${pair%:*}
  netsnmp=${pair#*:}
  cat <<CONF
createUser privsha1$ours SHA "$SNMPIO_INTEROP_V3_PASSWORD" $netsnmp "$SNMPIO_INTEROP_V3_PASSWORD"
rouser privsha1$ours priv
CONF
done
