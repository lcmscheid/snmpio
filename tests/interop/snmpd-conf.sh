#!/bin/sh
# Prints the snmpd configuration the interop suite expects, to stdout.
#
#   tests/interop/snmpd-conf.sh [source]
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
# The writers are the only identities here that can write, and each reaches `system.sysContact`
# alone: `snmpio-writer`, a Community, and one user per Security Level on the representative pair,
# named after what it carries as the convention's users are. The SET tests address them only
# because tests/interop/start-agent.sh names them in the environment -- every other user and
# Community is read-only, which is what makes a SET with one of them the refused case for free.
# sysContact.0 is left unset below on purpose: net-snmp makes an object read-only when its
# configuration sets it.
#
# The password arrives in the environment rather than in this file: one value configures the Agent
# and drives the suite, so the two cannot drift.
#
# The Communities answer 127.0.0.1 alone unless `source` says otherwise, in net-snmp's spelling --
# `default` is any. tests/interop/start-agent.sh says `default`, and why; an `snmpd` run from this
# configuration anywhere else answers `public` to nobody but the machine it runs on.
set -eu

: "${SNMPIO_INTEROP_V3_PASSWORD:?set it to the password every interop user gets (8+ characters)}"
communitySource=${1:-127.0.0.1}
sysContact=.1.3.6.1.2.1.1.4

cat <<CONF
rocommunity public $communitySource
rocommunity netops-ro $communitySource
sysDescr snmpio interop Agent

createUser noauth
rouser noauth noauth

createUser netops-legacy SHA-256 "$SNMPIO_INTEROP_V3_PASSWORD" AES "$SNMPIO_INTEROP_V3_PASSWORD"
rouser netops-legacy priv

rwcommunity snmpio-writer $communitySource $sysContact
createUser writer-noauth
rwuser writer-noauth noauth $sysContact
createUser writer-authsha256 SHA-256 "$SNMPIO_INTEROP_V3_PASSWORD"
rwuser writer-authsha256 auth $sysContact
createUser writer-privsha256aes SHA-256 "$SNMPIO_INTEROP_V3_PASSWORD" AES "$SNMPIO_INTEROP_V3_PASSWORD"
rwuser writer-privsha256aes priv $sysContact
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
# states. The stock snmpd speaks all four (ADR-0006), spelled as the Simulator spells them, so ours
# is net-snmp's spelling in lower case and there is no pair to write down.
for netsnmp in AES192 AES256 AES192C AES256C; do
  ours=$(printf %s "$netsnmp" | tr '[:upper:]' '[:lower:]')
  cat <<CONF
createUser privsha1${ours} SHA "$SNMPIO_INTEROP_V3_PASSWORD" $netsnmp "$SNMPIO_INTEROP_V3_PASSWORD"
rouser privsha1${ours} priv
CONF
done
