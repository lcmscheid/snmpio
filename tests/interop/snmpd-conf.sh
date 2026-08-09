#!/bin/sh
# Prints the snmpd configuration the interop suite expects, to stdout.
#
# The v3 users are a convention shared with tests/TestInteropV3.cpp: one per auth protocol at
# authNoPriv, and one per (auth, privacy) pair at authPriv, named after what they carry. They are
# ours to create, which is why the suite can name them. An Agent running someone else's
# configuration is addressed the other way in -- SNMPIO_INTEROP_V3_USER names the one user it has,
# and the matrix covers the pair that user serves.
#
# The password arrives in the environment rather than in this file: one value configures the Agent
# and drives the suite, so the two cannot drift.
set -eu

: "${SNMPIO_INTEROP_V3_PASSWORD:?set it to the password every interop user gets (8+ characters)}"

cat <<CONF
rocommunity public 127.0.0.1
sysDescr snmpio interop Agent

createUser noauth
rouser noauth noauth
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
