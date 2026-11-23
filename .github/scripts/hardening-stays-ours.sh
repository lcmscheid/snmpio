#!/usr/bin/env bash
# hardening-stays-ours.sh LIBRARY CONSUMER PREFIX: snmpio, built in LIBRARY with SNMPIO_HARDENING
# on and installed into PREFIX, carried the whole set, and CONSUMER -- the examples, built against
# the installed package -- carries none of it.
#
# Hardening is PRIVATE to our own targets: choosing it for a consumer would be choosing their build
# flags. That is standard-library hardening, on in every build, and the OpenSSF set. So a consumer
# must see neither on a compile line, on a link line (build.ninja's), or in the installed CMake
# files. The library's compile lines are checked first, so that there was something to leak.
#
# The library is static, as in the package job. Its PRIVATE link options then reach no one, which
# is the point: the mistake this catches is the one that exports them -- a list made PUBLIC or
# INTERFACE, or moved onto an INTERFACE target -- and a static library exports those to every
# consumer's link line just as a shared one would. The hardened job checks the shared library's own
# link line, since its consumers cannot link it yet.
set -euo pipefail
source "$(dirname "$0")/hardening-lib.sh"

usage='usage: hardening-stays-ours.sh LIBRARY CONSUMER PREFIX'
library=${1:?$usage}
consumer=${2:?$usage}
prefix=${3:?$usage}

read_hardening_lists "$library"
compile_lines_carry "$library/compile_commands.json" src -- "${COMPILE[@]}"

shopt -s nullglob
installed=("$prefix"/lib*/cmake/snmpio/*.cmake)
shopt -u nullglob
[ "${#installed[@]}" -gt 0 ] || { echo "nothing to check: no CMake files under $prefix"; exit 1; }
absent "${COMPILE[@]}" "${LINK[@]}" -- \
  "$consumer/compile_commands.json" "$consumer/build.ninja" "${installed[@]}"
echo "none of ${#COMPILE[@]} + ${#LINK[@]} flags reached the consumer"
