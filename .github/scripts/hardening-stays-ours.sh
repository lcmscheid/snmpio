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

library=${1:?usage: hardening-stays-ours.sh LIBRARY CONSUMER PREFIX}
consumer=${2:?usage: hardening-stays-ours.sh LIBRARY CONSUMER PREFIX}
prefix=${3:?usage: hardening-stays-ours.sh LIBRARY CONSUMER PREFIX}

read_flags "$library/hardening/compile-flags.txt"
compile=("${FLAGS[@]}")
read_flags "$library/hardening/link-flags.txt"
link=("${FLAGS[@]}")
# An emptied list would find nothing and pass, so a flag from each half must be there.
for flag in -D_GLIBCXX_ASSERTIONS -D_FORTIFY_SOURCE=3 -Wl,-z,now; do
  printf '%s\n' "${compile[@]}" "${link[@]}" | grep -qxF -e "$flag" \
    || { echo "$library/hardening/ does not list $flag: is SNMPIO_HARDENING on?"; exit 1; }
done

compile_lines_carry "$library/compile_commands.json" "src" "${compile[@]}"

shopt -s nullglob
installed=("$prefix"/lib*/cmake/snmpio/*.cmake)
shopt -u nullglob
[ "${#installed[@]}" -gt 0 ] || { echo "nothing to check: no CMake files under $prefix"; exit 1; }
absent "${compile[@]}" "${link[@]}" -- \
  "$consumer/compile_commands.json" "$consumer/build.ninja" "${installed[@]}"
echo "none of ${#compile[@]} + ${#link[@]} flags reached the consumer"
