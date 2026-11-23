#!/usr/bin/env bash
# hardening-reached.sh [--library-only] BUILD [FLAG...]: a build with SNMPIO_HARDENING on carries
# the whole set, on every compile and link line of ours and in the binaries -- and each FLAG
# besides on every compile line, as the libcxx job asks of -stdlib=libc++.
#
# The binaries are the test executables, and libsnmpio.so in a shared build. --library-only is for
# a build without the tests, which must then be a shared one: a static archive has no link line,
# so there would be nothing of the linker's half to check.
#
# A flag that stopped reaching the build would leave CI green: Ubuntu's GCC fortifies and protects
# the stack by default, so the binaries would look much the same.
# CompilerHardening.FortifySourceStopsAnOverflowingCopy is what fails if _FORTIFY_SOURCE is on the
# line and not honoured.
set -euo pipefail
source "$(dirname "$0")/hardening-lib.sh"

usage='usage: hardening-reached.sh [--library-only] BUILD [FLAG...]'
dirs="src tests"
if [ "${1:-}" = --library-only ]; then
  dirs="src"
  shift
fi
build=${1:?$usage}
shift

read_flags "$build/hardening/compile-flags.txt"
compile=("${FLAGS[@]}" "$@")
read_flags "$build/hardening/link-flags.txt"
link=("${FLAGS[@]}")

# The lists are what the checks below check against, so an emptied or broken list would pass them
# having checked nothing. A flag from each half, and the x86_64 row where this is x86_64, must be
# there.
required=(-D_GLIBCXX_ASSERTIONS -D_FORTIFY_SOURCE=3 -Wl,-z,now)
[ "$(uname -m)" = x86_64 ] && required+=(-fcf-protection=full)
for flag in "${required[@]}"; do
  printf '%s\n' "${compile[@]}" "${link[@]}" | grep -qxF -e "$flag" \
    || { echo "$build/hardening/ does not list $flag: is SNMPIO_HARDENING on?"; exit 1; }
done

compile_lines_carry "$build/compile_commands.json" "$dirs" "${compile[@]}"
link_lines_carry "$build/build.ninja" "${link[@]}"
binaries=()
[ "$dirs" = src ] \
  || mapfile -t binaries < <(find "$build/tests" -maxdepth 1 -type f -executable -name 'snmpio_*')
mapfile -t -O "${#binaries[@]}" binaries \
  < <(find "$build" -maxdepth 1 -type f -name 'libsnmpio.so*')
elf_hardened "${binaries[@]}"
echo "every compile and link line of ours carries all ${#compile[@]} + ${#link[@]} flags"
