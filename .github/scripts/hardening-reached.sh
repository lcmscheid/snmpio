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

dirs=(src tests)
if [ "${1:-}" = --library-only ]; then
  dirs=(src)
  shift
fi
build=${1:?usage: hardening-reached.sh [--library-only] BUILD [FLAG...]}
shift

read_hardening_lists "$build"
compile_lines_carry "$build/compile_commands.json" "${dirs[@]}" -- "${COMPILE[@]}" "$@"
link_lines_carry "$build" "${LINK[@]}"
binaries=()
if [ "${#dirs[@]}" -gt 1 ]; then
  find_files "$build/tests" -executable -name 'snmpio_*'
  binaries=("${FILES[@]}")
fi
find_files "$build" -name 'libsnmpio.so*'
elf_hardened "${binaries[@]}" "${FILES[@]}"
echo "every compile and link line of ours carries all $((${#COMPILE[@]} + $#)) + ${#LINK[@]} flags"
