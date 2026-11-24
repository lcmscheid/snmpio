#!/usr/bin/env bash
# hardening-reached.sh BUILD [FLAG...]: a build with SNMPIO_HARDENING on carries the whole set, on
# every compile and link line of ours and in the binaries -- and each FLAG besides on every compile
# line, as the libcxx job asks of -stdlib=libc++.
#
# The binaries are the test executables, and libsnmpio.so in a shared build. A shared build's
# tests link their own static copy of the library (tests/CMakeLists.txt), whose compile lines are
# under src/ like the library's and so checked with them.
#
# A flag that stopped reaching the build would leave CI green: Ubuntu's GCC fortifies and protects
# the stack by default, so the binaries would look much the same.
# CompilerHardening.FortifySourceStopsAnOverflowingCopy is what fails if _FORTIFY_SOURCE is on the
# line and not honoured.
set -euo pipefail
source "$(dirname "$0")/hardening-lib.sh"

build=${1:?usage: hardening-reached.sh BUILD [FLAG...]}
shift

read_hardening_lists "$build"
compile_lines_carry "$build/compile_commands.json" src tests -- "${COMPILE[@]}" "$@"
link_lines_carry "$build" "${LINK[@]}"
find_files "$build/tests" -executable -name 'snmpio_*'
binaries=("${FILES[@]}")
find_files "$build" -name 'libsnmpio.so*'
elf_hardened "${binaries[@]}" "${FILES[@]}"
echo "every compile and link line of ours carries all $((${#COMPILE[@]} + $#)) + ${#LINK[@]} flags"
