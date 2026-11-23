# Sourced by hardening-reached.sh and hardening-stays-ours.sh; not run on its own.
#
# The flags come from the lists CMakeLists.txt writes into the build directory (hardening/), so
# that the set is written down once. Each check prints what it found wrong and returns 1, and the
# callers run under `set -euo pipefail`: a jq, awk or readelf that fails outright fails the step
# rather than passing on output it never printed.

# read_flags FILE: the flags in FILE, one per line, into the array FLAGS. Blank lines are skipped;
# a missing or unreadable file is an error, not an empty list.
read_flags() {
  [ -r "$1" ] || { echo "no readable $1: was the build configured?"; return 1; }
  FLAGS=()
  local flag
  while IFS= read -r flag; do
    [ -n "$flag" ] && FLAGS+=("$flag")
  done <"$1"
  return 0
}

# compile_lines_carry COMMANDS DIRS FLAG...: every compile line in COMMANDS
# (compile_commands.json) whose source file is under one of DIRS (space-separated, relative to
# $PWD) carries every FLAG as a whole word -- -Wformat is not found in -Wformat=2. A line is ours
# by where its file is, not by what it mentions: every test line names GoogleTest's include path.
# Each of DIRS must have a line, so the check cannot pass by having filtered everything away.
compile_lines_carry() {
  local commands=$1 dirs=$2
  shift 2
  jq empty "$commands" || { echo "no readable $commands"; return 1; }
  local problems
  problems=$(jq -r --arg root "$PWD/" \
      --argjson dirs "$(printf '%s\n' $dirs | jq -R . | jq -s .)" \
      --argjson flags "$(printf '%s\n' "$@" | jq -R . | jq -s .)" '
    [.[] | .file as $file | select($dirs | any(. as $dir | $file | startswith($root + $dir + "/")))]
      as $ours
    | ($dirs[] | . as $dir
        | select($ours | any(.file | startswith($root + $dir + "/")) | not)
        | "no compile line of ours under \($dir)/"),
      ($ours[] | .file as $file | (.command | split(" ")) as $words
        | $flags[] | select(IN($words[]) | not)
        | "\($file) was compiled without \(.)")' "$commands")
  [ -z "$problems" ] || { echo "$problems"; return 1; }
}

# link_lines_carry NINJA FLAG...: every executable or shared library of ours that NINJA
# (build.ninja) links passes every FLAG to the linker. Ours are the targets named snmpio*; a static
# archive is not linked, so it has no link line to check. There must be at least one.
#
# The FLAGs are -Wl, options. CMake spells a LINKER: option for the compiler at hand -- -Wl,-z,now
# for GCC, -Xlinker -z -Xlinker now for Clang -- so both sides are compared as what the linker
# receives: the words -Wl, splits on its commas, and each word after an -Xlinker.
link_lines_carry() {
  local ninja=$1
  shift
  [ -r "$ninja" ] || { echo "no readable $ninja"; return 1; }
  awk -v wanted="$*" '
    # The linker words on a command line, space-joined and space-framed.
    function linkerWords(line,   n, i, words, parts, out) {
      out = " "
      n = split(line, words, " ")
      for (i = 1; i <= n; i++) {
        if (words[i] ~ /^-Wl,/) {
          gsub(/,/, " ", words[i])
          out = out substr(words[i], 5) " "
        } else if (words[i] == "-Xlinker" && i < n) {
          out = out words[++i] " "
        }
      }
      return out
    }
    function finish(   i, have) {
      if (!target) return
      links++
      have = linkerWords(linkFlags)
      for (i = 1; i <= count; i++)
        if (!index(have, linkerWords(want[i]))) {
          print target " was linked without " want[i]; bad = 1
        }
      target = ""
    }
    BEGIN { count = split(wanted, want, " ") }
    /^[^ ]/ { finish() }
    /^build .*: CXX_(EXECUTABLE|SHARED_LIBRARY)_LINKER__snmpio/ {
      target = $2; linkFlags = ""; next
    }
    target && /^  LINK_FLAGS = / { linkFlags = substr($0, length("  LINK_FLAGS = ") + 1) }
    target && /^  TARGET_FILE = / { target = substr($0, length("  TARGET_FILE = ") + 1) }
    END {
      finish()
      if (!links) { print "no executable or shared library of ours in " FILENAME; bad = 1 }
      exit bad
    }' "$ninja"
}

# elf_hardened FILE...: the linker's half, read back off each binary. Bind-now is the one property
# that shows -z now worked: Ubuntu's linker emits RELRO and a non-executable stack whatever it is
# asked, so those two are read back only so that a binary worse than the default fails. -z nodlopen
# marks shared objects only (NOOPEN), so it is required of them and not of executables -- a PIE is
# a shared object too, told apart by its PIE flag. --as-needed and --no-copy-dt-needed-entries
# leave nothing in the binary to read; link_lines_carry is their check.
elf_hardened() {
  local binary dynamic segments stack
  [ "$#" -gt 0 ] || { echo "no binaries to check"; return 1; }
  for binary in "$@"; do
    dynamic=$(readelf -dW "$binary")
    segments=$(readelf -lW "$binary")
    grep -q 'BIND_NOW' <<<"$dynamic" || { echo "$binary is not bind-now"; return 1; }
    grep -q 'GNU_RELRO' <<<"$segments" || { echo "$binary has no RELRO"; return 1; }
    stack=$(grep 'GNU_STACK' <<<"$segments") || { echo "$binary has no GNU_STACK"; return 1; }
    if grep -q 'RWE' <<<"$stack"; then echo "$binary has an executable stack"; return 1; fi
    if grep -q 'Shared object file' <<<"$(readelf -hW "$binary")" \
        && ! grep -q 'FLAGS_1.*PIE' <<<"$dynamic"; then
      grep -q 'FLAGS_1.*NOOPEN' <<<"$dynamic" || { echo "$binary is dlopen-able"; return 1; }
    fi
  done
}

# absent FLAG... -- FILE...: no FLAG appears in any FILE, as a word. A macro (-D or -U) is looked
# for by its name, which is how an installed CMake file would carry it. A linker option is looked
# for by what follows -Wl, -- which is also how LINKER: would carry it -- and in Clang's -Xlinker
# spelling (link_lines_carry says why there are two). A missing FILE is an error: it proves nothing.
absent() {
  local flags=() files=() flag needle payload found=0
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do flags+=("$1"); shift; done
  shift
  files=("$@")
  [ "${#files[@]}" -gt 0 ] || { echo "no files to check"; return 1; }
  for file in "${files[@]}"; do
    [ -r "$file" ] || { echo "nothing to check: no readable $file"; return 1; }
  done
  for flag in "${flags[@]}"; do
    case $flag in
      -D* | -U*)
        needle=${flag#-?}
        needle=${needle%%=*}
        needle="(^|[^A-Za-z0-9_]|-[DU])$(escape "$needle")([^A-Za-z0-9_]|$)" ;;
      -Wl,*)
        payload=${flag#-Wl,}
        needle="(^|[[:space:]\";:,])$(escape "$payload")(\$|[[:space:]\";,])"
        needle="$needle|$(escape "-Xlinker ${payload//,/ -Xlinker }")(\$|[[:space:]\";])" ;;
      *)
        needle="(^|[[:space:]\";])$(escape "$flag")(\$|[[:space:]\";,])" ;;
    esac
    if grep -nE -e "$needle" "${files[@]}"; then
      echo "a consumer inherited $flag"
      found=1
    fi
  done
  return "$found"
}

# escape TEXT: TEXT with every ERE metacharacter escaped.
escape() {
  sed 's/[][\.*^$+?(){}|/]/\\&/g' <<<"$1"
}
