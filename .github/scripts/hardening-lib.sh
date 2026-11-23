# Sourced by hardening-reached.sh, hardening-stays-ours.sh and the libcxx job; not run on its own.
#
# The flags come from the lists CMakeLists.txt writes into the build directory (hardening/), so
# that the set is written down once. Each check prints what it found wrong and returns 1. The
# callers run under `set -euo pipefail`, and every command whose failure would otherwise read as a
# result -- a jq, cmake, find or readelf that fails outright -- runs where errexit sees it, or has
# its status checked by hand.

# read_hardening_lists BUILD: BUILD's two lists into the arrays COMPILE and LINK. The lists are what
# every check checks against, so an emptied or broken one would pass them having checked nothing: a
# flag from each half, and the x86_64 row where this is x86_64, must be there.
read_hardening_lists() {
  local build=$1 flag required=(-D_GLIBCXX_ASSERTIONS -D_FORTIFY_SOURCE=3 -Wl,-z,now)
  read_list "$build/hardening/compile-flags.txt"
  COMPILE=("${LIST[@]}")
  read_list "$build/hardening/link-flags.txt"
  LINK=("${LIST[@]}")
  if [ "$(uname -m)" = x86_64 ]; then required+=(-fcf-protection=full); fi
  for flag in "${required[@]}"; do
    printf '%s\n' "${COMPILE[@]}" "${LINK[@]}" | grep -qxF -e "$flag" \
      || { echo "$build/hardening/ does not list $flag"; return 1; }
  done
}

# read_list FILE: FILE's non-blank lines into the array LIST. A missing file is an error, not an
# empty list.
read_list() {
  local line
  [ -r "$1" ] || { echo "no readable $1: is SNMPIO_HARDENING on?"; return 1; }
  LIST=()
  while IFS= read -r line; do
    if [ -n "$line" ]; then LIST+=("$line"); fi
  done <"$1"
}

# find_files DIR FIND-ARG...: the files `find DIR -maxdepth 1 -type f FIND-ARG...` lists, into the
# array FILES -- empty when there are none, and an error when find fails.
find_files() {
  local dir=$1 found
  shift
  found=$(find "$dir" -maxdepth 1 -type f "$@")
  FILES=()
  if [ -n "$found" ]; then mapfile -t FILES <<<"$found"; fi
}

# json_array WORD...: the WORDs as a JSON array of strings.
json_array() {
  if [ "$#" -eq 0 ]; then echo '[]'; return; fi
  printf '%s\n' "$@" | jq -cR . | jq -cs .
}

# compile_lines_carry COMMANDS DIR... -- FLAG...: every compile line in COMMANDS
# (compile_commands.json) whose source file is under one of the DIRs (relative to $PWD) carries
# every FLAG as a whole word -- -Wformat is not found in -Wformat=2. A line is ours by where its
# file is, not by what it mentions: every test line names GoogleTest's include path. Each DIR must
# have a line, so the check cannot pass by having filtered everything away.
compile_lines_carry() {
  local commands=$1 dirs=() problems
  shift
  while [ "$1" != "--" ]; do dirs+=("$1"); shift; done
  shift
  jq empty "$commands" || { echo "no readable $commands"; return 1; }
  problems=$(jq -r --arg root "$PWD/" \
      --argjson dirs "$(json_array "${dirs[@]}")" --argjson flags "$(json_array "$@")" '
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

# link_lines_carry BUILD FLAG...: every executable and shared library of ours in BUILD passes every
# FLAG to the linker. Ours are the targets named snmpio*; a static archive is not linked, so it has
# no link line to check. There must be at least one.
#
# The link lines come from CMake's File API, its documented way for a tool to read a target's link
# command (cmake-file-api(7), codemodel version 2), rather than from a generator's own files. A
# query takes effect at the next configure, so this writes one and re-runs CMake on the existing
# build, as an IDE does.
#
# The FLAGs are -Wl, options. CMake spells a LINKER: option for the compiler at hand -- -Wl,-z,now
# for GCC, -Xlinker -z -Xlinker now for Clang (cmake-commands(7), "Handling Compiler Driver
# Differences") -- so both sides are compared as what the linker receives: the words -Wl, splits on
# its commas, and each word after an -Xlinker.
link_lines_carry() {
  local build=$1 api index model targets=() problems
  shift
  api=$build/.cmake/api/v1
  mkdir -p "$api/query/client-snmpio"
  : >"$api/query/client-snmpio/codemodel-v2"
  cmake "$build" >/dev/null
  find_files "$api/reply" -name 'index-*.json'
  [ "${#FILES[@]}" -gt 0 ] || { echo "CMake wrote no File API reply under $api"; return 1; }
  index=$(printf '%s\n' "${FILES[@]}" | sort | tail -n 1)
  model=$(jq -er '.reply["client-snmpio"]["codemodel-v2"].jsonFile' "$index")
  mapfile -t targets < <(jq -r '.configurations[].targets[].jsonFile' "$api/reply/$model")
  problems=$(cd "$api/reply" && jq -rn --argjson flags "$(json_array "$@")" '
    def linkerWords:
      [foreach .[] as $word ({xlinker: false};
          if .xlinker then {xlinker: false, out: [$word]}
          elif $word == "-Xlinker" then {xlinker: true, out: []}
          elif $word | startswith("-Wl,") then {xlinker: false, out: ($word[4:] | split(","))}
          else {xlinker: false, out: []} end;
          .out[])];
    def hasRun($run): . as $words
      | any(range(0; ($words | length) - ($run | length) + 1);
          $words[.:. + ($run | length)] == $run);
    [inputs | select((.name | startswith("snmpio"))
        and (.type == "EXECUTABLE" or .type == "SHARED_LIBRARY"))] as $ours
    | if ($ours | length) == 0 then "no executable or shared library of ours"
      else $ours[] | .name as $name
        | ([.link.commandFragments[] | select(.role == "flags") | .fragment | splits(" +")]
            | map(select(. != "")) | linkerWords) as $have
        | $flags[] | select(. as $flag | $have | hasRun([$flag] | linkerWords) | not)
        | "\($name) was linked without \(.)"
      end' "${targets[@]}")
  [ -z "$problems" ] || { echo "$problems"; return 1; }
}

# elf_hardened FILE...: the linker's half, read back off each binary. Bind-now is the one property
# that shows -z now worked: Ubuntu's linker emits RELRO and a non-executable stack whatever it is
# asked, so those two are read back only so that a binary worse than the default fails. -z nodlopen
# marks shared objects only (NOOPEN), so it is required of them and not of executables -- a PIE is
# a shared object too, told apart by its PIE flag. --as-needed and --no-copy-dt-needed-entries
# leave nothing in the binary to read; link_lines_carry is their check.
elf_hardened() {
  local binary header dynamic segments stack
  [ "$#" -gt 0 ] || { echo "no binaries to check"; return 1; }
  for binary in "$@"; do
    header=$(readelf -hW "$binary")
    dynamic=$(readelf -dW "$binary")
    segments=$(readelf -lW "$binary")
    grep -q 'BIND_NOW' <<<"$dynamic" || { echo "$binary is not bind-now"; return 1; }
    grep -q 'GNU_RELRO' <<<"$segments" || { echo "$binary has no RELRO"; return 1; }
    stack=$(grep 'GNU_STACK' <<<"$segments") || { echo "$binary has no GNU_STACK"; return 1; }
    if grep -q 'RWE' <<<"$stack"; then echo "$binary has an executable stack"; return 1; fi
    if grep -q 'Shared object file' <<<"$header" && ! grep -q 'FLAGS_1.*PIE' <<<"$dynamic"; then
      grep -q 'FLAGS_1.*NOOPEN' <<<"$dynamic" || { echo "$binary is dlopen-able"; return 1; }
    fi
  done
}

# absent FLAG... -- FILE...: no FLAG appears in any FILE, as a word. A macro (-D or -U) is looked
# for by its name, which is how an installed CMake file would carry it. A linker option is looked
# for by what follows -Wl, -- which is also how LINKER: would carry it -- and in Clang's -Xlinker
# spelling (link_lines_carry says why there are two). A word may end at a generator expression's
# closing >, as in $<$<CONFIG:Release>:LINKER:--as-needed>. A missing FILE is an error: it proves
# nothing.
absent() {
  local flags=() files=() file flag needle payload status found=0
  local end='($|[[:space:]";,>])'
  while [ "$1" != "--" ]; do flags+=("$1"); shift; done
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
        needle="(^|[^A-Za-z0-9_]|-[DU])$(escape "${needle%%=*}")([^A-Za-z0-9_]|$)" ;;
      -Wl,*)
        payload=${flag#-Wl,}
        needle="(^|[[:space:]\";:,])$(escape "$payload")$end"
        needle="$needle|$(escape "-Xlinker ${payload//,/ -Xlinker }")$end" ;;
      *)
        needle="(^|[[:space:]\";:])$(escape "$flag")$end" ;;
    esac
    # grep exits 1 for "no match" and 2 for an error, and only the first is a pass.
    status=0
    grep -nE -e "$needle" "${files[@]}" || status=$?
    case $status in
      0) echo "a consumer inherited $flag"; found=1 ;;
      1) ;;
      *) echo "grep could not look for $flag"; return 1 ;;
    esac
  done
  return "$found"
}

# escape TEXT: TEXT with every ERE metacharacter escaped.
escape() {
  sed 's/[][\.*^$+?(){}|]/\\&/g' <<<"$1"
}
