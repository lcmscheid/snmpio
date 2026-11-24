#!/usr/bin/env bash
# shared-library.sh PREFIX STATIC-PREFIX CONSUMER: snmpio, built with BUILD_SHARED_LIBS=ON and
# installed into PREFIX, exports its whole public API and keeps snmpio::detail hidden, and CONSUMER
# -- the examples, built against that install -- loads it from PREFIX (#106).
#
# The public API is what the libsnmpio.a installed into STATIC-PREFIX, built from the same
# sources, defines out of line in namespace snmpio, but for snmpio::detail and Client::Impl:
# everything else src/ defines there is declared by an installed header, so it is either marked
# SNMPIO_EXPORT or a link error waiting for the first consumer that calls it. Comparing against the
# archive catches a function the examples never call, which linking them alone would not. A sample
# of the API must be there too, so that the comparison cannot pass by having read nothing.
#
# A symbol is in a namespace by its mangled name -- _ZN6snmpio6detail, or the same after a
# special-name prefix (_ZTV, _ZTI, _ZGV, ...) or a cv-qualifier (_ZNK) -- and not by what its
# demangled form mentions: Asio's own templates instantiated over a detail type of ours,
# boost::asio::detail::service_registry::create<snmpio::detail::Deriver> and the like, are Asio's to
# export (its push_options.hpp makes them default visibility), and are not in our namespace.
# detail::cleanse is the one exception, and SecretOctets.hpp says why.
set -euo pipefail

usage='usage: shared-library.sh PREFIX STATIC-PREFIX CONSUMER'
prefix=${1:?$usage}
static=${2:?$usage}
consumer=${3:?$usage}

# keep_existing PATH...: those PATHs that exist, into the array FILES. Given a glob, it keeps what
# the glob matched: an unmatched glob is left as itself, which does not exist.
keep_existing() {
  local path
  FILES=()
  for path in "$@"; do
    if [ -e "$path" ]; then FILES+=("$path"); fi
  done
}

# matches GREP-ARG...: what grep, given GREP-ARGs, selects from stdin -- nothing when it selects
# nothing. grep exits 1 for that and 2 for an error, and only the first is a pass
# (hardening-lib.sh's absent() keeps them apart the same way).
matches() {
  local status=0
  grep "$@" || status=$?
  [ "$status" -le 1 ] || { echo "grep $* failed" >&2; return 2; }
}

keep_existing "$prefix"/lib*/libsnmpio.so
[ "${#FILES[@]}" -eq 1 ] || { echo "expected one libsnmpio.so under $prefix/lib*"; exit 1; }
library=$(readlink -f "${FILES[0]}")
keep_existing "$static"/lib*/libsnmpio.a
[ "${#FILES[@]}" -eq 1 ] || { echo "expected one libsnmpio.a under $static/lib*"; exit 1; }
archive=${FILES[0]}

# Captured before grep reads them: grep -q leaving early under pipefail could otherwise fail on the
# writer's SIGPIPE.
demangled=$(nm -DC --defined-only "$library")
for symbol in 'snmpio::Client::Client(' 'snmpio::Oid::parse(' 'snmpio::make_error_code('; do
  grep -qF -e " $symbol" <<<"$demangled" || { echo "$library does not export $symbol"; exit 1; }
done

exports=$(mktemp)
trap 'rm -f "$exports"' EXIT
nm -D --defined-only "$library" | awk '{ print $3 }' | sort -u >"$exports"

ours='^_Z[A-Z]*N[KVrRO]*6snmpio'
detail=$(matches -E "${ours}6detail" "$exports" | c++filt)
detail=$(matches -vxF 'snmpio::detail::cleanse(void*, unsigned long)' <<<"$detail")
[ -z "$detail" ] || { echo "$library exports snmpio::detail:"; echo "$detail"; exit 1; }

# The archive's definitions but its weak functions (W), which are inline functions and template
# instantiations every consumer compiles for itself. Weak objects (V) and unique ones (u) are kept:
# a typeinfo, a vtable or an inline function's static has to be one instance across the boundary,
# so a public one must be exported.
defined=$(nm --defined-only "$archive" | awk '$2 ~ /^[TDBRVu]$/ { print $3 }' | sort -u)
public=$(matches -E "$ours" <<<"$defined" | matches -vE "${ours}(6detail|6Client4Impl)")
[ -n "$public" ] || { echo "$archive defines nothing in snmpio"; exit 1; }
missing=$(matches -vxF -f "$exports" <<<"$public" | c++filt)
[ -z "$missing" ] || { echo "$library does not export:"; echo "$missing"; exit 1; }

soname=$(readelf -dW "$library" | sed -n 's/.*(SONAME).*\[\(.*\)\]/\1/p')
[[ $soname =~ ^libsnmpio\.so\.[0-9]+$ ]] || { echo "$library has SONAME '$soname'"; exit 1; }

keep_existing "$consumer"/example-*
[ "${#FILES[@]}" -gt 0 ] || { echo "no examples under $consumer"; exit 1; }
for example in "${FILES[@]}"; do
  resolved=$(ldd "$example" | awk -v soname="$soname" '$1 == soname { print $3 }')
  [ -n "$resolved" ] || { echo "$example does not load $soname"; exit 1; }
  [ "$(readlink -f "$resolved")" = "$library" ] \
    || { echo "$example loads $soname from $resolved, not from $prefix"; exit 1; }
done
echo "$soname exports all $(wc -l <<<"$public") of the API and no snmpio::detail but cleanse;" \
  "${#FILES[@]} examples load it"
