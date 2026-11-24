#!/usr/bin/env bash
# shared-library.sh PREFIX CONSUMER: snmpio, built with BUILD_SHARED_LIBS=ON and installed into
# PREFIX, exports its public API and keeps snmpio::detail hidden, and CONSUMER -- the examples,
# built against that install -- loads it from PREFIX (#106).
#
# The public API is sampled rather than listed: a class, a free function and an error-code hook,
# each one a consumer cannot link without. A symbol is in snmpio::detail by its mangled name --
# _ZN6snmpio6detail, or the same after a special-name prefix (_ZTV, _ZTI, _ZGV, ...) or a
# cv-qualifier (_ZNK) -- and not by what its demangled form mentions: Asio's own templates
# instantiated over a detail type of ours, boost::asio::detail::service_registry::create<
# snmpio::detail::Deriver> and the like, are Asio's to export (its push_options.hpp makes them
# default visibility), and are not in our namespace. detail::cleanse is the one exception, and
# SecretOctets.hpp says why.
set -euo pipefail

usage='usage: shared-library.sh PREFIX CONSUMER'
prefix=${1:?$usage}
consumer=${2:?$usage}

shopt -s nullglob
libraries=("$prefix"/lib*/libsnmpio.so)
shopt -u nullglob
[ "${#libraries[@]}" -eq 1 ] || { echo "expected one libsnmpio.so under $prefix/lib*"; exit 1; }
library=$(readlink -f "${libraries[0]}")

# Captured before grep reads them: grep -q leaving early under pipefail could otherwise fail on the
# writer's SIGPIPE.
demangled=$(nm -DC --defined-only "$library")
for symbol in 'snmpio::Client::Client(' 'snmpio::Oid::parse(' 'snmpio::make_error_code('; do
  grep -qF -e " $symbol" <<<"$demangled" || { echo "$library does not export $symbol"; exit 1; }
done

# grep exits 1 for "no match" and 2 for an error, and only the first is a pass (hardening-lib.sh's
# absent() keeps them apart the same way).
mangled=$(nm -D --defined-only "$library" | awk '{ print $3 }')
status=0
inDetail=$(grep -E '^_Z[A-Z]*N[KVrRO]*6snmpio6detail' <<<"$mangled") || status=$?
[ "$status" -le 1 ] || { echo "grep could not read the export list"; exit 1; }
detail=
if [ -n "$inDetail" ]; then
  status=0
  detail=$(c++filt <<<"$inDetail" | grep -vxF 'snmpio::detail::cleanse(void*, unsigned long)') \
    || status=$?
  [ "$status" -le 1 ] || { echo "could not demangle the export list"; exit 1; }
fi
[ -z "$detail" ] || { echo "$library exports snmpio::detail:"; echo "$detail"; exit 1; }

soname=$(readelf -dW "$library" | sed -n 's/.*(SONAME).*\[\(.*\)\]/\1/p')
[[ $soname =~ ^libsnmpio\.so\.[0-9]+$ ]] || { echo "$library has SONAME '$soname'"; exit 1; }

shopt -s nullglob
examples=("$consumer"/example-*)
shopt -u nullglob
[ "${#examples[@]}" -gt 0 ] || { echo "no examples under $consumer"; exit 1; }
for example in "${examples[@]}"; do
  resolved=$(ldd "$example" | awk -v soname="$soname" '$1 == soname { print $3 }')
  [ -n "$resolved" ] || { echo "$example does not load $soname"; exit 1; }
  [ "$(readlink -f "$resolved")" = "$library" ] \
    || { echo "$example loads $soname from $resolved, not from $prefix"; exit 1; }
done
echo "$soname exports the API and no snmpio::detail but cleanse; ${#examples[@]} examples load it"
