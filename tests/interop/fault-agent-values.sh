#!/bin/sh
# Prints the Simulator's values.json for the interop suite, to stdout.
#
# Mounted over /etc/snmpfault/values.json beside tests/interop/fault-agent-auth.sh's auth.json, so
# what the Simulator serves this suite is said here and nowhere else. The image's own
# configuration serves four instances under `system` and two under `interfaces`, which fits in one
# GETBULK -- so no Walk against it ever continued from one Response to the next request.
#
# What it serves, and for which test:
#
#   - `system`: sysDescr.0, which every half of the suite GETs; sysUpTime.0; sysContact.0, the
#     writable entry the SET tests write and restore, as on `snmpd`; and sysLocation.0. sysDescr.0
#     is the read-only entry a refused SET targets: the Simulator has no per-user access control,
#     so a read-only object is the only refusal it can give.
#   - `interfaces`: ifNumber.0 and ten columns of ifTable over five interfaces, 51 instances -- the
#     Subtree tests/InteropWalk.hpp walks, several batches long at the library's default
#     max-repetitions. Columns 10 and 16 sort after 9 by sub-identifier and before it as text, so
#     an Agent that ordered OIDs as strings would fail the Walk rather than pass it.
#   - one enterprise object past both, so a Walk of `interfaces` ends by leaving the Subtree, as it
#     does on `snmpd`, rather than at the end of the MIB view.
#
# Each entry has one value, so what a test reads is what this says: the Simulator picks among
# several at random on startup. sysContact.0 is the only writable entry, which is all the SET
# tests need, so nothing else here can be changed by a run: not sysLocation.0 or ifAdminStatus,
# which their MIBs make writable, nor the enterprise object.
set -eu

first=1
value() {  # value <oid> <type> <value> [readOnly]
  [ "$first" = 1 ] || printf ',\n'
  first=0
  printf '    {"name": "%s", "oid": "%s", "type": "%s", "values": ["%s"]' "$1" "$1" "$2" "$3"
  [ $# -eq 4 ] && printf ', "readOnly": true'
  printf '}'
}

printf '{\n  "values": [\n'

value 1.3.6.1.2.1.1.1.0 string "snmpio interop Simulator" readOnly
value 1.3.6.1.2.1.1.3.0 timeticks 1000 readOnly
value 1.3.6.1.2.1.1.4.0 string "noc@example.com"
value 1.3.6.1.2.1.1.6.0 string "rack 4, row B" readOnly

interfaces=5
value 1.3.6.1.2.1.2.1.0 integer "$interfaces" readOnly
# <column>:<type>:<value>, in column order.
for column in 1:integer: 2:string: 3:integer:6 4:integer:1500 5:gauge:1000000000 \
              7:integer:1 8:integer:1 9:timeticks:0 10:counter:0 16:counter:0; do
  number=${column%%:*}
  rest=${column#*:}
  type=${rest%%:*}
  fixed=${rest#*:}
  i=1
  while [ "$i" -le "$interfaces" ]; do
    # ifIndex is the index itself and ifDescr names it; every other column is the same for all.
    case $number in
      1) v=$i ;;
      2) v="eth$((i - 1))" ;;
      *) v=$fixed ;;
    esac
    value "1.3.6.1.2.1.2.2.1.$number.$i" "$type" "$v" readOnly
    i=$((i + 1))
  done
done

value 1.3.6.1.4.1.9999.1.1.0 gauge 45 readOnly

printf '\n  ]\n}\n'
