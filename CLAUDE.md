# snmpio

An async C++20 SNMPv2c/SNMPv3 command generator built directly on Asio. Manager side only, no
net-snmp dependency. Currently at **stage 3 of 6** — v2c and v3 both work end to end over UDP at
`noAuthNoPriv` and `authNoPriv`, discovery and Reports included. Privacy is stage 4. `README.md`
has the stage table.

## Read before changing anything

- **`CONTEXT.md`** — the domain glossary. Its _Avoid:_ lists are binding: this codebase says
  Target, not "device"; Command Generator, not "manager"; Credentials, not "auth config".
- **`docs/adr/`** — seven decisions, several of which look wrong until you read why. If a change
  contradicts one, say so explicitly rather than quietly overriding it.

## Build

Presets only — `cmake --preset <name>`, each writing to `build/<preset>/`.

| Preset | What |
|---|---|
| `default` | Boost.Asio, `RelWithDebInfo` (the project default, ADR-0002) |
| `standalone` | Standalone Asio — needs `pacman -S asio` |
| `debug` · `asan` | Debug, optionally ASan + UBSan |
| `tidy` · `fuzz` | clang-tidy folded into the build; Clang fuzzers |

```sh
cmake --preset default && cmake --build --preset default && ctest --preset default
```

## Conventions

**Naming** — types and files `UpperCamelCase`, functions and variables `lowerCamelCase`, private
members `m_lowerCamelCase`, namespaces `lower_case`. Enforced by `.clang-tidy`, not by review.

Three names are fixed by forces outside this repo and must not be "corrected":
`make_error_code` (ADL customisation point for both `error_code` types), `LLVMFuzzerTestOneInput`
(libFuzzer looks it up by name), and `begin`/`end`/`size` on `Oid` (range-for).

**Tooling version** — clang-format and clang-tidy are pinned to **22.1.8**, in CI and here. Their
output changes between major versions, so an unpinned workstation will reformat files CI then
rejects. `pip install clang-format==22.1.8 clang-tidy==22.1.8` if your distro ships a different one.

**Static analysis** — `.clang-tidy` runs ten check groups with `WarningsAsErrors: '*'`. Every
disabled check carries its reason in the file; add yours the same way rather than silently
widening the list. `tests/` and `fuzz/` have an overlay for test idioms.

**Crypto** — OpenSSL EVP, never our own (ADR-0001). Key derivation is pinned to RFC 3414's own
MD5 and SHA-1 vectors; the SHA-2 rows have no published vectors and were generated from an
independent implementation, so they pin against drift rather than against being wrong.

**Codec posture** — lenient where leniency is unambiguous (redundant integer sign padding,
non-minimal long-form lengths), strict where it is not (indefinite length, high-tag-number form,
sub-identifier overflow). Changing which side something falls on is an ADR-sized decision.

**Tests** — 151 of them, and the defensive paths are the point. A decoder change that keeps them all
green has probably not been tested; the misbehaving-agent cases are why ADR-0006 exists.

**Licence** — Apache-2.0. No per-file copyright headers, deliberately (ADR-0007). Anything ported
from gosnmp or async-snmp needs an attribution comment at the site *and* a `NOTICE` entry.

## Agent skills

### Issue tracker

GitHub Issues via the `gh` CLI, on [`lcmscheid/snmpio`](https://github.com/lcmscheid/snmpio).
See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical roles, unchanged: `needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
