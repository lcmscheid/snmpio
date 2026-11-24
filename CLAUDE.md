# snmpio

An async C++20 SNMPv2c/SNMPv3 Command Generator built directly on Asio. No Agent side, no
net-snmp dependency. Stages 0–4 and 6 of 7 are done — v2c and v3 both work end to end over UDP at
all three Security Levels, discovery, Reports and privacy included, and stage 6 made it safe to
depend on (`docs/threat-model.md`). Interop is stage 5, whose automated half is done; the
hardware checklist remains. Stage 7 is docs, packaging and release.
`README.md` has the stage table.

## Read before changing anything

- **`CONTEXT.md`** — the domain glossary. Its _Avoid:_ lists are binding: this codebase says
  Target, not "device"; Command Generator, not "manager"; Credentials, not "auth config".
- **`docs/adr/`** — twelve decisions, several of which look wrong until you read why. If a change
  contradicts one, say so explicitly rather than quietly overriding it.

## Build

Presets only — `cmake --preset <name>`, each writing to `build/<preset>/`.

| Preset | What |
|---|---|
| `default` | Boost.Asio, `RelWithDebInfo` (the project default, ADR-0002) |
| `standalone` | Standalone Asio — needs `pacman -S asio` |
| `debug` · `asan` | Debug, optionally ASan + UBSan |
| `tsan` | Clang, Debug, TSan — fenced blocks off on Asio before 1.38.2 |
| `hardened` | The OpenSSF compiler hardening flags, PRIVATE to our targets (`SNMPIO_HARDENING`) |
| `tidy` · `fuzz` | clang-tidy folded into the build; Clang fuzzers |

```sh
cmake --preset default && cmake --build --preset default && ctest --preset default
```

## Conventions

**Naming** — types and files `UpperCamelCase`, functions and variables `lowerCamelCase`, private
members `m_lowerCamelCase`, namespaces `lower_case`. Enforced by `.clang-tidy`, not by review.

Four names are fixed by forces outside this repo and must not be "corrected":
`make_error_code` (ADL customisation point for both `error_code` types), `LLVMFuzzerTestOneInput`
(libFuzzer looks it up by name), `begin`/`end`/`size` on `Oid` (range-for), and `PrintTo` in
`tests/` (GoogleTest's ADL printer hook).

**Tooling version** — clang-format and clang-tidy are whatever Arch's `clang` package ships, on
the workstation and in CI (`archlinux:latest`); they follow Arch rather than a pin. Their output
changes between major versions, so a major LLVM bump gets its own commit — the `.clang-tidy` and
code changes the new major asks for, and nothing else. Use `/usr/bin/clang-format` and
`/usr/bin/clang-tidy`; nothing installs them from PyPI.

**Static analysis** — `.clang-tidy` runs ten check groups with `WarningsAsErrors: '*'`. Every
disabled check carries its reason in the file; add yours the same way rather than silently
widening the list. `tests/` and `fuzz/` have an overlay for test idioms.

**Crypto** — OpenSSL EVP (ADR-0001), never our own. Every primitive is OpenSSL's (EVP for ciphers
and digests, RAND for keys). A construction around one is allowed only when a published
specification defines it: RFC 3414's password-to-key, the key extensions' IETF drafts, and FF1 for
Message IDs (ADR-0012). Never one of our own design. Key derivation is pinned to RFC 3414's own MD5
and SHA-1 vectors; the SHA-2 rows have no published vectors and were generated from an independent
implementation, so they pin against drift rather than against being wrong. The privacy key rows
are the same arrangement, generated from gosnmp — no RFC publishes AES-192/256 key extension
vectors, because neither extension is in an RFC. FF1's rows are too: an independent FF1, checked
against NIST's samples first.

**Codec posture** — lenient where leniency is unambiguous (redundant integer sign padding,
non-minimal long-form lengths), strict where it is not (indefinite length, high-tag-number form,
sub-identifier overflow). Changing which side something falls on is an ADR-sized decision.

**Tests** — the defensive paths are the point. A decoder change that keeps them all green has
probably not been tested; the misbehaving-agent cases are why ADR-0006 exists.

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
