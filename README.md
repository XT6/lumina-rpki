# lumina-rpki

[![CI](https://github.com/XT6/lumina-rpki/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/XT6/lumina-rpki/actions/workflows/ci.yml)

An RPKI validator written from scratch.

## Installing

Lumina needs Erlang/OTP and Elixir (versions in [`.tool-versions`](.tool-versions)) and rsync 3.1.0 or later. On macOS, `/usr/bin/rsync` is openrsync, which is too old.

```sh
scripts/install-deps.sh           # installs what's missing, fetches dev dependencies, builds ./lumina
scripts/install-deps.sh --check   # only reports; exits 1 if something is missing
```

Erlang and Elixir come from mise or asdf when either is installed (both read `.tool-versions`), otherwise from Homebrew on macOS; rsync from Homebrew on macOS, or apt-get/dnf on Linux. If a good rsync is installed but not first on `PATH`, either fix `PATH` or give it to `lumina sync --rsync PATH`.

## `lumina sync`

Fetches the trust anchors and repositories into a local cache. Nothing is validated yet.

```sh
./lumina sync                          # every TAL in ./tals/ (the five RIRs)
./lumina sync --tal tals/lacnic.tal    # one TAL
./lumina help sync                     # flags: --cache, --timeout, --max-depth, --per-host, --rsync, --progress, --quiet
```

On a terminal, a status line on stderr shows progress: the TAL, the walk level, publication points, rsync runs (done, running, failed), files mirrored, and the slowest fetch in progress. `--progress` writes timestamped lines instead when stderr isn't a terminal (logs, CI); `--quiet` turns progress off. The summary on stdout is the same either way.

Exit codes: `0` everything fetched, `1` a fetch failed (the cache is still usable), the cache is in use, or rsync is missing or too old, `2` usage error.

## `lumina print`

Prints RPKI objects in human-readable form, one `field: value` per line. It's useful for inspecting a repository, writing fixtures and debugging.

```sh
mix escript.build                         # builds ./lumina (needs Erlang/OTP on the host)
./lumina print ta.cer ca1.mft roa1.roa    # full printout
./lumina print --brief roa1.roa           # validity and payload, without cryptographic detail
./lumina help print
```

```
$ ./lumina print --brief roa1.roa
type: roa (signed object)
signing time: 2026-01-01T00:00:00Z
ee certificate validity:
  not before: 2026-01-01T00:00:00Z
  not after: 2036-01-01T00:00:00Z
roa:
  version: 0
  as id: AS64496
  prefixes:
    prefix: 1.1.0.0/17 max length 24
    prefix: 1.1.128.0/24
```

- **Command model:** `lumina <command> [flags] [arguments]` ([D-001](doc/decisions.md#d-001-cli-model)).
- **`--brief`:** leaves out key identifiers, public keys, signatures, digests, signer details and manifest hashes. It keeps validity dates, names, resources, URIs, ROA prefixes, manifest file names and CRL revocations.
- **Formats:** `.cer`, `.crl`, `.mft` and `.roa` print in full. `.gbr`, `.sig` and `.tak` print their envelope; their contents come in M9.
- **What it shows:** what each file contains. It doesn't validate. A file that fails to decode is reported with the layer that failed (DER, ASN.1, envelope, eContent, type).
- **Exit codes:** `0` success, `1` a file failed to decode, `2` usage error.
