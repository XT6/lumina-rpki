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

Releases are on [GitHub](https://github.com/XT6/lumina-rpki/releases): source archives and the `lumina` escript, which needs Erlang/OTP (version in `.tool-versions`) on the host. Versions are `0.<last milestone completed>.<patch>` ([releasing](doc/releasing.md)). `lumina version` prints the version, and every run starts with a banner on stderr naming it (`--quiet` leaves it out).

## `lumina sync`

Fetches the trust anchors and repositories into a local cache. Nothing is validated yet.

```sh
./lumina sync                          # every TAL in ./tals/ (the five RIRs)
./lumina sync --tal tals/lacnic.tal    # one TAL
./lumina sync --no-rrdp               # rsync only, never RRDP
./lumina help sync                     # flags: --cache, --timeout, --max-depth, --per-host, --rsync, --no-rrdp,
                                       #   --rrdp-max-size, --rrdp-idle-timeout, --progress, --quiet
```

A CA that names an RRDP repository (an HTTPS `rpkiNotify`, RFC 8182) is synced over RRDP, and fetched with rsync in the same run if that fails ([D-040](doc/decisions.md)); other CAs are fetched with rsync. `--no-rrdp` uses rsync for every publication point (trust anchors are still fetched over HTTPS first). An RRDP snapshot or delta file may be at most `--rrdp-max-size` (default `2G`), and a download may go `--rrdp-idle-timeout` seconds (default 300) without data; there is no limit on its total time (D-043). The summary counts each TAL's RRDP repositories by outcome, such as `rrdp: 12 repositories: 3 snapshot, 7 deltas, 1 unchanged, 1 failed (rsync fallback)`, then gives each repository a line with its session ID, the serial before and after, the deltas applied or the snapshot and why it was used, and the bytes received ([D-048](doc/decisions.md)), and lists each failure and warning with its reason:

```
  rrdp: 2 repositories: 1 snapshot, 1 deltas
    https://rrdp.example.net/rrdp/notification.xml: session 5d8a3f0e-6b1c-4e2a-9f7d-2c4b8e1a0d93, serial 41230 → 41236, 6 deltas, 1.2 MiB
    https://rpki.example.org/notification.xml: session 0b7e2c91-4f3a-4d6b-8e15-9a2f6c3d7e48 (new session), serial 812, snapshot, 35.4 MiB
```

On a terminal, a status line on stderr shows progress: the TAL, the walk level, publication points, rsync runs (done, running, failed), RRDP repositories (done, running, failed, bytes received), files mirrored, and the slowest fetch in progress (for an RRDP download, the file and how much of it has arrived). `--progress` writes timestamped lines instead when stderr isn't a terminal (logs, CI), plus a line for each RRDP repository that took more than 10 s; `--quiet` turns progress off. The summary on stdout is the same either way.

A module fetch whose connection drops or times out is tried once more after 10 to 30 s, and listed as `retried` in the summary; other failures (an unknown host, a refused connection, a missing module) aren't ([D-039](doc/decisions.md#d-039-a-module-fetch-is-retried-once-after-a-transient-failure)).

Exit codes: `0` everything fetched, `1` a fetch failed (the cache is still usable), the cache is in use, or rsync is missing or too old, `2` usage error.

## `lumina clean`

Removes what `lumina sync` put in the cache. The next sync fetches it again.

```sh
./lumina clean                         # empty the whole cache, after asking
./lumina clean --tal tals/arin.tal     # only what ARIN's tree uses; repositories another TAL's tree uses stay
./lumina clean --force                 # don't ask (cron jobs, scripts)
```

It lists what it will remove and asks `Remove? [y/N]`; without `--force` and with standard input not a terminal, it removes nothing ([D-047](doc/decisions.md#d-047-lumina-clean-empties-the-cache-after-confirmation)). A TAL never synced into the cache only warns. A TAL synced by Lumina before 0.8.1 has no record of its repositories, so `--tal` removes only its trust anchor and sync record.

Exit codes: `0` removed, or nothing to remove, `1` the cache is in use by a sync, the removal wasn't confirmed, or a file couldn't be removed, `2` usage error.

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
