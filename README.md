# lumina-rpki

[![CI](https://github.com/XT6/lumina-rpki/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/XT6/lumina-rpki/actions/workflows/ci.yml)

An RPKI relying party (validator) written from scratch in Elixir, from the RFC texts. It fetches the RPKI repositories over RRDP and rsync, validates certificates, CRLs, manifests and ROAs, and writes the Validated ROA Payloads (VRPs) as CSV or JSON.

## Quick start

```sh
scripts/install-deps.sh                                # Erlang/OTP, Elixir, rsync, then builds ./lumina
./lumina sync                                          # fetch the five RIRs' repositories into the cache (about 15 minutes the first time)
./lumina validate                                      # validate the cache, offline
./lumina vrps --output vrps.csv                        # write the VRPs as CSV
./lumina vrps --sync --format json --output vrps.json  # sync what is older than an hour, then write JSON
```

## Installing

Lumina needs Erlang/OTP and Elixir (versions in [`.tool-versions`](.tool-versions)) and rsync 3.1.0 or later. On macOS, `/usr/bin/rsync` is openrsync, which is too old.

```sh
scripts/install-deps.sh           # installs what's missing, fetches dev dependencies, builds ./lumina
scripts/install-deps.sh --check   # only reports; exits 1 if something is missing
```

Erlang and Elixir come from mise or asdf when either is installed (both read `.tool-versions`), otherwise from Homebrew on macOS; rsync from Homebrew on macOS, or apt-get/dnf on Linux. If a good rsync is installed but not first on `PATH`, either fix `PATH` or give it to `lumina sync --rsync PATH`.

Releases are on [GitHub](https://github.com/XT6/lumina-rpki/releases): source archives and the `lumina` escript, which needs Erlang/OTP (version in `.tool-versions`) on the host. Versions are `0.<last milestone completed>.<patch>` ([releasing](doc/releasing.md)).

## Commands

Every command is `lumina <command> [flags] [arguments]` ([D-001](doc/decisions.md#d-001-cli-model)); `lumina help <command>` lists its flags.

| Command | What it does |
| --- | --- |
| [`sync`](#lumina-sync) | fetch the trust anchors and repositories into the local cache |
| [`validate`](#lumina-validate) | validate the cache, offline, and summarise what is valid and invalid |
| [`vrps`](#lumina-vrps) | validate the cache, offline, and write the VRPs; `--sync` fetches first |
| [`clean`](#lumina-clean) | empty the cache, or remove what some TALs use from it |
| [`print`](#lumina-print) | print RPKI objects and TALs in human-readable form |
| `version` | print the version |
| `help` | show help for lumina or a command |

**Shared flags and behaviour:**
- **TALs:** `sync`, `validate` and `vrps` use every `.tal` file in `./tals/` (the five RIRs' TALs, D-004) unless `--tal FILE` picks some; repeat it for several. A trust anchor is named after its TAL file, without `.tal` (`lacnic`, `ripe-ncc`).
- **Cache:** `--cache DIR`; by default the user cache directory, `~/.cache/lumina` on Linux and `~/Library/Caches/lumina` on macOS.
- **Progress:** long-running commands report progress on stderr by default ([D-036](doc/decisions.md)): a status line on a terminal, timestamped lines otherwise. `--quiet` turns it off.
- **Banner:** every run but `lumina version` starts with one line on stderr: the version, the runtimes and the start time ([D-045](doc/decisions.md)). `--quiet` leaves it out.
- **Exit codes:** `0` success, `1` a failure the command describes (see each below), `2` a usage error.

## `lumina sync`

Fetches the trust anchors and repositories into the local cache. It validates as it walks, to know which CA certificates to follow (only those on a current manifest that validate), but the full validation of signed objects is `lumina validate`'s and `lumina vrps`'s.

```sh
./lumina sync                          # every TAL in ./tals/ (the five RIRs)
./lumina sync --tal tals/lacnic.tal    # one TAL
./lumina sync --no-rrdp                # rsync only, never RRDP
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

## `lumina validate`

Validates what the last sync put in the cache, without fetching anything: for each TAL, its trust anchor, then every CA certificate, CRL, manifest and signed object below it (RFC 6487, RFC 6488, RFC 9286, RFC 9582, resource inclusion per RFC 6487 §7.2).

```sh
./lumina validate                           # every TAL in ./tals/
./lumina validate --tal tals/lacnic.tal     # one TAL
./lumina validate --now 2030-01-01          # as of another time
./lumina validate --max-invalid 0           # fail on any invalid object
```

- **Summary, per TAL:** the trust anchor, publication points (and how many were read from RRDP and from rsync), valid and invalid objects of each type, every invalid one with its reasons, warnings, overclaiming certificates, and publication points missing from the cache.
- **Publication points:** each is read from where the last sync read it, its RRDP repository or the rsync mirror. One whose manifest checks fail (RFC 9286 §6) is validated from its last valid copy while that copy's manifest is current ([D-023](doc/decisions.md)).
- **Exit codes:** `0` valid, `1` a TAL with no trust anchor in the cache, an invalid trust anchor, or more than `--max-invalid` percent (default 10) of a TAL's objects invalid ([D-022](doc/decisions.md)), `2` usage error.

## `lumina vrps`

Validates the cache as `lumina validate` does and writes the VRPs of the valid ROAs: one row per distinct AS, prefix, maxLength and trust anchor.

```sh
./lumina vrps                                   # CSV on stdout
./lumina vrps --output vrps.csv                 # to a file, replaced in one step
./lumina vrps --format json --output vrps.json  # JSON, with metadata
./lumina vrps --sync --output vrps.csv          # sync the TALs last synced over an hour ago, then write
./lumina vrps --sync --max-age 10m              # ... over 10 minutes ago
./lumina vrps --wide                            # debugging: add each ROA's URI, one row per VRP and ROA
```

```
ASN,IP Prefix,Max Length,Trust Anchor
AS13335,1.0.0.0/24,24,apnic
AS64496,2001:db8::/32,48,lacnic
```

- **Formats:** CSV in Routinator's columns, or Lumina's JSON; both are described in [doc/output.md](doc/output.md).
- **`--sync`:** first syncs, as `lumina sync` does, each TAL with no trust anchor in the cache or last synced more than `--max-age` (default `1h`) ago; the others are validated from the cache as they are ([D-037](doc/decisions.md)). It takes `lumina sync`'s flags (`--timeout`, `--max-depth`, `--per-host`, `--rsync`, `--no-rrdp`, `--rrdp-max-size`, `--rrdp-idle-timeout`).
- **Output:** the VRPs go to stdout or `--output FILE`. A short summary goes to stderr: why each TAL was synced and the sync's summary, the VRPs of each TAL, and warnings.
- **Exit codes:** `0` written; `1` as for `lumina validate`, a sync that couldn't fetch a trust anchor or its own publication point, or `FILE` can't be written (the VRPs of the TALs that validated are still written); `2` usage error.

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

- **`--brief`:** leaves out key identifiers, public keys, signatures, digests, signer details and manifest hashes. It keeps validity dates, names, resources, URIs, ROA prefixes, manifest file names and CRL revocations.
- **Formats:** `.cer`, `.crl`, `.mft` and `.roa` print in full. `.gbr`, `.sig` and `.tak` print their envelope; their contents come in M9.
- **What it shows:** what each file contains. It doesn't validate. A file that fails to decode is reported with the layer that failed (DER, ASN.1, envelope, eContent, type).
- **Exit codes:** `0` success, `1` a file failed to decode, `2` usage error.

## Building from source

```sh
mix escript.build    # builds ./lumina (needs Erlang/OTP on the host)
mix test             # the test suite
mix check            # everything CI runs
```

Design decisions are in [doc/decisions.md](doc/decisions.md), RFC findings in [doc/rfc-findings.md](doc/rfc-findings.md), and the tests in [doc/tests/CATALOG.md](doc/tests/CATALOG.md).
