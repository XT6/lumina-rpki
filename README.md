# lumina-rpki

[![CI](https://github.com/XT6/lumina-rpki/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/XT6/lumina-rpki/actions/workflows/ci.yml)

An RPKI validator written from scratch.

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
