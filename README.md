# lumina-rpki

[![CI](https://github.com/XT6/lumina-rpki/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/XT6/lumina-rpki/actions/workflows/ci.yml)

An RPKI validator written from scratch.

## `lumina --print`

Prints RPKI objects in human-readable form, one `field: value` per line. It's useful for inspecting a repository, writing fixtures and debugging.

```sh
mix escript.build                       # builds ./lumina (needs Erlang/OTP on the host)
./lumina --print ta.cer ca1.mft roa1.roa
```

```
type: roa (signed object)
content type: routeOriginAuthz (1.2.840.113549.1.9.16.1.24)
...
roa:
  version: 0
  as id: AS64496
  prefixes:
    prefix: 1.1.0.0/17 max length 24
    prefix: 1.1.128.0/24
```

- **Formats:** `.cer`, `.crl`, `.mft` and `.roa` print in full. `.gbr`, `.sig` and `.tak` print their envelope; their contents come in M9.
- **What it shows:** what each file contains. It doesn't validate. A file that fails to decode is reported with the layer that failed (DER, ASN.1, envelope, eContent, type).
- **Exit codes:** `0` if every file printed, `1` if any failed to decode, `2` for usage errors.
