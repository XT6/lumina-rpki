# ASN.1 modules

Lumina decodes RPKI objects with ASN.1 modules taken **verbatim from the RFC texts** in [`doc/rfc/`](../doc/rfc/README.md). Nothing here is written by hand.

| Folder | Contents | Produced by |
| --- | --- | --- |
| `rfc/` | Each module exactly as its RFC defines it | `mix lumina.asn1.extract` |
| `patches/` | Unified diffs that make `rfc/` compile with OTP's `asn1ct` | Written by hand and reviewed |
| `build/` | `rfc/` with the patches applied: the compiler input | `mix lumina.asn1.extract` |
| `../gen/asn1/` (git-ignored) | Erlang generated from `build/` | `mix compile` |

## Modules

| Module | RFC | Section | Defines |
| --- | --- | --- | --- |
| `PKIX1Explicit88` | [5280](../doc/rfc/rfc5280.txt) | A.1 | Certificates, CRLs, names, extensions (explicitly tagged) |
| `PKIX1Implicit88` | [5280](../doc/rfc/rfc5280.txt) | A.2 | Standard certificate extensions (implicitly tagged) |
| `CryptographicMessageSyntax2004` | [5652](../doc/rfc/rfc5652.txt) | 12.1 | CMS: `ContentInfo`, `SignedData`, `SignerInfo` |
| `IPAddrAndASCertExtn` | [3779](../doc/rfc/rfc3779.txt) | Appendix A | IP address and AS identifier extensions |
| `RPKI-ROA-2023` | [9582](../doc/rfc/rfc9582.txt) | 4 | ROA eContent |
| `RPKIManifest` | [9286](../doc/rfc/rfc9286.txt) | Appendix A | Manifest eContent |

The list lives in `Mix.Lumina.ASN1` (`lib/mix/lumina/asn1.ex`). Add a module there when a milestone needs one, for example RSC (RFC 9323) or TAK (RFC 9691) in M9.

## Extraction

```sh
mix lumina.asn1.extract           # regenerate asn1/rfc/ and asn1/build/
mix lumina.asn1.extract --check   # what CI and `mix check` run: fail if either differs
```

For each module, the task:

1. finds the module header (the module name, alone or followed by its OID, with `DEFINITIONS` right after it),
2. checks that the header sits in the RFC section listed above, so the citation can't be wrong,
3. takes everything up to the first `END` line (`END -- of Module` is accepted),
4. removes page furniture: form feeds, `[Page N]` footers and `RFC NNNN` running headers,
5. collapses runs of blank lines, and strips the common indentation and trailing whitespace.

ASN.1 ignores whitespace, so steps 4 and 5 don't change the module. Anything else in an extracted file is RFC text. Where an RFC indents some lines less than the rest (for example `DEFINITIONS` in RFC 9286), that layout is kept.

Never edit files in `rfc/` or `build/`. `--check` fails on any difference, and changes needed for the compiler go in patches.

## Compiling

`mix compile` runs the `lumina_asn1` compiler, defined in `mix.exs` because a compiler in `lib/` can't run before `lib/` is compiled. It runs OTP's `asn1ct` on every module in `build/` and writes Erlang to `gen/asn1/`, which the normal Erlang compiler then builds into the app.

- **Options:** `der`, `maps` (SEQUENCE and SET values are maps keyed by field name) and `undec_rest` (decoding returns the bytes left after the value, so trailing data can be rejected; see [F-010](../doc/rfc-findings.md#f-010-no-rule-for-data-after-the-encoded-object)).
- **Order:** modules are compiled in passes until all succeed, so imports never need ordering by hand.
- **When it runs:** everything is recompiled if any module changes, is added or removed, or the options change. `mix clean` removes `gen/`.

Use the compiled modules through `Lumina.ASN1`, never directly:

```elixir
Lumina.ASN1.decode(:pkix, :Certificate, der)   # {:ok, %{tbsCertificate: ..., ...}} | {:error, reason}
Lumina.ASN1.encode(:pkix, :Certificate, value) # {:ok, der} | {:error, reason}
```

The wrapper never raises, rejects trailing bytes, and shortens `asn1ct`'s error reasons, which include stack traces ([F-011](../doc/rfc-findings.md#f-011-asn1ct-error-reasons-carry-stack-traces)). It doesn't check that input is strict DER; that's `Lumina.DER` (#25).

## Patches

The modules as published don't compile with `asn1ct` (OTP 29). Each patch in `patches/` is a unified diff against `rfc/`. Every hunk carries a comment saying why it exists:

```asn1
-- LUMINA PATCH (<kind>): <reason>
```

| Module | Kind | Change | Why | Effect on decoding |
| --- | --- | --- | --- | --- |
| `PKIX1Explicit88` | builtin-type | Removes the definitions of `UniversalString`, `BMPString`, `UTF8String` | 1988-syntax workaround; `asn1ct` treats them as built-in ([F-007](../doc/rfc-findings.md#f-007-rfc-5280-modules-redefine-built-in-string-types)) | None: same universal tags |
| `PKIX1Implicit88` | builtin-type | Deletes the `BMPString, UTF8String` import line | The RFC's own comment says to delete it once "new" types are supported (F-007) | None |
| `CryptographicMessageSyntax2004` | attribute-certificate | Replaces the imports of `AttributeCertificate` (RFC 3281) and `AttributeCertificateV1` (§12.2) with `SEQUENCE OF ANY` | RFC 3281 is obsolete and not in the library; its successor's module imports from CMS in turn ([F-006](../doc/rfc-findings.md#f-006-cms-module-imports-from-an-obsoleted-rfc), [F-009](../doc/rfc-findings.md#f-009-cms-and-attribute-certificate-modules-import-from-each-other)) | Attribute certificates decode as a list of undecoded elements instead of full structures. RPKI never carries them (RFC 6488 §2.1.4), and M5 rejects any certificate choice other than one EE certificate. |
| `RPKI-ROA-2023` | content-type | Removes the `CONTENT-TYPE` import and the `ct-routeOriginAttestation` information object | RFC 6268 isn't in the library ([F-005](../doc/rfc-findings.md#f-005-rpki-content-modules-depend-on-a-different-cms-module-generation)) | None: the information object only binds the eContent type to its OID; the CMS decoder (#29) does that instead |
| `RPKIManifest` | content-type | Same, for `ct-rpkiManifest` | Same, and RFC 9286 doesn't even cite RFC 6268 ([F-004](../doc/rfc-findings.md#f-004-rfc-9286-imports-from-rfc-6268-without-referencing-it)) | None |

`IPAddrAndASCertExtn` (RFC 3779) compiles as published. Its earlier error was a side effect of the RFC 5280 problem.

### Rules

- **Strict application:** a hunk must match the extracted text exactly at the line it names, with no offset or fuzz. If the extraction changes, the patch fails instead of landing somewhere else.
- **Allowed changes only:** each kind may remove and add only specific kinds of lines, besides comments and blank lines (`Mix.Lumina.ASN1.Patch`). A patch can't delete a field, change a constraint or add a type. The one exception is the two opaque placeholders of the attribute-certificate kind.
- **Errata are not applied by patches.** For example, erratum 7118 (`fileList SIZE (1..MAX)`) is enforced during validation in M5 (#37), not in the module. The modules stay as published, plus compiler workarounds.
- **Patches stay necessary:** a test compiles each patched module as published and expects it to fail. If a future OTP accepts one, that test says the patch can go.

To change a patch, edit `patches/<Module>.patch`, run `mix lumina.asn1.extract`, and commit both the patch and `build/`. To create one, edit a copy of `rfc/<Module>.asn1` and run `diff -u --label a/<Module>.asn1 --label b/<Module>.asn1 rfc/<Module>.asn1 <copy>`.
