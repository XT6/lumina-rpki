# ASN.1 modules

Lumina decodes RPKI objects with ASN.1 modules taken **verbatim from the RFC texts** in [`doc/rfc/`](../doc/rfc/README.md). Nothing here is written by hand.

| Folder | Contents | Produced by |
| --- | --- | --- |
| `rfc/` | Each module exactly as its RFC defines it | `mix lumina.asn1.extract` |

The patches that make these modules compile with OTP's `asn1ct` (#23) and the compile step (#24) build on `rfc/`.

## Modules

| Module | RFC | Section | Defines |
| --- | --- | --- | --- |
| `PKIX1Explicit88` | [5280](../doc/rfc/rfc5280.txt) | A.1 | Certificates, CRLs, names, extensions (explicitly tagged) |
| `PKIX1Implicit88` | [5280](../doc/rfc/rfc5280.txt) | A.2 | Standard certificate extensions (implicitly tagged) |
| `CryptographicMessageSyntax2004` | [5652](../doc/rfc/rfc5652.txt) | 12.1 | CMS: `ContentInfo`, `SignedData`, `SignerInfo` |
| `AttributeCertificateVersion1` | [5652](../doc/rfc/rfc5652.txt) | 12.2 | Imported by the CMS module |
| `IPAddrAndASCertExtn` | [3779](../doc/rfc/rfc3779.txt) | Appendix A | IP address and AS identifier extensions |
| `RPKI-ROA-2023` | [9582](../doc/rfc/rfc9582.txt) | 4 | ROA eContent |
| `RPKIManifest` | [9286](../doc/rfc/rfc9286.txt) | Appendix A | Manifest eContent |

The list lives in `Mix.Lumina.ASN1` (`lib/mix/lumina/asn1.ex`). Add a module there when a milestone needs one, for example RSC (RFC 9323) or TAK (RFC 9691) in M9.

## Extraction

```sh
mix lumina.asn1.extract           # regenerate asn1/rfc/
mix lumina.asn1.extract --check   # what CI and `mix check` run: fail if asn1/rfc/ differs
```

For each module, the task:

1. finds the module header (the module name, alone or followed by its OID, with `DEFINITIONS` right after it),
2. checks that the header sits in the RFC section listed above, so the citation can't be wrong,
3. takes everything up to the first `END` line (`END -- of Module` is accepted),
4. removes page furniture: form feeds, `[Page N]` footers and `RFC NNNN` running headers,
5. collapses runs of blank lines, and strips the common indentation and trailing whitespace.

ASN.1 ignores whitespace, so steps 4 and 5 don't change the module. Anything else in an extracted file is RFC text. Where an RFC indents some lines less than the rest (for example `DEFINITIONS` in RFC 9286), that layout is kept.

Never edit files in `rfc/`. `--check` fails on any difference, and changes needed for the compiler go in patches (#23).

## Known compiler issues

Compiling the pristine modules with `asn1ct` (OTP 29) currently fails. #23 handles this with documented, encoding-neutral patches:

- **`PKIX1Explicit88`, `PKIX1Implicit88`:** redefine `UniversalString`, `BMPString` and `UTF8String`, which `asn1ct` treats as built-in.
- **`IPAddrAndASCertExtn`:** an imported OID error, probably a consequence of the above.
- **`RPKI-ROA-2023`, `RPKIManifest`:** import `CONTENT-TYPE` from RFC 6268, which isn't in the library. The decision is to patch it out; see #23.
- **`CryptographicMessageSyntax2004`:** imports `AttributeCertificate` from RFC 3281, which isn't in the library either. RPKI signed objects don't use attribute certificates (RFC 6488 §2.1.4), so #23 decides how to handle it.
