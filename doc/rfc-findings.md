# RFC findings log

Problems, errata and ambiguities found in the RFC texts while building Lumina from them, and what we did about each. It's kept as material for talks and write-ups about implementing RPKI from the specifications alone.

Each entry records the following:

- **Where** in the RFC text, quoted where useful.
- **Kind** of finding:
  - **erratum:** the text is wrong
  - **ambiguity:** two readings are possible
  - **reference:** a dependency is missing or obsolete
  - **tooling:** the text is fine but doesn't work with today's tools
- **Official errata status:** checked against the [RFC Editor errata database](https://www.rfc-editor.org/errata.php), with the erratum ID if one exists.
- **Impact on Lumina** and the **resolution**, linking to the issue or PR.

Reporting a new erratum to the RFC Editor is the maintainer's call. Entries marked *not reported* are candidates.

## Summary

| ID | RFC | Kind | Official errata | Status in Lumina |
| --- | --- | --- | --- | --- |
| [F-001](#f-001-manifest-filelist-allows-an-empty-list) | 9286 App. A | erratum | [7118](https://www.rfc-editor.org/errata/eid7118), verified | Module kept as published; rejected in M5 (#37) |
| [F-002](#f-002-rfc-3779-worked-example-has-wrong-bytes) | 3779 App. B | erratum | [6792](https://www.rfc-editor.org/errata/eid6792), verified | Tests use corrected values (#26) |
| [F-003](#f-003-cms-module-points-to-a-non-existent-appendix-b) | 5652 §12.1 | erratum | [6546](https://www.rfc-editor.org/errata/eid6546), verified | No effect (comment only) |
| [F-004](#f-004-rfc-9286-imports-from-rfc-6268-without-referencing-it) | 9286 App. A | reference | none (not reported) | Patched out (#23) |
| [F-005](#f-005-rpki-content-modules-depend-on-a-different-cms-module-generation) | 9582 §4, 9286 App. A, 9323 | reference | none | Patched out (#23) |
| [F-006](#f-006-cms-module-imports-from-an-obsoleted-rfc) | 5652 §12.1, §12.2 | reference | none | Open: #23 |
| [F-007](#f-007-rfc-5280-modules-redefine-built-in-string-types) | 5280 A.1, A.2 | tooling | none | Patch (#23) |
| [F-008](#f-008-certificate-signature-field-has-two-names) | 5280 §4.1 vs A.1 | ambiguity | [7634](https://www.rfc-editor.org/errata/eid7634), held for document update | Decide in #27 |

## Entries

### F-001: manifest `fileList` allows an empty list

- **Where:** RFC 9286, Appendix A (ASN.1 module):

  ```asn1
  fileList  SEQUENCE SIZE (0..MAX) OF FileAndHash
  ```

  RFC 9286 §7 says "A CA's manifest will always contain at least one entry", so the module allows something the prose forbids.
- **Kind:** erratum (technical).
- **Official errata:** [7118](https://www.rfc-editor.org/errata/eid7118), **verified**. The corrected text is `SIZE (1..MAX)`. RFC 9981 (2026), which updates RFC 9286, doesn't touch this line.
- **Found:** 2026-11-12, while checking the errata of every module extracted in #22.
- **Impact:** `asn1/rfc/RPKIManifest.asn1` is extracted verbatim, so it contains the **uncorrected** `0..MAX`. A decoder built from it accepts an empty manifest.
- **Resolution:** maintainer decision (2026-11-12): empty manifests are **not allowed**, and they're rejected **during validation**, not decoding.
  - The ASN.1 module stays as published (`0..MAX`), so an empty manifest decodes in M1 and `lumina --print` can show it.
  - M5 manifest validation rejects it with "manifest has no entries (RFC 9286 §7, erratum 7118)" (#37).
  - The alternative was rejected: patching the module to `1..MAX` would make an empty manifest fail as a generic decode error, if the compiler enforces size constraints at all, and the object couldn't be inspected.
- **Talk note:** extracting a module "verbatim from the RFC" faithfully reproduces known, verified errors. The RFC text is not the whole specification; the errata are part of it.

### F-002: RFC 3779 worked example has wrong bytes

- **Where:** RFC 3779, Appendix B, the DER example of an IP address delegation extension.
- **Kind:** erratum (technical).
- **Official errata:** [6792](https://www.rfc-editor.org/errata/eid6792), **verified** (2021). The example encodes `b010` where `172.16/12` needs `ac10` (172 is `0xac`), and it encodes one IPv6 prefix as `/47` where the text before the example says `/48`.
- **Impact:** #26 planned to test the RFC 3779 decoder against "the values the RFC states" in Appendices B and C. Using the bytes as printed would make a correct decoder fail, or "prove" an incorrect one.
- **Resolution:** #26 uses the erratum-corrected values, and the test cites erratum 6792.
- **Talk note:** the worked example in a 2004 RFC was wrong for 17 years before the erratum was verified. Test vectors copied from RFCs need to be checked against the errata too.

### F-003: CMS module points to a non-existent "Appendix B"

- **Where:** RFC 5652 §12.1, a comment in the IMPORTS of `CryptographicMessageSyntax2004`:

  ```asn1
  -- Imports from Appendix B of this document
  ```

  RFC 5652 has no Appendix B. The imported module is in §12.2.
- **Kind:** erratum (editorial).
- **Official errata:** [6546](https://www.rfc-editor.org/errata/eid6546), **verified**.
- **Impact:** none, since it's a comment. Our extracted copy keeps it.
- **Resolution:** none needed. Recorded because the cross-reference had to be resolved by hand during #22.

### F-004: RFC 9286 imports from RFC 6268 without referencing it

- **Where:** RFC 9286, Appendix A:

  ```asn1
  IMPORTS
    CONTENT-TYPE
    FROM CryptographicMessageSyntax-2010 -- in RFC 6268
  ```

  RFC 6268 isn't listed in RFC 9286's references (§10.1 Normative or §10.2 Informative). Compare RFC 9582, whose module has the same import and lists RFC 6268 as a normative reference (§8.1).
- **Kind:** reference.
- **Official errata:** none found (checked 2026-11-12). **Not reported**; this is a candidate for an editorial erratum.
- **Impact:** an implementer working only from the RFC 9286 reference list wouldn't know they need RFC 6268 to compile the module.
- **Resolution:** the `CONTENT-TYPE` import is patched out (F-005, #23).

### F-005: RPKI content modules depend on a different CMS module generation

- **Where:**
  - The ROA (RFC 9582 §4), manifest (RFC 9286 App. A) and RSC (RFC 9323) modules import `CONTENT-TYPE` from `CryptographicMessageSyntax-2010` (RFC 6268), which uses X.680 2002-style information object classes.
  - The envelope those objects travel in is defined by the RPKI signed object template (RFC 6488), which builds on RFC 5652. Its module, `CryptographicMessageSyntax2004`, uses 1988-style syntax.
- **Kind:** reference.
- **Official errata:** none. This is a design choice, not an error.
- **Impact:**
  - Compiling the content modules requires a second, newer generation of CMS modules that isn't otherwise needed, and isn't in the set of RFCs an RPKI relying party is built from.
  - `CONTENT-TYPE` only links each content-type OID to its eContent type; it doesn't affect encoding.
- **Resolution:** maintainer decision (2026-11-12). The import and the `ct-…` information objects are patched out. The OIDs and types are kept as written, and the OID-to-type link becomes explicit code in the CMS decoder. Documented in #23 and #29.

### F-006: CMS module imports from an obsoleted RFC

- **Where:** RFC 5652 §12.1 and §12.2:

  ```asn1
  -- Imports from RFC 3281 [ACPROFILE], Appendix B
  AttributeCertificate
     FROM PKIXAttributeCertificate
  ```

  RFC 3281 was obsoleted by RFC 5755 (2010), one year after RFC 5652 was published.
- **Kind:** reference.
- **Official errata:** none (this isn't an error in RFC 5652 as published).
- **Impact:** the CMS module doesn't compile without a module from an obsolete RFC that isn't in our library. RPKI signed objects never carry attribute certificates: the `certificates` field contains exactly one EE certificate (RFC 6488 §2.1.4).
- **Resolution:** open, in #23.

### F-007: RFC 5280 modules redefine built-in string types

- **Where:** RFC 5280 Appendix A.1 defines three string types itself, under the comment `-- UNIVERSAL Types defined in 1993 and 1998 ASN.1 and required by this specification`:

  ```asn1
  UniversalString ::= [UNIVERSAL 28] IMPLICIT OCTET STRING
  BMPString ::= [UNIVERSAL 30] IMPLICIT OCTET STRING
  UTF8String ::= [UNIVERSAL 12] IMPLICIT OCTET STRING
  ```

  Appendix A.2 imports two of them from A.1, and **its own comment anticipates the fix**:

  ```asn1
  -- delete following line if "new" types are supported --
  BMPString, UTF8String,  -- end "new" types --
  ```
- **Kind:** tooling. The modules use 1988 ASN.1 syntax, and these lines supply types that 1988 compilers didn't know.
- **Official errata:** none, since this is intentional.
- **Impact:** OTP's `asn1ct` (OTP 29) treats these types as built-in and fails: A.1 with `syntax error before: 'UniversalString'`, and A.2 with `syntax error before: 'BMPString'`, on the import. The modules don't compile as published.
- **Resolution:** documented patches (#23) remove the A.1 definitions and delete the A.2 import line, exactly as A.2's comment instructs. The encoding is identical, because the built-in types have the same universal tags.
- **Talk note:** a 2008 RFC carries workarounds for 1988 compilers, plus instructions for removing them once compilers caught up. Eighteen years later, removing them is required.

### F-008: certificate signature field has two names

- **Where:** RFC 5280 §4.1 names the third field of `Certificate` `signatureValue`. Appendix A.1, the normative module, names it `signature`.
- **Kind:** ambiguity, editorial only, since field names don't affect encoding.
- **Official errata:** [7634](https://www.rfc-editor.org/errata/eid7634), held for document update. The same inconsistency goes back to RFC 2459 and RFC 3280.
- **Impact:** the name used in Lumina's certificate struct and in `lumina --print` output.
- **Resolution:** decide in #27. The ASN.1 compiler will use the module's name (`signature`).

## Process notes

These aren't RFC problems, but they're relevant to the same talks.

- **Machine-checked citations catch our own mistakes.** The ASN.1 extractor checks that each module sits in the RFC section we attribute it to. On its first run, it caught that #22 cited the manifest module as RFC 9286 §4.2; it's in Appendix A. (2026-11-12, PR #35)
- **Errata review is now part of the work.** Before relying on an RFC's module or example, check its errata. F-001 and F-002 were found only because we looked.

## How to add an entry

1. Give it the next `F-NNN` ID, and add a row to the summary.
2. Quote the text, and give the RFC section.
3. Check the [errata database](https://www.rfc-editor.org/errata.php) for the RFC, and record the erratum ID and status, or "none found" with the date.
4. Say what it means for Lumina and link the issue or PR that resolves it.
5. Add a **talk note** if there's a broader lesson.
