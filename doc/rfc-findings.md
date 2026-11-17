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

Where a live repository departs from the RFCs, or its servers from what everyone else's accept, the entry goes under [TA deviations](#ta-deviations) instead, numbered `TD-NNN`: those aren't gaps in the RFC texts.

## Summary

| ID | RFC | Kind | Official errata | Status in Lumina |
| --- | --- | --- | --- | --- |
| [F-001](#f-001-manifest-filelist-allows-an-empty-list) | 9286 App. A | erratum | [7118](https://www.rfc-editor.org/errata/eid7118), verified | Module kept as published; rejected by validation (#37) |
| [F-002](#f-002-rfc-3779-worked-example-has-wrong-bytes) | 3779 App. B | erratum | [6792](https://www.rfc-editor.org/errata/eid6792), verified | Tests use corrected values (#26) |
| [F-003](#f-003-cms-module-points-to-a-non-existent-appendix-b) | 5652 §12.1 | erratum | [6546](https://www.rfc-editor.org/errata/eid6546), verified | No effect (comment only) |
| [F-004](#f-004-rfc-9286-imports-from-rfc-6268-without-referencing-it) | 9286 App. A | reference | none (not reported) | Patched out (#23) |
| [F-005](#f-005-rpki-content-modules-depend-on-a-different-cms-module-generation) | 9582 §4, 9286 App. A, 9323 | reference | none | Patched out (#23) |
| [F-006](#f-006-cms-module-imports-from-an-obsoleted-rfc) | 5652 §12.1, §12.2 | reference | none | Opaque placeholders (#23) |
| [F-007](#f-007-rfc-5280-modules-redefine-built-in-string-types) | 5280 A.1, A.2 | tooling | none | Patched (#23) |
| [F-008](#f-008-certificate-signature-field-has-two-names) | 5280 §4.1 vs A.1 | ambiguity | [7634](https://www.rfc-editor.org/errata/eid7634), held for document update | Module names used (#27) |
| [F-009](#f-009-cms-and-attribute-certificate-modules-import-from-each-other) | 5652 §12.1, 5755 App. B | reference | none found | Avoided by F-006 placeholders (#23) |
| [F-010](#f-010-no-rule-for-data-after-the-encoded-object) | 6481 §2.2, 6488 §3 | ambiguity | none found (not reported) | Trailing bytes rejected (#24, #25) |
| [F-011](#f-011-asn1ct-error-reasons-carry-stack-traces) | (OTP `asn1ct`) | tooling | n/a | Wrapper shortens reasons (#24) |
| [F-012](#f-012-the-roa-module-enforces-the-afi-rule-at-decode-time) | 9582 §4, §4.3.1, §4.3.2 | tooling | none | Accepted; decode error citing §4.3.1 (#24, #30, #171) |
| [F-013](#f-013-the-address-sort-key-has-a-part-that-never-matters) | 3779 §2.2.3.6 | ambiguity | none found (not reported) | Sort by lowest address (#26) |
| [F-014](#f-014-two-rfc-3779-errata-change-what-a-decoder-must-accept) | 3779 §2.2.3.9, §3.2.3.8 | erratum | [2537](https://www.rfc-editor.org/errata/eid2537) verified, [7653](https://www.rfc-editor.org/errata/eid7653) held | Both followed (#26) |
| [F-015](#f-015-two-conforming-validators-can-disagree-on-unknown-extensions) | 6487 §4.1, §4.8, §5; 8897 §3.1, §3.3 | ambiguity | none found (not reported) | Versions settled by 8897; unknown non-critical extensions accepted with a warning (D-013, #42) |
| [F-016](#f-016-no-rfc-says-how-a-repository-directory-uri-ends) | 6487 §4.8.8.1 | ambiguity | none found (not reported) | Both forms handled in M3 (#43) |
| [F-017](#f-017-rfc-6487-still-points-to-the-obsolete-algorithm-profile) | 6487 §4.3, §4.7, §5, §6.1.1; also 7935, 8630 | reference | none found (not reported) | Use the current RFCs |
| [F-018](#f-018-rfc-9582-tells-cas-that-relying-parties-will-change-their-minds) | 9582 §4.3.2.2, §4.3.3 | ambiguity | none (by design) | Warn, not reject (D-030, #171) |
| [F-019](#f-019-manifest-times-inherit-a-crl-rule-they-cannot-follow) | 9286 §4.2.1 | ambiguity | none found (not reported) | RFC 5280 GeneralizedTime rules enforced (#48) |
| [F-020](#f-020-a-repository-file-extension-for-an-object-banned-from-repositories) | 9323 §2, §9.3; 6481 §7.2 | ambiguity | none found (not reported) | `.sig` recognized; repository policy in M5 |
| [F-021](#f-021-the-tal-grammar-leaves-whitespace-and-blank-lines-open-and-its-example-is-indented) | 8630 §2.2, §2.4 | ambiguity | none found (not reported) | Strict grammar, whitespace warns (D-002, #54) |
| [F-022](#f-022-the-whole-rp-procedure-for-tals-is-a-should) | 8630 §3 | ambiguity | none found (not reported) | Lumina performs every step (#56) |
| [F-023](#f-023-a-non-empty-set-of-resources-across-one-or-two-extensions) | 8630 §2.3; 3779 App. A | ambiguity | none found (not reported) | Each present extension must be non-empty (#56) |
| [F-024](#f-024-the-rsync-uri-scheme-has-no-module-and-no-encoding) | 5781 §2 | ambiguity | none found (not reported) | Module = first path segment; percent-encoding rejected (#70) |
| [F-025](#f-025-an-rsync-uri-path-can-become-an-option-on-the-server) | 5781 §2, §4; 6487 §4.8.8 | tooling | none found (not reported) | Source written as `module/./path` when the path starts with `-` (#72, #189) |
| [F-026](#f-026-otps-http-client-cant-bound-a-response-body) | 8630 §4 (OTP `:httpc`) | tooling | n/a | Own HTTP/1.1 GET over `:ssl` (#73) |
| [F-027](#f-027-rfc-7935-names-a-signature-algorithm-as-the-public-key-algorithm) | 7935 §3.1; 4055 §1.2 | erratum | [5737](https://www.rfc-editor.org/errata/eid5737) (Rejected) | Accept both for reading the key; the profile check is #109 |
| [F-028](#f-028-rfc-7935-4-cites-the-public-key-section-for-the-signature-format) | 7935 §4 | reference | none found (not reported) | Signature format from RFC 4055 §3.2 and RFC 5280 §4.1.1.3 (#108) |
| [F-029](#f-029-barry-gives-the-root-certificate-serial-number-0) | 6487 §4.2; 5280 §4.1.2.2 (Barry) | tooling | n/a | Every fixture sets the TA serial to 1 (#109) |
| [F-030](#f-030-barry-cant-set-the-certificate-policies-value) | 6487 §4.8.9; 7318 §2 (Barry) | tooling | n/a | Policy rules tested on decoded certificates (#110) |
| [F-031](#f-031-rfc-7935-2-takes-rsaencryptions-parameters-from-rfc-3370-outside-the-library) | 7935 §2; 3370 §3.2 | reference, tooling | none found (not reported) | RFC 3370 added; rsaEncryption parameters must be NULL, absent only warns because Barry omits them (#129, #130) |
| [F-032](#f-032-manifest-file-name-extensions-depend-on-an-iana-registry-outside-the-library) | 9286 §4.2.2; 6481 §7.2 | reference | none found (not reported) | Extensions from the IANA registry as of 2026-11-14, temporary and deprecated entries included (#132) |
| [F-033](#f-033-inheriting-resources-the-issuer-doesnt-hold) | 3779 §2.2.3.5, §3.2.3.3; 9286 §5.1 | ambiguity | none found (not reported) | Inheriting nothing is holding nothing (D-026, #153) |
| [F-034](#f-034-encompass-is-worded-range-by-range) | 6487 §7.1; 3779 §2.3, §3.3 | ambiguity | [5188](https://www.rfc-editor.org/errata/eid5188), held (related); otherwise none found (not reported) | Compared as sets (D-027, #152) |
| [F-035](#f-035-what-using-inherit-asks-of-a-manifest-ee-certificate) | 9286 §5.1 | ambiguity | none found (not reported; to report) | Explicit kinds warn, absent ones don't (D-029, #157) |
| [F-036](#f-036-a-verified-erratum-makes-the-solidus-an-escape-only-character) | 8259 §7 | erratum | [5318](https://www.rfc-editor.org/errata/eid5318), verified (editorial) | `/` written unescaped, as the prose allows (#167) |
| [F-037](#f-037-a-delta-publish-doesnt-say-when-its-hash-is-required) | 8182 §3.4.2, §3.5.4 | gap | [6919](https://www.rfc-editor.org/errata/eid6919), held for document update | Enforced as the erratum says (#204) |
| [F-038](#f-038-barry-writes-session_id-1) | 8182 §3.5.1.3 | tooling | — | Fixtures set `session` to a version 4 UUID (#202) |
| [F-039](#f-039-rfc-8182-cites-no-xml-specification) | 8182 §3.5, §7 | missing reference | none found (not reported) | XML 1.0 (Fifth Edition) for the subset RRDP needs (D-041, #198) |
| [F-040](#f-040-rfc-8182-cites-obsoleted-http-rfcs) | 8182 §3.4.1, §3.4.4, §7 | obsolete reference | none found (not reported) | RFC 9110 §13.1.3 and RFC 9112 for the HTTP side (#200) |
| [F-041](#f-041-rfc-8182-doesnt-say-a-snapshot-publishes-each-uri-once) | 8182 §3.5.2.3 | ambiguity | none found (not reported) | A URI published twice rejects the snapshot (`duplicate_publish`, #203) |

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
  - M5 manifest validation rejects it with "manifest has no entries (RFC 9286 §7, erratum 7118)" (#37). Done: `Lumina.Manifest.check/1`'s rule `manifest_empty`, fixture `m5-mft-empty-file-list`; the publication point fails (and, since the CA's CRL isn't listed, for that too).
  - The alternative was rejected: patching the module to `1..MAX` would make an empty manifest fail as a generic decode error, if the compiler enforces size constraints at all, and the object couldn't be inspected.
- **Talk note:** extracting a module "verbatim from the RFC" faithfully reproduces known, verified errors. The RFC text is not the whole specification; the errata are part of it.

### F-002: RFC 3779 worked example has wrong bytes

- **Where:** RFC 3779, Appendix B, the DER example of an IP address delegation extension.
- **Kind:** erratum (technical).
- **Official errata:** [6792](https://www.rfc-editor.org/errata/eid6792), **verified** (2021). The example encodes `b010` where `172.16/12` needs `ac10` (172 is `0xac`), and it encodes one IPv6 prefix as `/47` where the text before the example says `/48`.
- **Impact:** #26 planned to test the RFC 3779 decoder against "the values the RFC states" in Appendices B and C. Using the bytes as printed would make a correct decoder fail, or "prove" an incorrect one.
- **Resolution (#26):**
  - The test uses the erratum-corrected bytes and cites erratum 6792.
  - A second test decodes the bytes **as printed**, and shows they mean `176.16/12`.
- **Detail:** the two errors are different in kind. For IPv4 the **bytes** are wrong (`b010`). For IPv6 the bytes are right (`03 07 00 200100000002` is 48 bits, so `/48`), and only the **annotation** next to them says `/47`.
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
- **Resolution (#23):** the CMS module's imports of `AttributeCertificate` (RFC 3281) and `AttributeCertificateV1` (§12.2, which itself imports from RFC 3281) are replaced by local opaque types, `SEQUENCE OF ANY`.
  - Attribute certificates still decode, as a list of undecoded elements, so nothing that was decodable becomes undecodable.
  - M5 rejects any certificate choice other than the single EE certificate anyway.
  - The §12.2 module is no longer extracted.
  - Using RFC 5755 instead was considered and rejected (F-009).

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
- **Resolution:** documented patches (#23) remove the A.1 definitions and delete the A.2 import line, exactly as A.2's comment instructs. RFC 3779's module, which failed with `illegal_oid` on an import from A.1, compiles unpatched once A.1 does. The encoding is identical, because the built-in types have the same universal tags.
- **Talk note:** a 2008 RFC carries workarounds for 1988 compilers, plus instructions for removing them once compilers caught up. Eighteen years later, removing them is required.

### F-008: certificate signature field has two names

- **Where:** RFC 5280 §4.1 names the third field of `Certificate` `signatureValue`. Appendix A.1, the normative module, names it `signature`.
- **Kind:** ambiguity, editorial only, since field names don't affect encoding.
- **Official errata:** [7634](https://www.rfc-editor.org/errata/eid7634), held for document update. The same inconsistency goes back to RFC 2459 and RFC 3280.
- **Impact:** the name used in Lumina's certificate struct and in `lumina --print` output.
- **Resolution (#27):** `Lumina.Certificate` follows the normative module (A.1):
  - the value is `signature`;
  - the outer `AlgorithmIdentifier` is `signature_algorithm`;
  - the `AlgorithmIdentifier` inside `tbsCertificate` is `tbs_signature_algorithm`. In A.1 that field is also called `signature`, which makes the naming confusing twice over.

### F-009: CMS and attribute certificate modules import from each other

- **Where:** RFC 5652 §12.1 (`CryptographicMessageSyntax2004`) imports `AttributeCertificate` from `PKIXAttributeCertificate`, the RFC 3281 module. RFC 5755, which obsoletes RFC 3281, defines its module in Appendix B under a **new name**, `PKIXAttributeCertificate-2008`, and that module **imports `ContentInfo` from `CryptographicMessageSyntax2004`**:

  ```asn1
  ContentInfo
    FROM CryptographicMessageSyntax2004
  ```
- **Kind:** reference.
- **Official errata:** none found (checked 2026-11-12). RFC 5755 has a verified erratum on its Appendix B imports ([6567](https://www.rfc-editor.org/errata/eid6567), an unused `CRLDistributionPoint` import), but nothing about this.
- **Impact:** to satisfy the CMS import with the current RFC, you would have to:
  - add RFC 5755 to the library,
  - rename the import in the CMS module (the name no longer matches), and
  - compile two modules that import from each other.

  Compilers that work one module at a time, such as `asn1ct`, can't compile such a cycle directly.
- **Resolution:** not attempted. The CMS module gets opaque attribute certificate types instead (F-006, #23).
- **Talk note:** obsoleting an RFC doesn't update the modules that import from it. Module names change, and dependencies can turn into cycles.

### F-010: no rule for data after the encoded object

- **Where:** RFC 6481 §2.2 says, for two object types only:

  > Each ".crl" file contains exactly one CRL encoded in DER format.
  >
  > Each ".cer" file contains exactly one certificate encoded in DER format.

  The same section says nothing comparable for manifests or other signed objects (ROAs and others). RFC 6488 §3, the checks a relying party must make on every signed object, only requires:

  > l. The signed object is DER encoded.

  No RFC in the library says what a relying party must do when a file holds a valid encoding **followed by more bytes**.
- **Kind:** ambiguity. A file of "valid DER + junk" arguably isn't "a DER-encoded object", but no RFC says so, and the CRL/certificate wording ("contains exactly one") can be read as allowing other content around the object.
- **Official errata:** none found for RFC 6481 or RFC 6488 (checked 2026-11-12). **Not reported**; a candidate for clarifying text.
- **Why it happens:** BER and DER decoders read one tag-length-value and stop. Anything after it is "the rest", and what happens to it is up to the library. OTP's `asn1ct` generated `decode/2` **discards it silently** unless the module is compiled with `undec_rest`. During #24, a TA certificate with two bytes appended decoded as valid.
- **Why it matters:**
  - **Parser differential.** If one relying party rejects such a file and another accepts it, they produce different VRP sets from the same repository.
  - **Smuggled data.** The manifest hash covers the whole file, so appended bytes don't break integrity checks, and they can travel inside an otherwise "valid" object.
- **Resolution in Lumina:**
  - The ASN.1 modules are compiled with `undec_rest`, and `Lumina.ASN1.decode/3` rejects any leftover bytes with `{:trailing_bytes, n}` (#24).
  - The strict DER checker (#25) also rejects trailing bytes, so there are two layers.
- **Suggested improvements:**
  - **RFC text.** In RFC 6481 §2.2, state it once for every object type instead of per type: *"Each file in a publication point MUST contain exactly one DER-encoded object and no other data."* In RFC 6488 §3, add a check: *"m. The file containing the signed object consists of exactly one DER encoding; no octets follow the end of the encoding."* The second matters most, because §3 is the checklist relying parties follow.
  - **ASN.1 modules.** Nothing to change. ASN.1 describes values, not files, so "no data after the value" can't be expressed in a module; it has to be said in prose.
  - **Tooling.** Decoders used for security-relevant input should treat leftover bytes as an error by default.
- **Talk note:** the specs define the object precisely and never define the file around it. A default "decode the first value, ignore the rest" turns that gap into a disagreement between implementations.

### F-011: `asn1ct` error reasons carry stack traces

- **Where:** not in any RFC. This is OTP's ASN.1 compiler.
- **Kind:** tooling. Recorded because it shaped Lumina's decoding layer.
- **Why it happens:** the generated `decode/2` catches failures inside the generated code and returns them as `{error, {asn1, {Reason, Stacktrace}}}`, to help debug generated code. The reason that matters, for example `{invalid_value, 0}`, sits next to a list of internal stack frames.
- **Impact:** error values are bulky, expose generated-code internals in messages, and can change between OTP versions, which makes them poor test assertions. Some malformed input also makes the generated code exit instead of returning an error (see F-012).
- **Resolution in Lumina:** `Lumina.ASN1` keeps only the reason (`{:asn1, {:invalid_value, 0}}`), turns exits and exceptions into `{:error, ...}`, and never raises (#24). A test feeds it 2000 random inputs.
- **Suggested improvements:** none for the RFCs or modules. An `asn1ct` option to return errors without the stack trace would remove the need for the wrapping.

### F-012: the ROA module enforces the AFI rule at decode time

- **Where:** RFC 9582 §4 (ASN.1 module) constrains `addressFamily` with an information object set:

  ```asn1
  addressFamily ADDRESS-FAMILY.&afi ({AddressFamilySet}),
  ...
  AddressFamilySet ADDRESS-FAMILY ::=
    { addressFamilyIPv4 | addressFamilyIPv6 }
  ```

  The prose agrees (§4.3.1): "addressFamily MUST be either 0001 or 0002."
- **Kind:** tooling. The RFC is consistent; this note is about where the rule ends up being enforced.
- **Official errata:** none.
- **Impact:** a compiler that honours table constraints, as `asn1ct` does, makes the **decoder** reject any other AFI: the generated code exits. In Lumina this is the one RFC 9582 rule that fails at decode time rather than in validation (M7), so its error is a generic decode error instead of "AFI must be IPv4 or IPv6 (RFC 9582 §4.3.1)". Dialyzer flags the generated lookup functions, because they only ever exit (ignored in `.dialyzer_ignore.exs`).
- **Resolution:** accepted. The rule is unambiguous, and patching the constraint out would break the rule that patches never change what is accepted. The decoder turns the exit into an error, and a test covers AFI 3 (#24). Since #171, `Lumina.ROA.decode_econtent/1` names it: after an ASN.1 failure it walks the DER without a schema and, for an AFI other than 0001 or 0002, returns `invalid_address_family` citing §4.3.1.
- **More of the same (#30):** the module's parameterized type `ROAIPAddress {INTEGER: ub}` binds `address BIT STRING (SIZE(0..ub))` and `maxLength INTEGER (0..ub)` to 32 or 128 through the same information object set. So a maxLength of 33 in an IPv4 family also fails at decode time, while a maxLength **below** the prefix length (the other half of the same §4.3.2.2 MUST) decodes and is left to validation. One sentence of the RFC ends up enforced in two layers.
- **Talk note:** information object sets put validation rules inside the ASN.1, so the same rule can fail in the decoder or in validation, depending on the toolchain.

### F-013: the address sort key has a part that never matters

- **Where:** RFC 3779 §2.2.3.6:

  > The addressPrefix and addressRange elements MUST be sorted using the binary representation of:
  >
  >    <lowest IP address in range> | <prefix length>
- **Kind:** ambiguity.
- **Official errata:** none found (checked 2026-11-12). **Not reported.**
- **The problem:**
  1. An `addressRange` has no prefix length, so for half of the element types the second part of the key is undefined.
  2. It never matters. The same section says entries "MUST NOT overlap", and two entries with the same lowest address always overlap. In a valid extension, the lowest address alone already gives a strict order, and the `| <prefix length>` part never breaks a tie.
- **Impact:** none for decoding. A checker that tries to build the key literally has to invent a "length" for ranges.
- **Resolution in Lumina:** `Lumina.Resources.ip_issues/1` sorts by `{lowest, highest}` address. That is equivalent for valid input and well-defined for ranges. Overlaps are reported separately (#26).
- **Suggested text:** *"…MUST be sorted by ascending lowest IP address in the prefix or range."* Optionally add: *"Since elements MUST NOT overlap, no two elements share a lowest address."*
- **Talk note:** the example in §2.2.3.6 exists to warn against sorting by the DER bytes. The key it introduces for that purpose carries a component that can never decide anything.

### F-014: two RFC 3779 errata change what a decoder must accept

- **Where:**
  - RFC 3779 §2.2.3.9 said a range's maximum address "MUST contain at least one bit whose value is 1, i.e., the subsequent octets may not be omitted nor all zero".
  - RFC 3779 §3.2.3.8 doesn't require an `ASRange`'s ends to differ.
- **Kind:** erratum (technical), two of them.
- **Official errata:**
  - [2537](https://www.rfc-editor.org/errata/eid2537), **verified**: the §2.2.3.9 sentence should be **deleted**. It contradicts the encoding rule. For example, the maximum `0.0.0.255` encodes as 24 zero bits (`03 04 00 00 00 00`).
  - [7653](https://www.rfc-editor.org/errata/eid7653), held for document update: an `ASRange`'s min and max "MUST specify two distinct AS identifiers", in line with RFC 3779 §1's goal of a unique, canonical encoding.
- **Impact:** a decoder that follows the published §2.2.3.9 text rejects valid range maximums. A canonical-form check that ignores 7653 accepts a range written where a single id belongs.
- **Resolution (#26):**
  - Lumina doesn't check the deleted rule. A test decodes `0.0.0.1-0.0.0.255`, whose maximum has no one bits, with no issue reported.
  - `as_issues/1` reports equal range ends as `:range_single`, citing 7653.
- **Talk note:** a verified erratum that **deletes** a MUST is easy to miss. Reading only the RFC, you would implement a rule that rejects valid encodings.

### F-015: two conforming validators can disagree on unknown extensions

- **Where:**
  - RFC 6487 §4.1 says the version "MUST be 3", then for relying parties: "RPs need not process version 1 or version 2 certificates".
  - RFC 6487 §4.8 says: "A certificate-using system MUST reject the certificate if it encounters a critical extension it does not recognize; however, a non-critical extension MAY be ignored if it is not recognized".
  - RFC 8897 §3.1, the relying party requirements, says: "An RP is required to verify that a resource certificate adheres to the profile established by Section 4 of [RFC6487]. … any extension excluded by Section 4.8 of [RFC6487] must be omitted."
- **Kind:** ambiguity: requirements on relying parties phrased as permissions.
- **Official errata:** none found for RFC 6487 or RFC 8897 (checked 2026-11-12). **Not reported.**
- **The problem:**
  - **Version:** "need not process" isn't "MUST reject". RFC 8897 §3.1 settles it, since an RP must verify adherence to the §4 profile, so a v1 or v2 certificate is rejected.
  - **CRL version:** RFC 6487 §5 has the same pattern: "RPs are NOT required to process version 1 CRLs". RFC 8897 §3.3 settles it indirectly. It requires the AKI and CRL Number extensions and makes RPs verify that, and a v1 CRL can't carry extensions, so it fails.
  - **Unknown non-critical extensions:** not settled.
    - "MAY be ignored" lets one RP ignore the extension and another reject the certificate.
    - RFC 8897's "any extension excluded by Section 4.8" doesn't help, because §4.8 lists mandatory extensions and never lists excluded ones. Whether "not listed" means "excluded" is exactly the question.
- **Impact:** a CA that adds an unknown non-critical extension gets its certificate accepted by some validators and rejected by others, which means different VRP sets. This is the same parser-differential risk as F-010.
- **Resolution:**
  - Version: reject v1/v2 (fixture `m1-cert-version-2`).
  - Unknown non-critical extensions: **accepted with a warning** (D-013, maintainer decision 2026-11-13, #42; fixture `m4-cert-unknown-extension`, `Lumina.Profile.extensions/2`, #110). A CRL extension in a certificate is treated the same way: Lumina knows it, but it has no meaning there.
  - Unknown critical extensions: reject, as §4.8 requires (fixture `m1-cert-unknown-critical-extension`).
  - The decoder keeps every unknown extension, with its criticality, so any decision can be implemented.
- **Data point (2026-11-12):** in a full rsync copy of LACNIC's repository, **none of the 3,514 certificates** carries an unknown extension, critical or not, and all are version 3. So for LACNIC's repository today, the #42 decision changes no verdicts.
- **Suggested text:** RFC 6487 §4.8 could state the RP rule directly, for example *"A relying party MUST reject a resource certificate that contains any extension not listed in this section."* RFC 8897 §3.1 could then point to that sentence.
- **Talk note:** "MAY" in a list of RP requirements means two compliant implementations are allowed to disagree, and in a routing security system disagreement is the failure mode.

### F-016: no RFC says how a repository directory URI ends

- **Where:** RFC 6487 §4.8.8.1: the SIA `id-ad-caRepository` accessLocation is an rsync URI that "points to the directory containing all published material issued by this CA". RFC 6481 describes publication points as directories. Neither says whether the URI ends in `/`.
- **Kind:** ambiguity.
- **Official errata:** none found (checked 2026-11-12). **Not reported.**
- **Found:** decoding Barry's certificates (#27). Barry writes `rsync://localhost:8873/rpki/ca1` with no trailing slash, which is valid as far as the RFCs go.
- **Impact:**
  - **Copy semantics:** for rsync, `rsync://host/module/dir` and `rsync://host/module/dir/` behave differently, since a trailing slash copies the directory's contents rather than the directory.
  - **Comparisons:** code that compares, joins or caches repository URIs as strings can treat the two forms as different publication points.
  - **Divergence:** validators that insist on one form diverge on certificates that use the other.
- **Resolution:** handled in M3 (#43). The fetcher normalizes both forms to the same directory and cache location.
- **Suggested text:** *"The id-ad-caRepository URI identifies a directory and MUST end with '/'"*, or alternatively *"relying parties MUST treat the URI as a directory whether or not it ends in '/'"*.

### F-017: RFC 6487 still points to the obsolete algorithm profile

- **Where:** RFC 6487 says "The algorithm used in this profile is specified in [RFC6485]" in five places (§4.3, §4.7, §5, and twice in §6.1.1 for certificate requests). RFC 6485 was obsoleted by RFC 7935 in 2016.
- **Kind:** reference.
- **Official errata:** none found for RFC 6487 (checked 2026-11-12). **Not reported.**
- **The problem:**
  - RFC 7935 obsoletes RFC 6485 but isn't marked as updating RFC 6487.
  - None of RFC 6487's updates (RFC 7318, RFC 8209, RFC 9829) changed these references.
  - A reader of RFC 6487 follows the citation to an obsolete document, and the RFC index entry for RFC 6487 gives no hint of RFC 7935.
- **Impact:** small in practice, since RFC 7935 keeps the same suite (RSA 2048, SHA-256), but an implementer must know to substitute it. Lumina's library holds RFC 7935 and lists RFC 6485 as obsoleted.
- **Resolution:** signature and key checks in M4 cite RFC 7935.
- **Same pattern elsewhere:** RFC 7935 (August 2016) cites RFC 3447 for RSASSA-PKCS1-v1_5 (§2). RFC 8017 obsoleted RFC 3447 three months later (November 2016). Lumina's library holds RFC 8017.
- **And in RFC 8630 (2019), the TAL specification:** it cites RFC 7230 for HTTPS (obsoleted by RFC 9110 and RFC 9112 in 2022), RFC 6486 for manifests (obsoleted by RFC 9286 in 2022) and RFC 7525 for TLS best practice (obsoleted by RFC 9325). Three of its references are now obsolete, all replaced after it was published.
- **Talk note:** the same pattern as F-006 and F-009. Obsoleting an RFC updates the metadata of the obsoleted document, not the documents that cite it.

### F-018: RFC 9582 tells CAs that relying parties will change their minds

- **Where:**
  - RFC 9582 §4.3.2.2: "The maxLength element SHOULD NOT be encoded if the maximum length is equal to the prefix length. Certification Authorities SHOULD anticipate that future Relying Parties will become increasingly stringent in considering the presence of superfluous maxLength elements an encoding error."
  - §4.3.3: "the process described in this section SHOULD be used … Certification Authorities SHOULD anticipate that future Relying Parties will impose a strict requirement for the ipAddrBlocks field to be in this canonical form."
- **Kind:** ambiguity, deliberate. The RFC defines a canonical form, makes it a SHOULD, and announces that RP behaviour will tighten later.
- **Official errata:** none, and none expected; this is by design.
- **Impact:** what a relying party should do today with a ROA holding a superfluous maxLength, or prefixes out of canonical order, is left open, and the RFC expects the answer to change over time. Relying parties that tighten at different times will disagree on the same ROA during the transition, the same divergence risk as F-010 and F-015.
- **Resolution:** `Lumina.ROA.issues/1` reports `:superfluous_max_length`, `:not_canonical_order` and `:duplicate_address`. The maintainer decided they only warn (D-030, 2026-11-15); `Lumina.ROA.check/2` gives them severity `:warning` and the ROA stays valid (#171). RFC 9582 has no errata (checked 2026-11-15).
- **Data point (2026-11-12):** a full rsync copy of LACNIC's repository decoded with Lumina's M1 decoders. **0 of 17,747 ROAs** show a superfluous maxLength, out-of-order or duplicate prefixes, or any other §4.3 issue. Enforcing the SHOULDs strictly would reject nothing in LACNIC's repository today.
- **Talk note:** a standard that schedules its own tightening ("future Relying Parties will…") turns the gap between relying parties into a planned phase. Being lenient is the safe choice for VRP output only until it isn't.

### F-019: manifest times inherit a CRL rule they cannot follow

- **Where:** RFC 9286 §4.2.1, on the manifest's `thisUpdate`: "This field has the same format constraints as specified in [RFC5280] for the CRL field of the same name." `nextUpdate` refers back to it. The manifest module types both fields as `GeneralizedTime`.
- **What RFC 5280 says for the CRL field (§5.1.2.4):** "CRL issuers conforming to this profile MUST encode thisUpdate as UTCTime for dates through the year 2049. CRL issuers conforming to this profile MUST encode thisUpdate as GeneralizedTime for dates in the year 2050 or later."
- **Kind:** ambiguity.
- **Official errata:** none found for RFC 9286, its predecessor RFC 6486, or RFC 9981 (checked 2026-11-12). **Not reported.**
- **The problem:**
  - Taken literally, the referenced constraints require UTCTime for every manifest dated before 2050, but the field can only hold GeneralizedTime.
  - So every manifest in existence would be non-conforming.
  - The rule that can actually carry over is RFC 5280 §4.1.2.5.2's GeneralizedTime profile: Zulu time, seconds present, no fractional seconds. That rule is stricter than DER, which allows fractions.
- **Impact:** a relying party that follows the reference literally rejects everything. One that ignores it accepts fractional seconds that RFC 5280's profile forbids. Two plausible readings give different verdicts on a fractional-second manifest.
- **Resolution:**
  - M5 checks manifest times against RFC 5280 §4.1.2.5.2 (#48). Done: `Lumina.Manifest.check/1`'s rule `manifest_time_format` rejects a thisUpdate or nextUpdate that isn't `YYYYMMDDHHMMSSZ`; a GeneralizedTime dated before 2050 is not rejected.
  - `Lumina.Time` keeps the raw value so the check can be precise.
  - Decoding accepts any DER GeneralizedTime.
- **Suggested text:** *"This field MUST be encoded as GeneralizedTime as specified in Section 4.1.2.5.2 of [RFC5280]."*
- **Talk note:** "same constraints as field X in document Y" imports everything about field X, including the parts that only make sense for X's type.

### F-020: a repository file extension for an object banned from repositories

- **Where:**
  - RFC 9323 §2: "because RSCs MUST NOT be distributed through the global RPKI repository system, the Subject Information Access (SIA) extension MUST be omitted from the RSC's X.509 End-Entity (EE) certificate."
  - RFC 9323 §9.3 nevertheless registers `.sig` in the "RPKI Repository Name Schemes" registry that RFC 6481 §7.2 created "for RPKI repository objects". RFC 6481 names the registry "Name Scheme", in the singular.
- **Kind:** ambiguity, minor.
- **Official errata:** none found (checked 2026-11-12). **Not reported.**
- **The problem:** the registry gives RSCs a repository file name, but the RFC never says what a relying party should do when a `.sig` file does turn up at a publication point, whether listed on a manifest or not. Ignore it? Treat the publication point as broken? Process it?
- **Impact:** small, but it's another place where relying parties may differ. For Lumina it matters as soon as M5 decides what to do with files of known but unexpected types.
- **Resolution:** `Lumina.Object` recognizes `.sig` as `:rsc` (#32). How a publication point treats it is decided with the rest of manifest processing in M5.
- **Talk note:** a registry called "repository name schemes" now includes the one object type that must never be in a repository.

### F-021: the TAL grammar leaves whitespace and blank lines open, and its example is indented

- **Where:** RFC 8630 §2.2 defines a TAL as an ordered sequence: optional comment lines, one or more URI lines, "a line break", then the base64 key, "To avoid long lines, line breaks MAY be inserted into the base64-encoded string."
- **Kind:** ambiguity.
- **Official errata:** none found for RFC 8630, RFC 7730 or RFC 6490 (checked 2026-11-12). **Not reported.**
- **What the grammar doesn't say:**
  1. Whether trailing whitespace on a line is allowed, and so whether `rsync://…/ta.cer ` is a valid URI line.
  2. Whether more than one blank line may separate the URIs from the key, or follow the key.
  3. Whether comments may appear after the first URI, or within the key.
  4. Whether the file may end with a line break after the key, or must.
  5. The comment text must conform to "Section 2 of [RFC5198]". That's a normative dependency on a document most RPKI implementers won't have read.
- **And its own example (§2.4) isn't a valid TAL as printed.** The example is indented by nine spaces, as RFC formatting does. Copied verbatim, the first line starts with spaces instead of `#`, so a strict parser sees an invalid URI on line 1. Test case `invalid-rfc-8630-example-as-printed` shows this, and `valid-rfc-8630-example` is the dedented version.
- **Impact:** parsers differ on all five points. Tolerant ones accept TALs that strict ones reject, so the same TAL file can work in one validator and fail in another.
- **Resolution:**
  - **D-002:** the grammar is followed strictly, and trailing whitespace is accepted with a warning.
  - **Point 4:** a final line break is optional; it ends the last line.
  - **Point 5:** comments must be valid UTF-8 without control characters (tab is tolerated). RFC 5198 isn't in the library, so this is a deliberately narrow reading of it.
  - Every point has a case in the test TAL corpus (#55), and `Lumina.TAL` reports a precise rule and line for each (#54).
- **Suggested text:**
  - Add to §2.2: *"Lines MUST NOT contain leading or trailing whitespace. Exactly one empty line separates the URI section from the key. Comment lines MUST NOT appear after the first URI."*
  - Mark the §2.4 example as indented for presentation only.
- **Talk note:** the one example in the specification can't be copied into a file and used.

### F-022: the whole RP procedure for TALs is a SHOULD

- **Where:** RFC 8630 §3: "In order to use the TAL to retrieve and validate a (putative) TA, an RP SHOULD: 1. Retrieve the object … 2. Confirm that the retrieved object is a current, self-signed RPKI CA certificate … 3. Confirm that the public key in the TAL matches the public key in the retrieved object. 4. Perform other checks, as deemed appropriate (locally) …"
- **Kind:** ambiguity.
- **Official errata:** none found (checked 2026-11-12). **Not reported.**
- **The problem:**
  - Every step, including step 3 (the TAL key must match the certificate's key), is a SHOULD.
  - §2.3 does say "The public key used to verify the TA MUST be the same as the subjectPublicKeyInfo in the CA certificate and in the TAL", but that sentence is about the TA, not about what the relying party must check.
  - Read literally, an RP that skips the key comparison is still conforming. Yet the key comparison is the only thing that ties a TA certificate to the TAL its operator distributed.
- **Impact:** in theory, an RP that accepts any self-signed certificate found at a TAL URI conforms to §3. In practice every serious validator checks the key, but the specification doesn't oblige it to.
- **Resolution:** Lumina performs every step as if it were a MUST. A key mismatch, a non-self-signed certificate, `inherit` or empty resources all make the TA unusable (#56). The "current" check (validity dates) and signature verification are M4.
- **Suggested text:** *"an RP MUST perform steps 1 to 3; step 4 is at the RP's discretion."*
- **Talk note:** the security of the whole RPKI starts at the TAL key comparison, and it's a SHOULD.

### F-023: "a non-empty set" of resources across one or two extensions

- **Where:** RFC 8630 §2.3: "The INR extension(s) of this TA MUST contain a non-empty set of number resources. It MUST NOT use the "inherit" form of the INR extension(s)."
- **Kind:** ambiguity.
- **Official errata:** none found (checked 2026-11-12). **Not reported.**
- **The problem:**
  - A TA can carry two INR extensions, IP addresses and AS numbers. "a non-empty set" is singular. Does the union of both have to be non-empty, or each extension that is present?
  - Take a TA with a present but empty IP extension (an `IPAddrBlocks` with no families) and a full AS extension. It passes the first reading and fails the second.
  - RFC 3779's ASN.1 makes such certificates possible: `IPAddrBlocks ::= SEQUENCE OF IPAddressFamily` has no `SIZE (1..MAX)`, and neither does `ASIdentifiers`, whose fields are both OPTIONAL. So an empty extension is valid DER.
  - Barry produces one with a single override.
- **Impact:** relying parties that read the rule differently disagree on such a TA, and so on its entire tree.
- **Resolution:** Lumina requires **each present** INR extension to be non-empty. An extension that is present but empty says nothing, and nothing legitimate needs it. Fixture `m2-ta-empty-ip` and `Lumina.TAL.check_ta/2` (#56) implement this.
- **Suggested text:** *"Each INR extension present in the TA MUST contain a non-empty set of number resources."*

### F-024: the rsync URI scheme has no module and no encoding

- **Where:** RFC 5781 §2 gives the generic form as `rsync://[user@]host[:PORT]/Source` and says the URI "follows the general syntax from RFC 3986". It also says: "Since the rsync URI is defined using standard elements from RFC 3986, no special encoding considerations are present."
- **Kind:** ambiguity.
- **Official errata:** none found for RFC 5781 or RFC 6481 (checked 2026-11-13). **Not reported.**
- **The problem:**
  - **No structure:** `Source` has no structure in the RFC. An rsync server serves named *modules*, and the first path segment selects one, but the word "module" doesn't appear in RFC 5781, RFC 6481 or RFC 6487. An RP that fetches whole modules relies on rsync's own convention, not on any RFC. (Lumina first planned to, D-006, then chose publication points instead, D-009.)
  - **No encoding:** RFC 3986 lets a path carry percent-encoded octets (§2.1). RFC 5781 doesn't say whether `%41` in an rsync URI means `A` or the three characters `%41` in a file name. Two RPs can therefore fetch different files for the same URI, or treat one file as two.
  - **Dot segments:** RFC 3986 §6.2.2.3 tells normalizers to remove `.` and `..`, but an RP that maps URIs to cache paths must decide whether to resolve them or reject them. Resolving `rsync://host/module/../../x` walks out of the module, and out of a cache directory too.
- **Impact:** every RP has to pick a reading. Different readings mean different fetches and different cache layouts for the same certificate, and a careless reading is a path-traversal bug.
- **Resolution:**
  - `Lumina.URI` (#70) takes the module to be the first path segment.
  - It rejects percent-encoding and dot segments outright, rather than decoding or resolving them.
  - It drops a trailing `/` (F-016).
- **Suggested text:** *"In RPKI, the first path segment of an rsync URI names an rsync module. RPKI rsync URIs MUST NOT contain percent-encoded octets or '.' or '..' segments."*
- **Talk note:** a URI scheme registered as "provisional", with one paragraph of semantics, carries the whole RPKI repository system. The interesting rules are rsync's, not the RFC's.

### F-025: an rsync URI path can become an option on the server

- **Where:**
  - RFC 5781 §4: "The security considerations of the rsync protocol are not covered in this document."
  - RFC 6487 §4.8.8: SIA URIs, including `caRepository`, are chosen by the CA that issues the certificate.
- **Kind:** tooling: the RFC text is fine, but the tool every RP uses behaves in a way it doesn't mention.
- **Official errata:** none found for RFC 5781 (checked 2026-11-13). **Not reported.**
- **Found:** by a test in #72 that fetched `rsync://host/module/--help`.
  - The rsync client sends the part of the path after the module to the server.
  - The rsync daemon (3.5.2 here) parses that as its own command line and rejected `--help/` as an unknown option.
  - `--secluded-args` (`-s`, formerly `--protect-args`) didn't change this in daemon mode.
- **Impact:**
  - **Who controls the path:** any CA can put any `caRepository` path in a certificate it issues, and every RP that fetches it passes that path to the named rsync server. A path segment starting with `-` reaches the server as an option, not a file name.
  - **Why it can't simply be rejected:** RPKI file and directory names can legitimately start with `-`, because base64url uses it.
- **Resolution:**
  - `Lumina.Rsync` wrote every source as `rsync://host/module/./path`. Without `--relative`, the `./` is a no-op, and nothing after it starts with `-`.
  - Since #189, only a path starting with `-` gets the `./`: APNIC's server refuses any path with a `./` segment (TD-001), and only the start of the path reaches the daemon's option parser.
  - Tests check both sides: `--help` is now just a missing file, at the start of the path or below it, and directories and files named `-x/-a.cer` still fetch.
- **Suggested text** (for RFC 6481 or a future rsync-in-RPKI document): *"Relying parties MUST ensure that no part of an rsync URI taken from a certificate is interpreted as an rsync option, on the client or the server."*
- **Talk note:**
  - The URI comes from the signed object, the path from the URI, and the option parser runs on someone else's server.
  - "Arguments as a list, no shell" isn't the end of injection. The protocol carries arguments too.
  - Found because a test tried an obvious hostile path.

### F-026: OTP's HTTP client can't bound a response body

- **Where:** RFC 8630 §4 has RPs fetch TA certificates over HTTPS, and RFC 9112 §6.3 lets a server end a response body by closing the connection, with no Content-Length.
- **Kind:** tooling: the RFCs are fine, but OTP's `:httpc` (inets 9.8.1) can't enforce a size limit on every response.
- **Official errata:** n/a.
- **Found:** while planning #73, by reading `httpc_handler.erl` and `httpc_response.erl`.
  - `max_body_size` is checked against a Content-Length and inside chunked decoding.
  - A body with neither is accumulated in memory until the server closes (`whole_body/2` with length -1).
  - `stream: :self` streams only 200 and 206 responses, so a non-200 body is always buffered whole.
- **Impact:** a hostile or broken server named in a TAL could make an RP built on `:httpc` hold any amount of data in memory, until the timeout ends it.
- **Resolution:** `Lumina.HTTPS` speaks a minimal HTTP/1.1 GET over `:ssl` itself. Every body (Content-Length, chunked or close-delimited) is bounded by the D-008 size limit, the head by 64 KiB, and every read by the overall timeout; a non-200 body isn't read at all. A test sends a close-delimited body past the limit.
- **Also, in `:ssl` (11.7.8):** `server_name_indication: :disable` doesn't only stop sending SNI, it also turns off the host name check, silently. A test connecting to `https://127.0.0.1/` with a certificate for `localhost` succeeded once that option was set. `Lumina.HTTPS` never sets it, and the test stays.
- **Talk note:** "no third-party dependencies" moves the trust to the standard library, and it needs the same reading.

### F-027: RFC 7935 names a signature algorithm as the public key algorithm

- **Where:** RFC 7935 §3.1, on subjectPublicKeyInfo: "The object identifier for RSA PKCS #1 v1.5 with SHA-256 MUST be used in the algorithm field, as specified in Section 5 of [RFC4055]." That OID is sha256WithRSAEncryption, a signature algorithm.
- **Kind:** erratum: RFC 4055 §1.2, which RFC 7935 itself cites for the key encoding, says rsaEncryption "MUST be used in the algorithm field within the subject public key information" when the key isn't restricted to PSS or OAEP. RPKI repositories, and every Barry fixture, use rsaEncryption.
- **Official errata:** [5737](https://www.rfc-editor.org/errata/eid5737), Technical, **Rejected** (2019-09-10). It proposed rsaEncryption; the verifier rejected it because a normative change needs SIDROPS working group consensus, not because it was wrong.
- **Found:** while writing `Lumina.Crypto` (#108), which has to decide which algorithm identifiers mark an RSA key.
- **Impact:** an RP that follows RFC 7935 §3.1 literally rejects the whole RPKI; one that follows RFC 4055 §1.2 rejects keys written to the letter of RFC 7935.
- **Resolution:** `Lumina.Crypto.rsa_public_key/1` reads the key under either OID: rsaEncryption with NULL parameters (RFC 4055 §1.2), or sha256WithRSAEncryption with NULL or absent parameters (RFC 4055 §5). RFC 4055 §1.2 says the RSAPublicKey is encoded the same way under any OID. Whether the certificate profile accepts both, warns, or rejects one is for the maintainer to decide in #109.
- **Talk note:** a rejected erratum isn't a wrong erratum. The status field records process, so "Rejected" can still mean "right, but not ours to change here".

### F-028: RFC 7935 §4 cites the public key section for the signature format

- **Where:** RFC 7935 §4: "The structure for the certificate's signature field is as specified in Section 1.2 of [RFC4055]."
- **Kind:** reference: RFC 4055 §1.2 is "RSA Public Keys" and says nothing about signature values. The conversion of a signature to the BIT STRING of a certificate or CRL is in RFC 4055 §3.2 (written for RSASSA-PSS), the PKCS #1 v1.5 algorithm identifiers in §5, and the field itself in RFC 5280 §4.1.1.3.
- **Official errata:** none found (2026-11-13, not reported).
- **Found:** while writing `Lumina.Crypto` (#108).
- **Impact:** small; the format is the obvious one (the octets of the signature, first bit first), but a reader following the citation finds nothing.
- **Resolution:** `Lumina.Crypto` cites RFC 4055 §3.2 and RFC 5280 §4.1.1.3 for the BIT STRING, and RFC 8017 §8.2.2 for its length.

### F-029: Barry gives the root certificate serial number 0

- **Where:** RFC 6487 §4.2 ("The serial number value is a positive integer") and RFC 5280 §4.1.2.2 ("The serial number MUST be a positive integer").
- **Kind:** tooling: Barry (pinned `478ee89`) numbers each certificate by its position among its siblings (`rpki_tree.c`, `child->serial = HASH_CNT(...)`), and never sets the root's, so every TA it writes has serial 0.
- **Official errata:** n/a.
- **Found:** writing the profile check for #109; every Barry fixture's TA failed it. The LACNIC repository copy in `test/realrepos/` has no certificate with a serial of 0 or below.
- **Impact:** an RP that checks §4.2 rejects every Barry-generated TA; one that doesn't check it passes tests that never exercise the rule.
- **Resolution:** every fixture's `case.repo` sets `obj.tbsCertificate.serialNumber = 1` on `ta.cer`, and all fixtures were regenerated. Worth raising with the Barry maintainers.

### F-030: Barry can't set the certificate policies value

- **Where:** RFC 6487 §4.8.9 as updated by RFC 7318 §2: exactly one policy, the RPKI CP, with at most one qualifier, a CPS pointer.
- **Kind:** tooling: Barry (pinned `478ee89`) can change the certificatePolicies extension's OID and criticality, but not its value (`ext.c`, `add_cp_fields`: "extnValue ... TODO not implemented yet"). It always writes id-cp-ipAddr-asNumber with no qualifier.
- **Official errata:** n/a.
- **Found:** writing the "wrong certificate policy" fixture that #110 asked for.
- **Impact:** no Barry fixture can carry another policy, two policies, or a qualifier, so the RFC 7318 rules can't be tested end to end with a signed repository.
- **Resolution:** the policy rules are tested on decoded fixture certificates with the extension value changed (`test/lumina/profile_extensions_test.exs`); the profile checks don't verify signatures, so that is enough for them. Once Barry writes this value, or the D-017 keys let tests re-sign certificates, a fixture can replace them. Worth raising with the Barry maintainers, with F-029.

### F-031: RFC 7935 §2 takes rsaEncryption's parameters from RFC 3370, outside the library

- **Where:** RFC 7935 §2: "The object identifier and parameters for rsaEncryption [RFC3370] MUST be used for the SignerInfo signatureAlgorithm field when generating CMS SignedData objects. RPKI implementations MUST accept either rsaEncryption or sha256WithRSAEncryption for the SignerInfo signatureAlgorithm field when verifying".
- **Kind:** reference: RFC 3370 isn't in `doc/rfc/`, so what "the parameters for rsaEncryption" are can't be read from the library. RFC 4055 §5, which is, says for sha256WithRSAEncryption that "the parameters MUST be NULL. Implementations MUST accept the parameters being absent as well as present."
- **Official errata:** none relevant found for RFC 7935 or RFC 6488 (2026-11-14; RFC 6488 erratum 8307 only corrects the wording of §2). Not reported.
- **Found:** writing the CMS profile checks (#129). Barry writes rsaEncryption with absent parameters.
- **Impact:** small; an RP that demanded NULL would reject Barry's objects.
- **Resolution:** `Lumina.CMS` accepts NULL or absent parameters for both signature algorithms and rejects anything else. Adding RFC 3370 to the library would settle it.
- **Update (2026-11-14, #130):** RFC 3370 was added to `doc/rfc/`. Its §3.2 says: "When the rsaEncryption algorithm identifier is used, the AlgorithmIdentifier parameters field MUST contain NULL", and unlike RFC 4055 §5 it doesn't ask implementations to accept them absent. Every signed object in the local LACNIC copy (21,259) has NULL; every Barry-generated one leaves them out (tooling). `Lumina.CMS.profile/1` now accepts NULL, warns `signature_algorithm_parameters_absent` (RFC 3370 §3.2) when absent, and rejects anything else. Making absent an error would need every fixture to declare its manifests as tree nodes so Barry can set the parameters, and all fixtures regenerated; the maintainer chose to keep the warning (D-025).

### F-032: Manifest file name extensions depend on an IANA registry outside the library

- **Where:** RFC 9286 §4.2.2: "The extension MUST be one of those enumerated in the 'RPKI Repository Name Schemes' registry maintained by IANA [IANA-NAMING]."
- **Kind:** reference: the registry's contents aren't in any one RFC. RFC 6481 §7.2 creates it (as "RPKI Repository Name Scheme", singular) with `.cer .crl .mft .roa`; RFC 6493 adds `.gbr`, RFC 9582 updates `.roa`, RFC 9323 §9.3 adds `.sig`, RFC 9691 adds `.tak`. The live registry (<https://www.iana.org/assignments/rpki/>, fetched 2026-11-14, last updated 2026-07-28) has more: `.asa` (ASPA, a temporary registration that "expires 2026-11-08"), `.ccr`, `.cdr` (temporary, expires 2027-06-23), and marks `.gbr` deprecated ("Moving RFC 6493 to Historic").
- **Official errata:** none relevant found for RFC 9286 or RFC 6481 (2026-11-14; RFC 9286 has 7118, F-001, and the rejected 7243). Not reported.
- **Found:** writing the manifest content checks (#132).
- **Impact:** the set of valid manifests changes with the registry. The local LACNIC copy's manifests list 177 `.asa` files: an RP that took the library's RFCs alone, or dropped `.asa` when its temporary registration lapsed, would reject those manifests and so fail whole publication points (RFC 9286 §4.4, §6.2).
- **Resolution:** `Lumina.Manifest` accepts every extension in the registry as fetched, temporary and deprecated entries included: `asa ccr cdr cer crl gbr mft roa sig tak`. The list is a constant to review when the registry changes; the maintainer may want `.asa` handled explicitly once ASPA is an RFC.

### F-033: Inheriting resources the issuer doesn't hold

- **Where:** RFC 3779 §2.2.3.5: "If the IPAddressChoice CHOICE contains the inherit element, then the set of authorized IP addresses for the specified AFI and optional SAFI is taken from the issuer's certificate, or from the issuer's issuer's certificate, recursively, until a certificate containing an IPAddressChoice containing an addressesOrRanges element is located." §3.2.3.3 says the same for AS identifiers. RFC 9286 §5.1, on the manifest's EE certificate: "This EE certificate MUST describe its Internet Number Resources (INRs) using the 'inherit' attribute, rather than an explicit description of a resource set (see [RFC3779]). (RPs are required to verify this.)"
- **Kind:** ambiguity.
- **Official errata:** none found for RFC 3779 (its errata mentioning inherit are about the Appendix B example, F-002), RFC 9286 or RFC 6487 (checked 2026-11-14). **Not reported.**
- **The problem:** RFC 3779 describes the search up the chain but not what happens when it finds no certificate with explicit resources of that kind: the issuer holds no IPv6, say, and neither does anyone above it. RFC 9286 §5.1 makes this an everyday case. A manifest's EE certificate must use inherit for its INRs, and producers write it for every kind (IPv4, IPv6 and AS numbers) whatever the CA holds.
- **Impact:** in the LACNIC repository (2026-11-14), 1,527 manifest EE certificates inherit a kind their CA doesn't hold: IPv4 (1,120), AS numbers (401) or IPv6 (192). An RP that treats an unsatisfiable inherit as an error fails all those manifests, and with them about 1,500 publication points and every ROA in them. Lumina did exactly that for an afternoon (D-026 as first decided).
- **Resolution:** inheriting a kind nobody above holds is holding nothing of it, with no error or warning (D-026, as revised, #153). Nothing is claimed, so nothing can be overclaimed.
- **Suggested text (RFC 3779 §2.2.3.5):** *"If no such certificate is located, the certificate holds no IP addresses for that AFI."* And likewise in §3.2.3.3.
- **Talk note:** a validator decision that looked cautious ("refuse to resolve an inherit to nothing") would have rejected 20% of a real repository. One SHOULD-sized sentence elsewhere (RFC 9286 §5.1) turns a corner case into the common case.

### F-034: "Encompass" is worded range by range

- **Where:** RFC 6487 §7.1: "Given two IP address and AS number sets, X and Y, X 'encompasses' Y if, for every contiguous range of IP addresses or AS numbers elements in set Y, the range element is either 'more specific' than or 'equal' to a contiguous range element within the set X." RFC 3779 §2.3: "the IP addresses in the IP address delegation extension of that certificate MUST be subsumed by IP addresses in the IP address delegation extension in the issuer's certificate" (§3.3 likewise for AS identifiers).
- **Kind:** ambiguity.
- **Official errata:** [5188](https://www.rfc-editor.org/errata/eid5188) (editorial, held for document update) changes "two IP address and AS number sets" to "two IP address or two AS number sets": the kinds are compared separately, which Lumina does. It doesn't touch the range-by-range wording. Nothing relevant for RFC 3779 §2.3 or §3.3 (checked 2026-11-14). **Not reported.**
- **The problem:** read literally, RFC 6487 §7.1 compares ranges: each range of the child must sit inside one range of the parent. RFC 3779 compares addresses. They differ when the parent lists adjacent ranges, say 10.0.0.0/9 and 10.128.0.0/9, and the child holds 10.0.0.0/8: every address of the child is the parent's, but no single parent range covers the child's.
- **Impact:** small in practice. RFC 3779 §2.2.3.6 requires adjacent blocks to be combined, so a canonical parent never lists 10.0.0.0/9 and 10.128.0.0/9; Lumina's profile rejects one that does. An RP that checks inclusion range by range without enforcing canonical form would reject valid delegations from a sloppy issuer.
- **Resolution:** compare as sets of numbers (D-027, #152).
- **Suggested text (RFC 6487 §7.1):** *"X 'encompasses' Y if every IP address or AS number in Y is also in X."*
- **Talk note:** the per-range wording is only safe together with a canonical-form rule from another document.

### F-035: What "using inherit" asks of a manifest EE certificate

- **Where:** RFC 9286 §5.1, on the manifest's EE certificate: "This EE certificate MUST describe its Internet Number Resources (INRs) using the 'inherit' attribute, rather than an explicit description of a resource set (see [RFC3779]). (RPs are required to verify this.)"
- **Kind:** ambiguity.
- **Official errata:** none found for §5.1. RFC 9286 has 7118 (Appendix A, F-001) and 7243 (rejected, §4.2.1) (checked 2026-11-15). **Not reported.** The maintainer marked it for a future report (2026-11-15); the suggested text below is the draft.
- **The problem:** two things are left open.
  1. **Absent kinds:** RFC 3779 resources are per kind (each address family, AS numbers). An EE certificate that inherits IPv4 and leaves IPv6 out "describes its INRs using inherit" for the kinds it describes, and gives no explicit description of anything. It is unclear whether every kind must be present with inherit, or only no kind may be explicit. RFC 6487 §4.8.10 and §4.8.11 let a certificate leave a family, or AS numbers, out.
  2. **The consequence:** "RPs are required to verify this" names no outcome. Is the manifest invalid, and with it the publication point (§6.2 wants a valid manifest), or is it only a reportable deviation?
- **Impact:** small in practice. Every manifest sampled from the LACNIC repository (148, 2026-11-14) inherits IPv4, IPv6 and AS numbers, even where the CA lacks a kind (F-033). Test tools are another matter. Barry writes explicit resources on every manifest it isn't told about, so an RP that rejects them can't run most fixtures.
- **Resolution:** a warning, `manifest_ee_resources_not_inherit`, naming each kind listed explicitly; an absent kind doesn't warn (D-029, #157). It becomes an error once Barry writes inherit by default.
- **Suggested text (RFC 9286 §5.1):** *"This EE certificate MUST NOT contain an explicit description of a resource set (see [RFC3779]); each kind of INR it contains MUST use the 'inherit' attribute. An RP MUST consider a manifest whose EE certificate does not comply invalid."* (Or "SHOULD warn", if the intent was softer.)
- **Talk note:** a requirement aimed at RPs ("required to verify") that doesn't say what verifying failure means leaves every RP to choose between a rejected publication point and a log line.

### F-036: A verified erratum makes the solidus an escape-only character

- **Where:** RFC 8259 §7: "All Unicode characters may be placed within the quotation marks, except for the characters that MUST be escaped: quotation mark, reverse solidus, and the control characters (U+0000 through U+001F)." The grammar below agrees: `unescaped = %x20-21 / %x23-5B / %x5D-10FFFF`, which includes the solidus `/` (U+002F), and lists `\/` among the optional escapes.
- **Kind:** erratum.
- **Official errata:** [5318](https://www.rfc-editor.org/errata/eid5318), verified, editorial, changes the rule to `unescaped = %x20-21 / %x23-2E / %x30-5B / %x5D-10FFFF`, so the solidus could only appear escaped. Its note: "The solidus U+002F is listed as being escaped above, but is not excluded in the 'unescaped' sequence." Also relevant: [7603](https://www.rfc-editor.org/errata/eid7603) (verified: a string is "Unicode code points", not characters), [7650](https://www.rfc-editor.org/errata/eid7650) (held: the rule name `char` clashes with ABNF's core `CHAR`). The rest are rejected, or about numbers and the media type (checked 2026-11-15). **Not reported.**
- **The problem:** the erratum contradicts the prose it sits under, which lets every character but the quotation mark, the reverse solidus and the controls stand unescaped. Being listed as escapable doesn't make a character escape-only: every character "may be escaped" (§7). Read with the erratum, `"1.0.0.0/24"` isn't JSON, and neither is nearly every JSON text with a URL in it.
- **Impact:** none in practice; decoders accept both forms, OTP's `:json` among them. Lumina's JSON has a solidus in every prefix and URI.
- **Resolution:** follow the prose: the solidus is written unescaped (#167). The JSON tests decode with `:json.decode/1` and check that the prefixes come out with a plain `/`.
- **Talk note:** a verified erratum can be wrong too; read it against the text it corrects.

### F-037: A delta publish doesn't say when its hash is required

- **Where:** RFC 8182 §3.4.2: "When a Relying Party encounters a "withdraw" element, or a "publish" element where an object is replaced, ... it MUST verify that the object to be withdrawn or replaced was retrieved from this same Repository Server". The §3.5.4 schema makes `hash` optional on a delta's `publish`.
- **Kind:** gap.
- **Official errata:** [6919](https://www.rfc-editor.org/errata/eid6919), held for document update (checked 2026-11-17). It adds the rule from RFC 8181: "the hash MUST be present if the publication operation is overwriting an existing object, and it MUST NOT be present if this publication operation is writing to a new object."
- **The problem:** without the rule, a `publish` without a hash for a URI the RP already holds is either a new object or a silent overwrite, and §3.4.2's check has nothing to compare.
- **Resolution:** Lumina enforces the erratum's rule: an overwrite without the old object's hash, a hash that doesn't match the stored object, or a hash for a URI not in the repository's store rejects the delta, and the snapshot is used (RFC 8182 §3.4.2). Done in #204: rules `publish_without_hash`, `replace_not_held`, `replace_hash_mismatch`, `withdraw_not_held`, `withdraw_hash_mismatch` (`Lumina.RRDP.Sync`).
- **Talk note:** the rule existed in the sibling protocol (RFC 8181) and was lost between the two documents.

### F-038: Barry writes session_id "1"

- **Where:** RFC 8182 §3.5.1.3: "The session_id attribute MUST be a random version 4 UUID [RFC4122], unique to this session." Barry (pinned `478ee89`) writes `session_id="1"` in its notification and snapshot files by default (`src/rpki_tree.c`).
- **Kind:** tooling incompatibility.
- **Official errata:** none needed; the RFC is clear.
- **Resolution:** `mix lumina.fixtures.gen` adds a `[notification: ...]` section with `session = <version 4 UUID>` to every fixture's descriptor, the UUID made from the fixture's id so it survives regeneration (`Mix.Lumina.Fixtures.session_id/1`, #202). Lumina rejects a session_id that isn't a UUID at all (D-042), so Barry's default can't be used. Suggestion for Barry: generate a random version 4 UUID by default.

### F-039: RFC 8182 cites no XML specification

- **Where:** RFC 8182 §3.5.1.3, §3.5.2.3 and §3.5.3.3: "A Relying Party MUST reject any ... File that is not well-formed or does not conform to the RELAX NG schema outlined in Section 3.5.4". §3.5.4 gives the schema in RELAX NG compact syntax with `xsd:` datatypes (`positiveInteger`, `anyURI`, `base64Binary`). §7 lists no XML 1.0, no Namespaces in XML, no RELAX NG (ISO/IEC 19757-2) and no XML Schema datatypes.
- **Kind:** missing reference.
- **Official errata:** none found for this; RFC 8182 has 7239 (verified, §3.2) and 6919 (held, §3.4.2) (checked 2026-11-17). **Not reported.**
- **The problem:** "well-formed", "XML namespace", the encoding rule and the schema's datatypes are defined only in W3C and ISO documents the RFC doesn't cite, so which XML version and which datatype definitions apply is left to the reader. Lumina builds only from the RFC texts; here it has to step outside them.
- **Resolution:** the parser follows XML 1.0 (Fifth Edition) for the subset RRDP needs (D-041, #198), and its errors name XML 1.0 sections. The schema's datatypes are checked in #199 as their names suggest (a positive decimal integer, an absolute URI, base64), which the RFC's own rules also say (§3.5.1.3: "an unbounded, unsigned positive integer in decimal format").
- **Talk note:** a MUST that rests on documents the RFC never names: two RPs can read "well-formed" against different XML versions and both claim conformance.

### F-040: RFC 8182 cites obsoleted HTTP RFCs

- **Where:** RFC 8182 §3.4.1: "a "User-Agent" header explained in Section 5.5.3. of [RFC7231]"; §3.4.4: "Relying Parties MUST use the "If-Modified-Since" header explained in Section 3.3 of [RFC7232]"; §3.2 and §4.3 cite [RFC7230] for HTTPS URIs and HTTPS. RFC 7230, 7231 and 7232 were obsoleted in June 2022 by RFC 9110 (semantics, §10.1.5 User-Agent, §13.1.3 If-Modified-Since) and RFC 9112 (HTTP/1.1 messages). RFC 9674 (2024) updates RFC 8182 but leaves these references.
- **Kind:** obsolete reference.
- **Official errata:** none found for this; RFC 8182 has 7239 (verified, §3.2) and 6919 (held, §3.4.2) (checked 2026-11-17). **Not reported.**
- **The problem:** none in substance: the header definitions carried over unchanged. A reader following the references lands on obsoleted documents, and neither RFC 9110 nor RFC 9112 is in Lumina's RFC library.
- **Resolution:** `Lumina.HTTPS` follows RFC 9110 §13.1.3 (send the earlier `Last-Modified` value as given) and RFC 9112 §6.3 and §7.1 (message framing, chunked coding) (#200). RFC 9110 and RFC 9112 aren't added to `doc/rfc/`; the tests cite RFC 8182 sections.
- **Talk note:** an RFC's references age even when an update to the RFC comes along: RFC 9674 rewrote §3.4.1's rules and left §3.4.1's citations alone.

### F-041: RFC 8182 doesn't say a snapshot publishes each URI once

- **Where:** RFC 8182 §3.5.2.3: the snapshot "represents a complete current state of the repository", and its rules cover the namespace, encoding, version, session_id and serial. Neither the rules nor the §3.5.4 schema say a `publish` element's `uri` appears only once. §3.5.3.3 doesn't say it of a delta either.
- **Kind:** ambiguity.
- **Official errata:** none found for this; RFC 8182 has 7239 (verified, §3.2) and 6919 (held, §3.4.2) (checked 2026-11-17). **Not reported.**
- **The problem:** a snapshot with two `publish` elements for one URI gives that object two contents. An RP that keeps the last one and an RP that keeps the first see different repositories from the same file, and a streaming RP can't tell which the publisher meant.
- **Resolution:** Lumina rejects such a snapshot (`snapshot_rejected` with rule `duplicate_publish`; the store is kept) (#203). A state with two values for one object isn't "a complete current state". Maintainer decision (2026-11-17, D-046): keep this strict reading, and check during live testing (#209) whether any live snapshot publishes a URI twice.
- **Talk note:** "complete current state" implies a set, but neither the rules nor the schema enforces it.

## TA deviations

Where a trust anchor's repository, or the servers it publishes on, departs from the RFCs or from what other repositories do, and Lumina has to decide what to do about it. Found by syncing the live RPKI.

| ID | Trust anchor | What | Status in Lumina |
| --- | --- | --- | --- |
| [TD-001](#td-001-apnics-rsync-server-refuses-a-path-with-a-dot-segment) | APNIC | rsync server refuses `module/./path` | `./` only before a path starting with `-` (#189) |
| [TD-002](#td-002-afrinics-ee-certificates-list-rpkinotify) | AFRINIC | rpkiNotify in EE certificates' SIA | Warning, not a reject (D-038, #190) |
| [TD-003](#td-003-prefixlogics-rrdp-session_id-is-a-version-5-uuid) | ARIN (delegated: prefixlogic) | RRDP session_id is a version 5 UUID | Warning, not a reject (D-042, #199) |

### TD-001: APNIC's rsync server refuses a path with a dot segment

- **Where:** `rsync://rpki.apnic.net/repository`, the module APNIC's TA publishes in. RFC 5781 §2 defines rsync URIs; it says nothing about dot segments, and RFC 3986 §5.2.4 treats `./` as a no-op.
- **Found:** by the M7 done test's live run (#170), 2026-11-16. `rsync://rpki.apnic.net/repository/./` and `.../repository/./838DB214166511E2B3BC286172FD1FF2/` fail with `change_dir "/." (in repository) failed: No such file or directory` (exit 23); without the `./` both list. The other RIRs' servers and every delegated one Lumina reached accept the form.
- **Impact:** Lumina wrote every source as `module/./path` (F-025), so it couldn't fetch APNIC's repository at all, and APNIC gave no VRPs.
- **Resolution:** maintainer decision (2026-11-16): the `./` is written only when the path after the module starts with `-`, the only case F-025 needs it (#189). An APNIC path starting with `-` would still fail; none does today.
- **Talk note:** a defence that is a no-op by the rsync manual still depends on every server's path handling.

### TD-002: AFRINIC's EE certificates list rpkiNotify

- **Where:** AFRINIC's manifest EE certificates (and so every publication point under its TA): the SIA lists `rpkiNotify` (`https://rrdp.afrinic.net/notification.xml`) beside `signedObject`. RFC 6487 §4.8.8.2: "Other AccessMethods MUST NOT be used for an EE certificates's SIA." RFC 8182 §3.2 as published asks for rpkiNotify "in resource certificates"; verified [erratum 7239](https://www.rfc-editor.org/errata/eid7239) corrects that to "CA resource certificates" (checked 2026-11-16). So the RFCs, read with the erratum, have no gap; AFRINIC followed the published text.
- **Found:** by the M7 done test's live run (#170), 2026-11-16. Lumina rejected the TA's manifest (`access_method`), so AFRINIC gave no VRPs, while Routinator's CSV has AFRINIC's.
- **Resolution:** maintainer decision (2026-11-16, D-038): an rpkiNotify in an EE certificate's SIA is the warning `ee_sia_rpki_notify`; any other extra method still rejects (#190). AFRINIC then validates: 1,495 CA certificates, 12,664 valid ROAs, 32,796 VRPs.
- **Talk note:** a context sentence lost between drafts became a MUST in a published RFC, a whole RIR implemented it, and the erratum came later.

### TD-003: prefixlogic's RRDP session_id is a version 5 UUID

- **Where:** `https://rrdp-ipv4.prefixlogic.com/rrdp/notification.xml` serves `session_id="3025d864-54b5-502e-9a2f-6f4b48f31bdd"`: version nibble 5. RFC 8182 §3.5.1.3: the session_id "MUST be a random version 4 UUID".
- **Found:** surveying the 126 notification URIs named in the five RIRs' CA certificates for the M8 plan, 2026-11-16. It is the only one of the 109 that answered.
- **Resolution:** maintainer decision (2026-11-17, D-042): a session_id of another UUID version warns; RRDP is used (#199).
- **Talk note:** a version 5 UUID is name-based, so it isn't random; the RFC wants randomness, but RPs pair the session with the notification URI anyway (§3.4.1), so nothing depends on it.

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
