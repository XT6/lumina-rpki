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
| [F-006](#f-006-cms-module-imports-from-an-obsoleted-rfc) | 5652 §12.1, §12.2 | reference | none | Opaque placeholders (#23) |
| [F-007](#f-007-rfc-5280-modules-redefine-built-in-string-types) | 5280 A.1, A.2 | tooling | none | Patched (#23) |
| [F-008](#f-008-certificate-signature-field-has-two-names) | 5280 §4.1 vs A.1 | ambiguity | [7634](https://www.rfc-editor.org/errata/eid7634), held for document update | Module names used (#27) |
| [F-009](#f-009-cms-and-attribute-certificate-modules-import-from-each-other) | 5652 §12.1, 5755 App. B | reference | none found | Avoided by F-006 placeholders (#23) |
| [F-010](#f-010-no-rule-for-data-after-the-encoded-object) | 6481 §2.2, 6488 §3 | ambiguity | none found (not reported) | Trailing bytes rejected (#24, #25) |
| [F-011](#f-011-asn1ct-error-reasons-carry-stack-traces) | (OTP `asn1ct`) | tooling | n/a | Wrapper shortens reasons (#24) |
| [F-012](#f-012-the-roa-module-enforces-the-afi-rule-at-decode-time) | 9582 §4, §4.3.1, §4.3.2 | tooling | none | Accepted; decode error (#24, #30) |
| [F-013](#f-013-the-address-sort-key-has-a-part-that-never-matters) | 3779 §2.2.3.6 | ambiguity | none found (not reported) | Sort by lowest address (#26) |
| [F-014](#f-014-two-rfc-3779-errata-change-what-a-decoder-must-accept) | 3779 §2.2.3.9, §3.2.3.8 | erratum | [2537](https://www.rfc-editor.org/errata/eid2537) verified, [7653](https://www.rfc-editor.org/errata/eid7653) held | Both followed (#26) |
| [F-015](#f-015-two-conforming-validators-can-disagree-on-unknown-extensions) | 6487 §4.1, §4.8, §5; 8897 §3.1, §3.3 | ambiguity | none found (not reported) | Versions settled by 8897; extensions open (#42) |
| [F-016](#f-016-no-rfc-says-how-a-repository-directory-uri-ends) | 6487 §4.8.8.1 | ambiguity | none found (not reported) | Both forms handled in M3 (#43) |
| [F-017](#f-017-rfc-6487-still-points-to-the-obsolete-algorithm-profile) | 6487 §4.3, §4.7, §5, §6.1.1; also 7935, 8630 | reference | none found (not reported) | Use the current RFCs |
| [F-018](#f-018-rfc-9582-tells-cas-that-relying-parties-will-change-their-minds) | 9582 §4.3.2.2, §4.3.3 | ambiguity | none (by design) | Reported by `ROA.issues/1`; decide in M7 |
| [F-019](#f-019-manifest-times-inherit-a-crl-rule-they-cannot-follow) | 9286 §4.2.1 | ambiguity | none found (not reported) | Use RFC 5280 GeneralizedTime rules (#48) |
| [F-020](#f-020-a-repository-file-extension-for-an-object-banned-from-repositories) | 9323 §2, §9.3; 6481 §7.2 | ambiguity | none found (not reported) | `.sig` recognized; repository policy in M5 |
| [F-021](#f-021-the-tal-grammar-leaves-whitespace-and-blank-lines-open-and-its-example-is-indented) | 8630 §2.2, §2.4 | ambiguity | none found (not reported) | Strict grammar, whitespace warns (D-002, #54) |
| [F-022](#f-022-the-whole-rp-procedure-for-tals-is-a-should) | 8630 §3 | ambiguity | none found (not reported) | Lumina performs every step (#56) |

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
- **Resolution:** accepted. The rule is unambiguous, and patching the constraint out would break the rule that patches never change what is accepted. The decoder turns the exit into an error, and a test covers AFI 3 (#24). M7 should map this decode error to a message that cites §4.3.1.
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
  - Unknown non-critical extensions: **open**, needs a maintainer decision (#42).
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
- **Resolution:** `Lumina.ROA.issues/1` reports `:superfluous_max_length`, `:not_canonical_order` and `:duplicate_address`, and doesn't reject them. Whether M7 accepts, warns or rejects is a maintainer decision for M7.
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
  - M5 checks manifest times against RFC 5280 §4.1.2.5.2 (#48).
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
