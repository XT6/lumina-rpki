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
| [F-012](#f-012-the-roa-module-enforces-the-afi-rule-at-decode-time) | 9582 §4, §4.3.1 | tooling | none | Accepted; decode error (#24) |
| [F-013](#f-013-the-address-sort-key-has-a-part-that-never-matters) | 3779 §2.2.3.6 | ambiguity | none found (not reported) | Sort by lowest address (#26) |
| [F-014](#f-014-two-rfc-3779-errata-change-what-a-decoder-must-accept) | 3779 §2.2.3.9, §3.2.3.8 | erratum | [2537](https://www.rfc-editor.org/errata/eid2537) verified, [7653](https://www.rfc-editor.org/errata/eid7653) held | Both followed (#26) |
| [F-015](#f-015-two-conforming-validators-can-disagree-on-unknown-extensions) | 6487 §4.1, §4.8; 8897 §3.1 | ambiguity | none found (not reported) | Version settled by 8897; extensions open (#42) |
| [F-016](#f-016-no-rfc-says-how-a-repository-directory-uri-ends) | 6487 §4.8.8.1 | ambiguity | none found (not reported) | Both forms handled in M3 (#43) |

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
  - **Unknown non-critical extensions:** not settled.
    - "MAY be ignored" lets one RP ignore the extension and another reject the certificate.
    - RFC 8897's "any extension excluded by Section 4.8" doesn't help, because §4.8 lists mandatory extensions and never lists excluded ones. Whether "not listed" means "excluded" is exactly the question.
- **Impact:** a CA that adds an unknown non-critical extension gets its certificate accepted by some validators and rejected by others, which means different VRP sets. This is the same parser-differential risk as F-010.
- **Resolution:**
  - Version: reject v1/v2 (fixture `m1-cert-version-2`).
  - Unknown non-critical extensions: **open**, needs a maintainer decision (#42).
  - Unknown critical extensions: reject, as §4.8 requires (fixture `m1-cert-unknown-critical-extension`).
  - The decoder keeps every unknown extension, with its criticality, so any decision can be implemented.
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
