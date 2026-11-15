# RFC library

These are the plain-text RFCs the validator is built from, grouped by the feature sets in [`GOAL.md`](../../GOAL.md). Each table links to the local `.txt` copy and to the HTML version on rfc-editor.org. Statuses come from the RFC Editor index as of 2026-11-12.

Only published RFCs are kept here. Drafts are not stored, and obsoleted RFCs are listed at the end so nobody implements them by mistake.

Errata, ambiguities and other problems found in these texts while implementing them are logged in [`../rfc-findings.md`](../rfc-findings.md). Check an RFC's errata before relying on its ASN.1 or examples. Some verified errata change the modules and test vectors.

## Feature map

| Feature (from `GOAL.md`) | Sections |
| --- | --- |
| TAL parsing | [Trust anchors](#1-trust-anchors) |
| Repository retrieval (rsync, then RRDP) | [Repository structure and retrieval](#2-repository-structure-and-retrieval) |
| Cryptographic validation | [Certificates and CRLs](#3-certificates-and-crls), [Signed objects](#4-signed-objects-cms), [Algorithms](#5-algorithms-and-signatures), [Manifests](#6-manifests) |
| Resource-inclusion validation | [IP and AS resources](#7-ip-and-as-resources) |
| TXT and JSON VRP output | [ROAs and VRPs](#8-roas-and-vrps) |
| (ASPA output) | Not yet an RFC, see [the last section](#not-yet-an-rfc) |

Supporting material: [Architecture and RP requirements](#0-architecture-and-rp-requirements), [Other signed objects](#9-other-signed-objects).

## 0. Architecture and RP requirements

These give the big picture: what the RPKI is, who issues what, and what an RP is obliged to do. RFC 8897 collects RP requirements from across the other RFCs and works well as a checklist. RFC 6907 walks through example scenarios that can be turned into test cases.

| RFC | Title | Local | Online | Notes |
| --- | --- | --- | --- | --- |
| 6480 | An Infrastructure to Support Secure Internet Routing | [txt](rfc6480.txt) | [html](https://www.rfc-editor.org/rfc/rfc6480.html) | Informational; architecture overview |
| 8897 | Requirements for RPKI Relying Parties | [txt](rfc8897.txt) | [html](https://www.rfc-editor.org/rfc/rfc8897.html) | Informational; RP requirements checklist |
| 6907 | Use Cases and Interpretations of RPKI Objects for Issuers and Relying Parties | [txt](rfc6907.txt) | [html](https://www.rfc-editor.org/rfc/rfc6907.html) | Informational; worked scenarios |

## 1. Trust anchors

A TAL holds one or more URIs (rsync or HTTPS) and the base64-encoded public key of a trust anchor certificate. The RP fetches the certificate and checks that its key matches the TAL. TAKs are signed objects that let a trust anchor announce a key rollover.

| RFC | Title | Local | Online | Notes |
| --- | --- | --- | --- | --- |
| 8630 | RPKI Trust Anchor Locator | [txt](rfc8630.txt) | [html](https://www.rfc-editor.org/rfc/rfc8630.html) | TAL format; obsoletes 7730 |
| 9691 | A Profile for RPKI Trust Anchor Keys (TAKs) | [txt](rfc9691.txt) | [html](https://www.rfc-editor.org/rfc/rfc9691.html) | Trust anchor key rollover |
| 4648 | The Base16, Base32, and Base64 Data Encodings | [txt](rfc4648.txt) | [html](https://www.rfc-editor.org/rfc/rfc4648.html) | TAL key encoding; also RRDP payloads |
| 3986 | Uniform Resource Identifier (URI): Generic Syntax | [txt](rfc3986.txt) | [html](https://www.rfc-editor.org/rfc/rfc3986.html) | URIs in TALs, SIA and AIA |

## 2. Repository structure and retrieval

RFC 6481 defines how a publication point is laid out and which file extensions map to which object types. Retrieval uses rsync first, with RRDP (snapshot and delta XML over HTTPS) to come later. RFCs 9674 and 9697 tighten RRDP: snapshot and delta files must come from the same origin as the notification file, and they explain how to detect a desynchronized session.

| RFC | Title | Local | Online | Notes |
| --- | --- | --- | --- | --- |
| 6481 | A Profile for Resource Certificate Repository Structure | [txt](rfc6481.txt) | [html](https://www.rfc-editor.org/rfc/rfc6481.html) | Publication point layout, file extensions |
| 5781 | The rsync URI Scheme | [txt](rfc5781.txt) | [html](https://www.rfc-editor.org/rfc/rfc5781.html) | Informational |
| 8182 | The RPKI Repository Delta Protocol (RRDP) | [txt](rfc8182.txt) | [html](https://www.rfc-editor.org/rfc/rfc8182.html) | Updated by 9674, 9697 |
| 9674 | Same-Origin Policy for RRDP | [txt](rfc9674.txt) | [html](https://www.rfc-editor.org/rfc/rfc9674.html) | Updates 8182 |
| 9697 | Detecting RRDP Session Desynchronization | [txt](rfc9697.txt) | [html](https://www.rfc-editor.org/rfc/rfc9697.html) | Updates 8182 |

## 3. Certificates and CRLs

Resource certificates are X.509 certificates (RFC 5280) narrowed down by the RPKI profile (RFC 6487). Validation means building and checking the path from the trust anchor down, including CRL checks. RFC 7318 relaxes the rules on policy qualifiers, and RFC 9829 specifies how CRL Number extensions are handled.

| RFC | Title | Local | Online | Notes |
| --- | --- | --- | --- | --- |
| 5280 | Internet X.509 PKI Certificate and CRL Profile | [txt](rfc5280.txt) | [html](https://www.rfc-editor.org/rfc/rfc5280.html) | Base profile; ASN.1 modules in Appendix A |
| 6487 | A Profile for X.509 PKIX Resource Certificates | [txt](rfc6487.txt) | [html](https://www.rfc-editor.org/rfc/rfc6487.html) | RPKI profile; updated by 7318, 8209, 9829 |
| 7318 | Policy Qualifiers in RPKI Certificates | [txt](rfc7318.txt) | [html](https://www.rfc-editor.org/rfc/rfc7318.html) | Updates 6487 |
| 9829 | Handling of RPKI CRL Number Extensions | [txt](rfc9829.txt) | [html](https://www.rfc-editor.org/rfc/rfc9829.html) | Updates 6487 |

DER encoding (ITU-T X.690) is not defined in any RFC, but every object in this library depends on it.

## 4. Signed objects (CMS)

Every RPKI signed object (manifest, ROA, Ghostbusters record, TAK, and so on) is a CMS SignedData wrapping a one-time-use EE certificate. RFC 6488 sets the common template and the validation steps shared by all of them. RFC 9589 covers how the signing-time attribute is used.

| RFC | Title | Local | Online | Notes |
| --- | --- | --- | --- | --- |
| 5652 | Cryptographic Message Syntax (CMS) | [txt](rfc5652.txt) | [html](https://www.rfc-editor.org/rfc/rfc5652.html) | SignedData; ASN.1 module |
| 6488 | Signed Object Template for the RPKI | [txt](rfc6488.txt) | [html](https://www.rfc-editor.org/rfc/rfc6488.html) | Common profile; updated by 9589 |
| 9589 | On the Use of the CMS Signing-Time Attribute in RPKI Signed Objects | [txt](rfc9589.txt) | [html](https://www.rfc-editor.org/rfc/rfc9589.html) | Updates 6488 |

## 5. Algorithms and signatures

RFC 7935 fixes the RPKI algorithm suite: RSA 2048-bit keys, SHA-256, and RSASSA-PKCS1-v1_5 signatures. The other RFCs here define the algorithm identifiers and the signature verification primitive.

| RFC | Title | Local | Online | Notes |
| --- | --- | --- | --- | --- |
| 7935 | The Profile for Algorithms and Key Sizes for Use in the RPKI | [txt](rfc7935.txt) | [html](https://www.rfc-editor.org/rfc/rfc7935.html) | Obsoletes 6485; updated by 8608 (BGPsec only) |
| 4055 | Additional Algorithms and Identifiers for RSA Cryptography for use in X.509 | [txt](rfc4055.txt) | [html](https://www.rfc-editor.org/rfc/rfc4055.html) | `sha256WithRSAEncryption` identifiers |
| 3370 | Cryptographic Message Syntax (CMS) Algorithms | [txt](rfc3370.txt) | [html](https://www.rfc-editor.org/rfc/rfc3370.html) | `rsaEncryption` parameters in CMS (§3.2), cited by RFC 7935 §2; added 2026-11-14 (F-031) |
| 5754 | Using SHA2 Algorithms with Cryptographic Message Syntax | [txt](rfc5754.txt) | [html](https://www.rfc-editor.org/rfc/rfc5754.html) | Digest algorithm identifiers in CMS |
| 8017 | PKCS #1: RSA Cryptography Specifications Version 2.2 | [txt](rfc8017.txt) | [html](https://www.rfc-editor.org/rfc/rfc8017.html) | Informational; RSASSA-PKCS1-v1_5 |

## 6. Manifests

A manifest lists every file at a publication point, with its hash. The RP uses it to find missing, altered or stale files, and to decide whether the publication point can be used at all. RFC 9981 updates how manifest numbers are handled.

| RFC | Title | Local | Online | Notes |
| --- | --- | --- | --- | --- |
| 9286 | Manifests for the RPKI | [txt](rfc9286.txt) | [html](https://www.rfc-editor.org/rfc/rfc9286.html) | Obsoletes 6486; updated by 9981 |
| 9981 | RPKI Manifest Number Handling | [txt](rfc9981.txt) | [html](https://www.rfc-editor.org/rfc/rfc9981.html) | Updates 9286 |

## 7. IP and AS resources

RFC 3779 defines the IP address and AS number certificate extensions, and the rule that a child's resources must be contained in its issuer's. RFC 8360 adds an alternative validation algorithm, selected by its own certificate policy OIDs, that checks resource overclaims differently.

| RFC | Title | Local | Online | Notes |
| --- | --- | --- | --- | --- |
| 3779 | X.509 Extensions for IP Addresses and AS Identifiers | [txt](rfc3779.txt) | [html](https://www.rfc-editor.org/rfc/rfc3779.html) | Resource extensions; ASN.1 module |
| 8360 | RPKI Validation Reconsidered | [txt](rfc8360.txt) | [html](https://www.rfc-editor.org/rfc/rfc8360.html) | Alternative validation algorithm and policy OIDs |

## 8. ROAs and VRPs

A valid ROA produces VRPs, each a (prefix, maxLength, origin ASN) tuple, which are the main output. RFC 9582 defines the object itself. The informational RFCs explain how routers consume VRPs, which helps when designing the output and testing edge cases.

| RFC | Title | Local | Online | Notes |
| --- | --- | --- | --- | --- |
| 9582 | A Profile for Route Origin Authorizations (ROAs) | [txt](rfc9582.txt) | [html](https://www.rfc-editor.org/rfc/rfc9582.html) | Obsoletes 6482 |
| 8259 | The JavaScript Object Notation (JSON) Data Interchange Format | [txt](rfc8259.txt) | [html](https://www.rfc-editor.org/rfc/rfc8259.html) | JSON output |
| 6483 | Validation of Route Origination Using the Resource Certificate PKI and ROAs | [txt](rfc6483.txt) | [html](https://www.rfc-editor.org/rfc/rfc6483.html) | Informational |
| 6811 | BGP Prefix Origin Validation | [txt](rfc6811.txt) | [html](https://www.rfc-editor.org/rfc/rfc6811.html) | Valid/Invalid/NotFound; updated by 8481, 8893 |
| 9319 | The Use of maxLength in the RPKI | [txt](rfc9319.txt) | [html](https://www.rfc-editor.org/rfc/rfc9319.html) | BCP 185 |

There is no RFC for the TXT or JSON output format. We define the format ourselves: [`doc/output.md`](../output.md).

## 9. Other signed objects

These object types can show up in repositories or be handed to an RP directly. They don't produce VRPs, but they still have to be recognized and validated, or deliberately ignored.

| RFC | Title | Local | Online | Notes |
| --- | --- | --- | --- | --- |
| 6493 | The RPKI Ghostbusters Record | [txt](rfc6493.txt) | [html](https://www.rfc-editor.org/rfc/rfc6493.html) | Historic status; `.gbr` objects still appear in repositories |
| 9323 | A Profile for RPKI Signed Checklists (RSCs) | [txt](rfc9323.txt) | [html](https://www.rfc-editor.org/rfc/rfc9323.html) | Detached content; not published in repositories |

TAKs (RFC 9691) are also signed objects; they're listed under [Trust anchors](#1-trust-anchors).

## Obsoleted, not to be implemented

| Obsoleted | Replaced by |
| --- | --- |
| 6482 (ROA) | 9582 |
| 6485 (algorithms) | 7935 |
| 6486 (manifests) | 9286 |
| 6490, 7730 (TAL) | 8630 |

## Not yet an RFC

ASPA (`draft-ietf-sidrops-aspa-profile`) is still an Internet-Draft. It will be added here once it's published as an RFC.
