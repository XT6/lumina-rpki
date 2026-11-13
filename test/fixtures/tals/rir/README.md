# RIR TALs

The Trust Anchor Locators published by the five Regional Internet Registries, used as real-world test data for TAL parsing (#58). The files are byte-exact copies of what each RIR served; never edit them. Each file was fetched over HTTPS from the RIR's own site on **2026-11-13**. The maintainer approved each source and its terms before the file was committed.

| File | RIR | Source | SHA-256 |
| --- | --- | --- | --- |
| `afrinic.tal` | AFRINIC | <https://rpki.afrinic.net/tal/afrinic.tal> | `2838ef30ea27ce5705abf5f5adb131d8c35b1f50858338a2f3c84bb207c2fa35` |
| `apnic-rfc7730-https.tal` | APNIC | <https://tal.apnic.net/tal-archive/apnic-rfc7730-https.tal> | `472e551f7c551c2e999e582b7c9437d3bee4900fe53afff62aeb28d4940ade94` |
| `arin.tal` | ARIN | <https://www.arin.net/resources/manage/rpki/arin.tal> | `1f8bdb03bcc30a3b8e11fd9a87102fba250c22137a3c8baa9c81b139cb412639` |
| `lacnic.tal` | LACNIC | <https://www.lacnic.net/innovaportal/file/4983/1/lacnic.tal> | `d44bb9394ab009c8b53e5efebf2a1c9450bab61a27efe00de5a3e4587a3a2f6a` |
| `ripe-ncc.tal` | RIPE NCC | <https://tal.rpki.ripe.net/ripe-ncc.tal> | `59ca27ef93f23682749fcefe7c6d70fbc723343549ff9e4d3996acaff79817fb` |

## Notes

- **APNIC:** the "Current TAL" at <https://tal.apnic.net/apnic.tal> lists only an rsync URI. By the maintainer's choice, the HTTPS-first variant from APNIC's TAL archive is committed instead. It has the same key (SKI `0b:9c:ca:90:dd:0d:7a:8a:37:66:6b:19:21:7f:e0:d8:40:37:b7:a2`).
- **LACNIC:** the file has no final newline. RFC 8630 §2.2 doesn't require one.
- **ARIN:** the file begins with an 11-line warranty disclaimer as comments.

## Terms found (2026-11-13)

This is a record of what was read, not legal advice.

- **ARIN:** the Relying Party Agreement (13 February 2023), §5, says: "You are specifically allowed to publicly distribute the ARIN TAL, including by embedding the ARIN TAL in validation software."
- **APNIC:** use of the TAL is governed by APNIC's RPKI limitations of liability: "The access and use of the RPKI Repository and all associated data is at the user's own risk entirely." There is no licence or redistribution clause.
- **RIPE NCC:**
  - The Certification Repository Terms and Conditions, in force from 13.11.2025, limit use of the repository to validating RPKI objects or scientific research (Art. 3.1).
  - Art. 6.1 says the RIPE NCC's intellectual property may only be reproduced and made available to third parties with prior written authorisation.
  - The TAL file isn't named in either clause. The maintainer approved committing it as test data for validator software.
- **LACNIC, AFRINIC:** no TAL terms were found. The pages that might hold them couldn't be read.

## Updating

RIRs occasionally roll keys or change URIs. To update a TAL, fetch it again from the source above, show the maintainer the change, and only then update the file, its SHA-256, the date and the expected values in `test/lumina/tal_rir_test.exs`.
