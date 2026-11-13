# TALs

The Trust Anchor Locators Lumina uses in production: one per Regional Internet Registry (D-004 in `doc/decisions.md`).

| File | RIR |
| --- | --- |
| `afrinic.tal` | AFRINIC |
| `apnic-rfc7730-https.tal` | APNIC (HTTPS-first variant from APNIC's TAL archive) |
| `arin.tal` | ARIN |
| `lacnic.tal` | LACNIC |
| `ripe-ncc.tal` | RIPE NCC |

The files are byte-exact copies of the TALs in `test/fixtures/tals/rir/`. That folder's README records each file's source URL, retrieval date, SHA-256 and the terms found when the maintainer approved it (#58). A test (`test/lumina/production_tals_test.exs`) fails if the two folders differ, so production always uses the TALs that were reviewed and tested.

## Updating

To update a TAL after an RIR rolls its key or changes its URIs:

1. Follow the steps in `test/fixtures/tals/rir/README.md`: fetch the file again, have the maintainer review the change, and update the fixture, its SHA-256 and the expected values.
2. Copy the same file here.

Never edit these files by hand.
