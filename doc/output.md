# Output formats

`lumina vrps` writes the Validated ROA Payloads (VRPs) of the valid ROAs, as CSV (the default) or as JSON (`--format json`). It validates what the cache holds; with `--sync`, it first syncs the TALs whose cache is missing or older than `--max-age` (D-037). There is no RFC for VRP output (`doc/rfc/README.md`): the CSV follows the columns of Routinator's CSV output (D-032), and the JSON is Lumina's own. Both have the same rows in the same order.

A VRP is an AS number, a prefix, a maxLength and the trust anchor it was validated under (RFC 9582 §4.3.2.2: a ROA prefix without maxLength gives a VRP whose maxLength is the prefix length). The trust anchor is named after its TAL file, without `.tal` (`lacnic`, `ripe-ncc`, `apnic-rfc7730-https`).

## Rows

- **Which:** one row per distinct (AS, prefix, maxLength, trust anchor), however many ROAs state it (D-033). With `--wide`, one row per VRP and ROA, so a VRP that two ROAs state appears twice, each time with its ROA's rsync URI.
- **Order:** IPv4 before IPv6, then by address, prefix length, maxLength, AS number, trust anchor and (with `--wide`) URI.
- **Values:** the AS number as `AS` and its decimal value; IPv4 prefixes in dotted decimal, IPv6 prefixes in RFC 5952 form (`2001:db8::/32`); maxLength in decimal.
- **When some trust anchors fail:** a TAL with no trust anchor in the cache, or an invalid one, gives no rows; one with more than `--max-invalid` percent invalid objects still gives its rows (D-034). The exit code is 1 in both cases.

## CSV

UTF-8, lines ending in LF, a header line first:

```
ASN,IP Prefix,Max Length,Trust Anchor
AS13335,1.0.0.0/24,24,apnic
AS64496,2001:db8::/32,48,lacnic
```

With `--wide`, a fifth column:

```
ASN,IP Prefix,Max Length,Trust Anchor,URI
AS13335,1.0.0.0/24,24,apnic,rsync://rpki.example.net/repo/a.roa
AS13335,1.0.0.0/24,24,apnic,rsync://rpki.example.net/repo/b.roa
```

A field holding a comma, a double quote or a line break is put in double quotes, with its double quotes doubled. Only a trust anchor name or a URI can need it.

## JSON

A JSON text (RFC 8259) in UTF-8: one object with two members, `metadata` and `roas`.

```json
{
  "metadata": {
    "generated": "2026-11-15T12:00:00Z",
    "validationTime": "2026-11-15T12:00:00Z",
    "lumina": "0.8.1",
    "trustAnchors": [
      {"name":"apnic","tal":"tals/apnic.tal","status":"ok","vrps":1},
      {"name":"lacnic","tal":"tals/lacnic.tal","status":"ok","vrps":1}
    ],
    "vrps": 2
  },
  "roas": [
    {"asn":"AS13335","prefix":"1.0.0.0/24","maxLength":24,"ta":"apnic"},
    {"asn":"AS64496","prefix":"2001:db8::/32","maxLength":48,"ta":"lacnic"}
  ]
}
```

### `metadata`

| Member | Type | Meaning |
| --- | --- | --- |
| `generated` | string | When the output was made, ISO 8601 in UTC, to the second. |
| `validationTime` | string | The time the cache was validated at (`--now`, by default the current time), ISO 8601 in UTC, to the second. |
| `lumina` | string | Lumina's version. |
| `trustAnchors` | array | One object per TAL, in the order the TALs were given (`--tal`) or found in `./tals/`. |
| `vrps` | number | The number of elements of `roas`. |

Each element of `trustAnchors`:

| Member | Type | Meaning |
| --- | --- | --- |
| `name` | string | The trust anchor's name, as in the rows' `ta`. |
| `tal` | string | The TAL file, as given. |
| `status` | string | `ok`; `no_trust_anchor` (none in the cache: run `lumina sync`); `invalid_trust_anchor`; or `too_many_invalid` (more than `--max-invalid` percent of its CA certificates and signed objects are invalid; its rows are there anyway, D-034). Anything but `ok` makes the exit code 1. |
| `vrps` | number | The number of elements of `roas` under this trust anchor. |

### `roas`

One object per row, in the row order above:

| Member | Type | Meaning |
| --- | --- | --- |
| `asn` | string | The AS number, `AS` and its decimal value. |
| `prefix` | string | The prefix, as in the CSV. |
| `maxLength` | number | The maxLength. |
| `ta` | string | The trust anchor's name. |
| `uri` | string | Only with `--wide`: the rsync URI of the ROA. |

Room is left for ASPA: a later version may add an `aspas` member next to `roas`. Readers should ignore members they don't know.

### Encoding

- Members are always in the order shown, and each element of `trustAnchors` and `roas` is on a line of its own, so the same cache validated at the same time gives the same bytes apart from `generated`.
- Strings are escaped as RFC 8259 §7 requires: the double quote, the backslash and the control characters U+0000 to U+001F. The solidus `/` is not escaped, as §7's prose allows (F-036). Other characters are written as UTF-8, unescaped. A byte in a TAL file's name that isn't UTF-8 is replaced by U+FFFD.
- Numbers are integers.
