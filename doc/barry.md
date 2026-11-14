# Barry

[Barry](https://github.com/LACNIC/barry) ("BAd Rpki RepositorY") is LACNIC's generator of RPKI repositories for testing relying parties. You describe a certificate tree in a small text file, a *Repository Descriptor* (RD), and override any field of any object. Barry writes out a TAL, an rsync tree and RRDP files, with keys, signatures, serial numbers and dates filled in automatically.

Lumina uses Barry to generate test fixtures, especially repositories that should be **rejected**. The fixture layout, required metadata and `mix lumina.fixtures.gen` are described in [testing.md](testing.md#barry-fixtures).

## Installing

```sh
scripts/install-barry.sh     # build and install into _tools/ (no sudo)
scripts/check-barry.sh       # check that it works
```

The script builds Barry and its two build dependencies from source, each pinned to a commit, into `_tools/`, which is git-ignored. Nothing is installed system-wide.

Running it again does nothing unless the pins have changed. Use `--force` to rebuild anyway. Set `LUMINA_TOOLS` to install somewhere else.

### Prerequisites

| Platform | Install |
| --- | --- |
| macOS | `brew install autoconf automake libtool pkgconf openssl@3 libxml2 gnu-sed` |
| Ubuntu | `sudo apt-get install autoconf automake libtool pkg-config bison flex make gcc libssl-dev libxml2-dev` |

On macOS, GNU sed is required because libasn1fort's `compile-asn1.sh` uses GNU `sed -i` syntax. The install script puts GNU sed first in `PATH` for the build only. Homebrew's OpenSSL and libxml2 are keg-only, so the script points the build at them.

CI builds Barry on Ubuntu in the `barry` job of `.github/workflows/ci.yml`, with `_tools/` cached on the script's contents.

## Pinned versions

Barry is still WIP, and its README warns that the RD format may change in backwards-incompatible ways before 1.0.0. Every component is therefore pinned to an exact commit in `scripts/install-barry.sh`.

| Component | Role | Pinned commit | Commit date |
| --- | --- | --- | --- |
| [asn1c](https://github.com/vlm/asn1c) | ASN.1 compiler used to build libasn1fort | [`8a274c3`](https://github.com/vlm/asn1c/commit/8a274c3f99761f249b6c205e1c89be1b1cb7c669) | 2026-06-28 |
| [libasn1fort](https://github.com/NICMx/libasn1fort) | RPKI ASN.1 objects (shared with FORT validator) | [`925b841`](https://github.com/NICMx/libasn1fort/commit/925b8419d2810a6ad59f3ef821efbf4155055822) | 2026-03-27 |
| [Barry](https://github.com/LACNIC/barry) | The generator | [`478ee89`](https://github.com/LACNIC/barry/commit/478ee89a78bbbabfd8acc542faf02b322cecf85d) | 2026-10-30 |

### Upgrading a pin

1. Change the `*_REV` variable in `scripts/install-barry.sh` to the new commit.
2. Run `scripts/install-barry.sh` (the changed pin triggers a rebuild), then `scripts/check-barry.sh`.
3. Regenerate the fixtures and run the full test suite. An RD format change shows up as fixtures that fail to generate or tests whose outcome changes.
4. Update the table above, and open a PR that explains why the upgrade is needed.

## Using it

```sh
_tools/bin/barry path/to/case.repo
_tools/bin/barry -p csv minimal.repo   # print every object and field; a quick way to find the override keys
```

Things to know when writing fixtures:

- **Output location.** Barry writes `<name>.tal`, `rsync/` and `rrdp/` into the current directory.
- **Default URIs.** TALs point to `rsync://localhost:8873/rpki/` and `https://localhost:8443/rrdp/`. Override them with `--rsync-uri` and `--rrdp-uri`.
- **Dates.** They default to the current time. Use `--now` and `--later`, or per-object overrides, to get reproducible validity periods. #7 relies on this so committed fixtures don't expire.
- **Keys.** These are freshly generated on every run, so regenerated fixtures differ byte for byte. That is why fixtures are committed together with their generated output (decision recorded in #7). `--keys` makes the output reproducible, but we don't use it. See [testing.md](testing.md#generating) for why.
- **Override keys.** These follow the ASN.1 field names from the RFC modules, prefixed with `obj.`. See Barry's README for the descriptor syntax and default resource distribution.

The install also provides `barry-delta`, `barry-mtim`, `barry-ncu` and `barry-rtr`, which Lumina doesn't use yet.

## Limitations and wishlist

Things Barry can't do, or does surprisingly, found while writing fixtures. Each row says how Lumina works around it and what we'd suggest upstream. The RFC findings log keeps the full story of the ones marked with an F-number.

| Barry (pinned `478ee89`) | Workaround in Lumina | Suggestion for Barry | Tracked |
| --- | --- | --- | --- |
| Gives the root certificate serial number 0, because only children are numbered (`rpki_tree.c`). RFC 6487 §4.2 requires a positive serial. | Every `case.repo` sets `obj.tbsCertificate.serialNumber = 1` on `ta.cer`. | Number the root too, starting at 1. | F-029, PR #119 |
| Can't set the certificatePolicies value; `add_cp_fields` has a TODO. It always writes id-cp-ipAddr-asNumber with no qualifier. | The policy and RFC 7318 qualifier rules are tested on decoded certificates. | Make `extnValue` editable: policy OIDs and qualifiers. | F-030, PR #120 |
| Writes a hexadecimal INTEGER as raw content octets, so `0x80…` encodes a negative number. Its README describes hexadecimals as byte arrays, so this is documented, but easy to trip on. | Large positive values are written in decimal (`m4-crl-number-too-large`). | Warn when a hexadecimal INTEGER would come out negative, or add a way to write an unsigned value. | PR #122 |
| `revokedCertificates` works: a list of serials, each revoked at `--now`, and the CRL is signed. Its README still lists the field as unimplemented. A per-entry revocation date or entry extensions can't be set. | None needed for revocation; the entry-extension rule (RFC 6487 §5) is tested on decoded CRLs. | Update the README. Allow `{ userCertificate, revocationDate, crlEntryExtensions }` per entry. | #52 |
| A GeneralName in an access description must be written `accessLocation = { value = ... }`; the README doesn't show it. | Used in `m4-cert-sia-no-manifest`. | Document it with an SIA example. | PR #120 |
| Can't set a signed object's signed attributes (beyond the content-type value), unsigned attributes, SignedData digestAlgorithms or crls; its README lists them as unimplemented. It always writes content-type, message-digest and signing-time. | The CMS profile rules for them are tested on decoded objects changed in memory (`test/lumina/cms_test.exs`, #129). | Make `signedAttrs`, `unsignedAttrs`, `digestAlgorithms` and `crls` editable. | #129 |
| Setting only `sid.issuerAndSerialNumber.serialNumber` fails with "Cannot encode SignedData"; the issuer name must be set too. | `m5-cms-sid-issuer-serial` sets `issuer.rdnSequence` as well. | Fill in the issuer, or say what's missing. | #129 |
| Can't mix a prefix list for one address family with `inherit` for the other. | Fixtures use `extnValue = inherit`, which inherits both families. | Allow `inherit` per family. | — |

Improving Barry upstream ([LACNIC/barry](https://github.com/LACNIC/barry)) is the maintainer's call.
