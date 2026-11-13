# Design decisions

Decisions about how Lumina works, made by the maintainer, with the reasoning behind them. Each one has an ID, a date, the decision, the reason, and where it was discussed.

Milestone-scoped decisions (such as which ASN.1 compiler to use, or how to treat an RFC erratum) are also recorded in their GitHub milestone or issue. Problems found in the RFC texts are in [rfc-findings.md](rfc-findings.md).

## Summary

| ID | Decision | Date | Discussed in |
| --- | --- | --- | --- |
| [D-001](#d-001-cli-model) | CLI model: `lumina <command> [flags] [arguments]` | 2026-11-12 | #34, PR #53 |
| [D-002](#d-002-tal-parsing-strictness) | TAL parsing: strict RFC 8630 §2.2 grammar; trailing whitespace only warns | 2026-11-12 | #54, M2 |
| [D-003](#d-003-order-of-ta-uris) | TA URIs tried HTTPS first, then in TAL order | 2026-11-12 | #57, M2 |
| [D-004](#d-004-production-tals) | Production TALs live in a top-level `tals/` folder, copies of the reviewed RIR TALs | 2026-11-13 | #67, M2 |
| [D-005](#d-005-repository-walk-before-validation) | M3 walks the repository through every CA certificate that decodes; M4 narrows it to those that validate | 2026-11-13 | M3 plan, #75 |
| [D-006](#d-006-one-rsync-run-per-module) | ~~One rsync run per rsync module~~ (superseded by D-009) | 2026-11-13 | M3 plan, #70, #72 |
| [D-007](#d-007-manifest-consistency-deferred-to-m5) | Manifest and directory consistency during a fetch is handled in M5 | 2026-11-13 | M3 plan |
| [D-008](#d-008-default-fetch-limits) | Default fetch limits: timeouts, object size, walk depth, redirects | 2026-11-13 | M3 plan, #72, #73, #75 |
| [D-009](#d-009-one-rsync-run-per-publication-point-not-already-covered) | ~~One rsync run per publication point, skipping any inside a directory already fetched in the run~~ (superseded by D-012) | 2026-11-13 | M3, #72, #75 |
| [D-010](#d-010-wildcard-server-certificates-are-accepted-with-a-warning) | Wildcard-only HTTPS server certificates are accepted with a warning | 2026-11-13 | PR #81, #73 |
| [D-011](#d-011-publication-points-fetched-in-parallel-capped-per-host) | Each walk level's rsync runs go in parallel, at most 8 at once per host | 2026-11-13 | #77, #85 |
| [D-012](#d-012-one-rsync-run-per-module-again) | One rsync run per module, as D-006: shared hosts are rare enough | 2026-11-13 | #99 |
| [D-013](#d-013-unknown-non-critical-extensions-accepted-with-a-warning) | Unknown non-critical certificate extensions are accepted with a warning | 2026-11-13 | #42, M4 plan |
| [D-014](#d-014-validation-during-the-walk) | Certificates are validated during the walk; only valid CAs are followed | 2026-11-13 | M4 plan |
| [D-015](#d-015-the-crl-that-decides-revocation-in-m4) | In M4, revocation uses the CRL named by the CRLDP; M5 adds the manifest check (RFC 9829) | 2026-11-13 | M4 plan |
| [D-016](#d-016-a-stale-crl-is-used-with-a-warning) | A CRL past its nextUpdate is still used, with a warning | 2026-11-13 | M4 plan |
| [D-017](#d-017-revocation-fixtures-are-re-signed-by-the-tests) | Revocation fixtures: Barry signs with keys we supply, tests re-sign CRLs with revoked entries | 2026-11-13 | M4 plan, #52 |

## D-001: CLI model

- **Date:** 2026-11-12
- **Decision:** the `lumina` executable uses the **command plus flags** model:

  ```
  lumina <command> [flags] [arguments]
  lumina print [--brief] FILE...
  lumina help [command]
  ```

  - **Commands** are verbs. Each command has its own flags and help text. The first is `print`; the validator commands come in M7.
  - **`print`** without flags gives the full printout. With **`--brief`** it leaves out most of the cryptographic detail: key identifiers, public keys, signature algorithms and values, digests, signer details and manifest hashes. It keeps validity dates and the useful payload: names, serials, resources, repository and CRL URIs, ROA prefixes, manifest file names, CRL revocations and unknown extensions.
  - **Exit codes** are shared by all commands: `0` success, `1` a file failed to decode (or, later, to validate), `2` a usage error, including an unknown command or flag.
- **Why:**
  - Lumina will grow several distinct operations (print, validate, output VRPs, and more), each with its own options.
  - Commands keep each operation's flags separate and make the help text per command.
  - New commands don't change the meaning of existing ones.
  - `--print` was the first version (PR #53, before this decision).
- **Consequences:**
  - `Lumina.CLI` dispatches on the first argument.
  - Unknown commands and flags exit `2` with usage.
  - Tests call `Lumina.CLI.run/3`, which returns the exit code instead of halting.

## D-002: TAL parsing strictness

- **Date:** 2026-11-12
- **Decision:** TALs are parsed with the RFC 8630 §2.2 grammar followed **strictly**:
  - comments only at the top
  - one or more rsync or HTTPS URIs
  - exactly one blank line
  - the base64 key, with nothing after it

  Anything outside that grammar is an error naming the rule and the line. The one exception is **trailing whitespace** on any line, which is ignored with a warning per line.
- **Why:**
  - RFC 8630 §2.2 doesn't say what to do with whitespace, extra blank lines or misplaced comments (F-021).
  - A strict parser makes every relying party's reading of a TAL the same, and a malformed TAL is better fixed than guessed at.
  - Trailing whitespace is the exception because editors add it invisibly and it carries no meaning.
- **Consequences:**
  - The rules and line semantics are fixed by the test TAL corpus (`test/fixtures/tals/README.md`, #55) and implemented by `Lumina.TAL` (#54).
  - The RFC's own example, copied with its indentation, is rejected (F-021).

## D-003: Order of TA URIs

- **Date:** 2026-11-12
- **Decision:** a TAL's URIs are tried **HTTPS first**, in the order the TAL lists them, then rsync in TAL order. If a URI fails, or returns a certificate whose key doesn't match the TAL, the next one is tried.
- **Why:**
  - RFC 8630 §3 leaves the preference rule to each relying party.
  - §4 RECOMMENDS HTTPS, because rsync has no transport security.
  - The TAL's own order is kept within each scheme.
- **Consequences:** `Lumina.TAL.uris_by_preference/1` (#57) implements it, and M3's fetcher follows it.

## D-004: Production TALs

- **Date:** 2026-11-13
- **Decision:** the TALs Lumina uses in production live in a top-level **`tals/`** folder. It starts with the five RIR TALs the maintainer approved in #58: AFRINIC, APNIC (HTTPS-first archive variant), ARIN, LACNIC and RIPE NCC. Each is a byte-exact copy of the file in `test/fixtures/tals/rir/`.
- **Why:**
  - Production TALs belong outside the test tree.
  - Keeping them identical to the test copies means every production TAL has been reviewed (source, terms), and parsed by the tests.
- **Consequences:**
  - A test fails if `tals/` and `test/fixtures/tals/rir/` differ.
  - Updating a TAL means updating both (`tals/README.md`).

## D-005: Repository walk before validation

- **Date:** 2026-11-13
- **Decision:**
  - In M3 the repository walk starts at the accepted TA and follows the SIA `caRepository` of every CA certificate that **decodes**: cA true, with a `caRepository` URI.
  - The walk is bounded by D-008's depth limit, loop detection and size limits.
  - M4, which validates certificates, changes "decodes" to "**validates**".
- **Why:**
  - RFC 6481 §5 describes a top-down walk through *valid* certificates, but validation arrives in M4.
  - M3's "done when" is mirroring a live RIR repository, which needs a walk.
  - The bounds keep a hostile or broken repository from making the walk run forever.
- **Consequences:** #75 implements the walk with the CA selection in one place, so M4 can swap in validation.

## D-006: One rsync run per module

- **Status:** superseded by [D-009](#d-009-one-rsync-run-per-publication-point-not-already-covered) on 2026-11-13, before any fetching code was written.
- **Date:** 2026-11-13
- **Decision:**
  - rsync fetches whole **modules**, `rsync://host[:port]/module/`, the URI's first path segment, recursively and once per run.
  - A publication point inside a module that has already been fetched needs no fetch of its own.
- **Why:**
  - Fewer rsync runs, and repository trees are expected to be clean (RFC 6481 §3: "Aside from subdirectories, any other objects SHOULD NOT be placed in a repository publication point").
  - The alternative, one run per publication point, follows the SIA more exactly, at the cost of many more connections.
- **Consequences:**
  - `Lumina.URI.module/1` (#70) gives the module, and the rsync runner (#72) fetches it.
  - RFC 5781 doesn't define modules at all (F-024).
  - The trailing slash of a `caRepository` URI (F-016) no longer changes what is fetched.

## D-007: Manifest consistency deferred to M5

- **Date:** 2026-11-13
- **Decision:** RFC 6481 §5 asks RPs to allow for a manifest and its directory being out of step during a fetch, for example by fetching the manifest again and retrying when it changed. That is handled in **M5**, where manifests are validated. M3 records what was fetched and when.
- **Why:** detecting the inconsistency needs manifest processing, which M3 doesn't have.
- **Consequences:** the cache store (#71) records each module's fetch time and outcome for M5 to use.

## D-008: Default fetch limits

- **Date:** 2026-11-13
- **Decision:** defaults, all configurable:

  | Limit | Default |
  | --- | --- |
  | rsync connect timeout | 30 s |
  | rsync I/O timeout | 300 s |
  | Maximum object size (rsync and HTTPS) | 20 MB |
  | Maximum walk depth (RFC 6481 §5) | 32 |
  | HTTPS redirects | HTTPS to HTTPS only, at most 3 |

- **Why:**
  - RFC 6481 §5 says the walk SHOULD support a locally configured maximum chain length.
  - The other limits keep a slow or hostile repository from stalling or filling the relying party.
- **Consequences:** #72 (rsync), #73 (HTTPS) and #75 (walk) implement them.

## D-009: One rsync run per publication point not already covered

- **Status:** superseded by [D-012](#d-012-one-rsync-run-per-module-again) on 2026-11-13.
- **Date:** 2026-11-13
- **Supersedes:** D-006.
- **Decision:**
  - rsync fetches a CA's **publication point**, the directory its SIA `caRepository` URI names, recursively, including every subdirectory.
  - A publication point inside a directory already fetched in the same run needs no fetch of its own.
  - The rsync module is no longer the unit of fetching.
- **Why:**
  - **Shared hosting:** D-006 assumed each rsync module holds one organisation's tree. Shared hosting breaks that.
    - In the maintainer's copy of the LACNIC repository, one CA delegates to `rsync://rpki-rsync.us-east-2.amazonaws.com/volume/c474d778-43cb-4c30-ad6a-39968cbc94bc/`.
    - The module there, `volume`, holds every CA that host serves, from any RIR, so fetching it would download other organisations' content to get one directory.
  - **The same few runs:** a recursive fetch of the TA's publication point still covers every CA nested below it. The LACNIC tree needs **3** rsync runs:
    - `rsync://repository.lacnic.net/rpki/lacnic/` covers 3,512 of its 3,514 CA certificates.
    - The other two are delegations to `rsync://rpki-repo.registro.br/repo/nicbr_repo/1/` and the Amazon-hosted directory above.
    - **Live, this estimate was wrong** (2026-11-13, #77): the local copy lacked registro.br's own tree. registro.br's member CAs each publish in a sibling directory, `rsync://rpki-repo.registro.br/repo/<key>/1/`, which no fetched directory covers. A sequential walk had made about 2,950 rsync runs there after 28 minutes, unfinished. D-011 keeps this rule and runs the fetches in parallel.
  - **It follows the RFCs:** RFC 6481 §2 and RFC 6487 §4.8.8.1 define the `caRepository` directory as the place that holds a CA's products. Fetching it means fetching what the certificate points to.
- **Consequences:**
  - The rsync runner (#72) fetches any rsync directory URI.
  - The walk (#75) works out which publication points are already covered.
  - `Lumina.URI.module/1` stays as a helper but isn't the unit of fetching.
  - The cache layout doesn't change: a publication point lands at its own `cache_path/2`, inside its host's tree.

## D-010: Wildcard server certificates are accepted with a warning

- **Date:** 2026-11-13
- **Decision:** when an HTTPS server's certificate matches the host only through a wildcard dNSName (`*.example.net`), Lumina accepts it, logs a warning and reports it in the fetch result.
- **Why:**
  - RFC 8630 §4 says DNS names in repository server certificates SHOULD NOT contain `*`. That is a rule for servers, not an instruction to relying parties to reject them.
  - Standard RFC 6125 matching accepts a wildcard in the leftmost label, and rejecting it could lose a TA certificate over a server-side SHOULD.
  - The warning lets an operator see the deviation.
  - It happens in production: on 2026-11-13, `https://rpki.afrinic.net/repository/AfriNIC.cer` was served with a certificate for `*.afrinic.net` only. Rejecting wildcards would lose AFRINIC's HTTPS TA URI. The same day, LACNIC's `https://rrdp.lacnic.net/ta/rta-lacnic-rpki.cer` was served with a certificate for `*.lacnic.net` only (#77).
- **Where:** PR #81 review, after #73.
- **Consequences:** `Lumina.HTTPS.fetch/2` returns `:warnings` with `{:wildcard_certificate, uri, name}`; #74 and `lumina sync` (#76) pass them on.

## D-011: Publication points fetched in parallel, capped per host

- **Date:** 2026-11-13
- **Decision:**
  - The walk keeps D-009's rule for *what* is fetched, but fetches the publication points of one breadth-first level **concurrently**.
  - At most **8** rsync runs at once per host (`:per_host` option of `Lumina.Walk.run/3`); different hosts are fetched at the same time.
  - Results are reported in walk order, the same as a sequential walk.
- **Why:**
  - The live LACNIC tree delegates to registro.br, where thousands of member CAs each publish in a directory of their own (see D-009). One rsync run each, one after another, took well over half an hour.
  - The maintainer chose parallel fetches over going back to fetching a whole parent directory (D-006's problem with shared hosting) or waiting for RRDP.
  - The per-host cap keeps any one repository server from seeing more than a few connections from Lumina at once.
- **Where:** #77 (live LACNIC run), #85.
- **Consequences:**
  - `Lumina.Walk` plans a level in order, fetches its new publication points with `Task.async_stream`, then reports in order. A point nested in another fetched in the same level isn't fetched again.
  - Fixture `m3-walk-siblings` (eight sibling CAs) and the test daemon's `:max_connections` option check the cap.
  - The cap is configurable: `lumina sync --per-host N` (#98), for slow links where each rsync run costs more.
  - Live result (2026-11-13, #77): the LACNIC tree took 3,685 rsync runs to 8 hosts and 7,195 publication points; fetching took about 4.5 minutes, against over 28 minutes unfinished sequentially. A level waits for its slowest fetch, so one unresponsive host (rsync connect timeout, 30 s) delays the next level.

## D-012: One rsync run per module, again

- **Date:** 2026-11-13
- **Supersedes:** D-009 (and restores D-006's unit of fetching).
- **Decision:**
  - rsync fetches the **module** of a publication point, `rsync://host[:port]/module/` (`Lumina.URI.module/1`), recursively, at most once per walk.
  - A publication point in a module already fetched in the walk is read from that copy.
  - D-011 still applies: the modules of one level are fetched in parallel, at most `--per-host` (8) at once per host.
- **Why:**
  - The maintainer: "as it would be rare that a pub host is shared, pull everything".
  - **Run count:** under D-009, registro.br's ~3,680 member CAs each took an rsync run, because each publishes in its own directory of `rsync://rpki-repo.registro.br/repo/`. A cold LACNIC sync took 4 min 32 s here, 3 min 40 s of it on that one level, and much longer from a machine farther away. The module `repo/` is 32,260 files and 58 MB in **one** run (its listing took 1.8 s on 2026-11-13).
  - **The cost D-009 avoided:** on a shared host the module holds other organisations' trees. Amazon's `rpki-rsync.us-east-2.amazonaws.com/volume/` has 77 top-level directories (22,220 files, 48 MB), of which LACNIC's tree uses 2. That's paid once, then rsync transfers only changes. Content outside the tree is mirrored but never walked.
- **Where:** after the slow sync on the maintainer's second machine, #99.
- **Consequences:**
  - `Lumina.Walk` plans a fetch of the module of each publication point not covered; `fetches` list modules, and each point's `covered_by` is its module.
  - Fixtures can serve extra modules on `localhost:8873` with `rsync_modules` in `case.exs`; `m3-walk-siblings` puts eight CAs in eight modules to keep testing D-011's cap.
  - A module is fetched again for each TAL in a sync (each TAL is a separate walk); sharing fetches across TALs would be a later improvement.
  - **Measured** (cold cache, 2026-11-13, LACNIC): 10 rsync runs instead of 3,685, and 1 min 52 s instead of 4 min 32 s. About a minute of what remains is three unresponsive delegated hosts waiting out rsync's 30 s connect timeout (#88). The cache holds 82,827 files.

## D-013: Unknown non-critical extensions accepted with a warning

- **Date:** 2026-11-13
- **Decision:** a resource certificate with a non-critical extension Lumina doesn't recognise is validated as if the extension weren't there. The extension is reported as a warning (its OID and the certificate). Unknown **critical** extensions are rejected, as RFC 6487 §4.8 requires.
- **Why:**
  - RFC 6487 §4.8: "a non-critical extension MAY be ignored if it is not recognized", with RFC 5280's general rule behind it.
  - RFC 8897 §3.1's "any extension excluded by Section 4.8" doesn't say what is excluded (F-015), so rejecting would rest on a reading, not on the text.
  - The warning keeps the deviation visible to operators, as D-010 does for wildcard certificates.
- **Where:** M4 plan, #42; resolves the open part of F-015.
- **Consequences:** the certificate extension checks (M4) list known extensions; anything else non-critical becomes a warning in the validation result, not a rejection.

## D-014: Validation during the walk

- **Date:** 2026-11-13
- **Completes:** D-005.
- **Decision:**
  - Certificates are validated as the walk reaches them (RFC 6481 §5, RFC 6487 §7.2). The walk follows only CA certificates that validate; an invalid CA is reported with its reasons and nothing below it is walked.
  - The same validation can be run offline over the cache (`lumina validate`), at a given time, without fetching.
- **Why:** RFC 6481 §5 describes a top-down walk through *valid* certificates. Following invalid CAs fetches repositories that can't contribute anything, and invalid certificates are exactly where an attacker would point a walk.
- **Where:** M4 plan.
- **Consequences:** `Walk.repository/1` (D-005's single selection point) takes the validation result. Validation needs the parent's key and CRL, so the walk carries the parent's validated certificate down.

## D-015: The CRL that decides revocation in M4

- **Date:** 2026-11-13
- **Decision:**
  - In M4, a certificate is revoked if its serial number is on the CRL its CRLDP names, found in the issuer's publication point, valid and signed with the issuer's key (RFC 6487 §7.2 point 5 as originally written).
  - M5 adds RFC 9829's requirement: the CRL must also be the one listed on the issuer's current manifest.
- **Why:** RFC 9829 §3.2 changes RFC 6487 §7.2 point 5 so that the issuer's current CRL is the one "identified by the issuer's current manifest and the CRLDP of the certificate". Manifests are M5. Doing CRLs in M4 without the manifest keeps the milestones apart; the manifest check tightens the rule later without changing the CRL code.
- **Where:** M4 plan.
- **Consequences:** M4's chain validation looks up the CRL by CRLDP. An M5 issue adds the manifest cross-check and cites RFC 9829.

## D-016: A stale CRL is used with a warning

- **Date:** 2026-11-13
- **Decision:** a CRL whose nextUpdate has passed is still used for revocation checks, and a warning is reported. It isn't treated as invalid in M4.
- **Why:** RFC 6487 and RFC 9829 don't say what a relying party does with a CRL past its nextUpdate. Treating it as invalid would invalidate every certificate it covers because a CA published late. M5's manifest rules (RFC 9286 §6) deal with stale publication points, so this is revisited there.
- **Where:** M4 plan.
- **Consequences:** the CRL checks report `stale_crl` as a warning.

## D-017: Revocation fixtures are re-signed by the tests

- **Date:** 2026-11-13
- **Decision:** fixtures that need revoked CRL entries are generated by Barry with keys Lumina supplies (`barry --keys=DIR`, PEM files). Tests add the revoked entries to the CRL and re-sign it with the issuer's key, so the CRL is valid and only revocation is being tested.
- **Why:** Barry (pinned `478ee89`) can't write revoked entries (#52). Re-encoding without re-signing, the earlier workaround, tests a broken signature rather than revocation.
- **Where:** M4 plan, #52.
- **Consequences:** fixture keys live in the repository (test-only keys). If Barry gains revoked entries, the fixtures can switch to descriptors and these tests stay the same.
