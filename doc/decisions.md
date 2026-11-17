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
| [D-017](#d-017-revocation-fixtures-are-re-signed-by-the-tests) | ~~Revocation fixtures: Barry signs with keys we supply, tests re-sign CRLs with revoked entries~~ (superseded by D-021) | 2026-11-13 | M4 plan, #52 |
| [D-018](#d-018-public-key-algorithm-rsaencryption-sha256withrsaencryption-warned) | Certificate keys: rsaEncryption; sha256WithRSAEncryption accepted with a warning | 2026-11-13 | #108, #109, F-027 |
| [D-019](#d-019-known-extensions-outside-the-certificate-profile-are-treated-as-unknown) | Known extensions outside the certificate profile (e.g. CRL extensions) are treated as unknown | 2026-11-13 | #110, PR #120 |
| [D-020](#d-020-rfc-8360-and-router-certificates-are-out-of-scope-for-now) | RFC 8360 (v2 policy) and router certificates are out of scope for now | 2026-11-13 | #110, PR #120, #121 |
| [D-021](#d-021-revocation-fixtures-use-barrys-revokedcertificates) | Revocation fixtures are plain Barry descriptors using `revokedCertificates` (supersedes D-017) | 2026-11-13 | #112, #52 |
| [D-022](#d-022-lumina-validate-fails-above-a-share-of-invalid-certificates) | `lumina validate` exits 1 only above a share of invalid certificates per TAL (default 10%) | 2026-11-14 | #114, PR #126 |
| [D-023](#d-023-a-failed-publication-point-falls-back-to-its-last-valid-copy) | A failed publication point falls back to its last valid copy while that copy's manifest is current | 2026-11-14 | M5 plan, #135 |
| [D-024](#d-024-manifest-replay-state-is-kept-in-the-cache-and-written-only-by-sync) | Manifest replay state is kept per CA in the cache, written only by `lumina sync` | 2026-11-14 | M5 plan, #136 |
| [D-025](#d-025-absent-rsaencryption-parameters-in-cms-only-warn) | Absent rsaEncryption parameters in a SignerInfo only warn | 2026-11-14 | #130, PR #140, F-031 |
| [D-026](#d-026-inheriting-resources-the-issuer-doesnt-hold-is-holding-none) | Inheriting resources the issuer doesn't hold is holding none (revised the same day) | 2026-11-14 | #153, F-033 |
| [D-027](#d-027-resources-are-compared-as-sets) | Resources are compared as sets | 2026-11-14 | #152, F-034 |
| [D-028](#d-028-an-overclaiming-certificate-is-invalid-as-a-whole) | An overclaiming certificate is invalid as a whole (RFC 6487 §7.2, not RFC 8360) | 2026-11-14 | M6 plan, #154 |
| [D-029](#d-029-a-manifest-ee-certificate-listing-resources-explicitly-only-warns) | A manifest EE certificate listing resources explicitly only warns; an absent kind is fine | 2026-11-15 | #157, F-035 |
| [D-030](#d-030-roa-encoding-shoulds-only-warn) | RFC 9582's SHOULDs on ROA encoding only warn; its MUSTs reject the ROA | 2026-11-15 | M7 plan, #171, F-018 |
| [D-031](#d-031-lumina-vrps-writes-vrps-from-the-cache) | `lumina vrps` validates the cache offline and writes the VRPs | 2026-11-15 | M7 plan, #165 |
| [D-032](#d-032-vrp-csv-in-routinators-columns) | VRP CSV in Routinator's columns; trust anchor named after its TAL file; JSON is our own | 2026-11-15 | M7 plan, #165, #167 |
| [D-033](#d-033-one-row-per-distinct-vrp-unless---wide) | One row per distinct VRP; `--wide` adds the ROA's URI and keeps duplicates | 2026-11-15 | M7 plan, #164, #166 |
| [D-034](#d-034-vrps-are-written-even-above---max-invalid) | Above `--max-invalid`, `lumina vrps` still writes the VRPs and warns | 2026-11-15 | M7 plan, #165 |
| [D-035](#d-035-vrps-compared-with-routinators-live-csv) | VRPs are compared with Routinator's live CSV, downloaded when the comparison runs | 2026-11-15 | M7 plan, #168, #170 |
| [D-036](#d-036-every-long-running-operation-reports-progress) | Every long-running operation reports progress | 2026-11-15 | #180 |
| [D-037](#d-037-lumina-vrps---sync-syncs-only-what-needs-it) | `lumina vrps --sync` syncs only the TALs that need it | 2026-11-16 | #185 |
| [D-038](#d-038-rpkinotify-in-an-ee-certificates-sia-only-warns) | rpkiNotify in an EE certificate's SIA only warns | 2026-11-16 | #190 |
| [D-039](#d-039-a-module-fetch-is-retried-once-after-a-transient-failure) | A module fetch is retried once after a transient failure | 2026-11-16 | #193 |
| [D-040](#d-040-rrdp-failure-falls-back-to-rsync-in-the-same-run) | RRDP failure falls back to rsync in the same run | 2026-11-17 | M8 plan, #206 |
| [D-041](#d-041-rrdp-xml-is-parsed-by-luminas-own-strict-streaming-parser) | RRDP XML is parsed by Lumina's own strict streaming parser; comments allowed | 2026-11-17 | M8 plan, #198 |
| [D-042](#d-042-a-session_id-that-isnt-a-version-4-uuid-only-warns) | A session_id that isn't a version 4 UUID only warns | 2026-11-17 | M8 plan, #199 |
| [D-043](#d-043-rrdp-limits-2-gib-files-300-s-idle) | RRDP limits: 2 GiB files, 300 s idle | 2026-11-17 | M8 plan, #200 |
| [D-044](#d-044-releases-are-0milestonepatch-tagged-and-published-on-github) | Releases are 0.<milestone>.<patch>, tagged and published on GitHub | 2026-11-17 | #211 |

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
- **Done (#137):** a publication point fetched in the current run that fails only because listed files are missing or don't match their hashes (RFC 9286 §6.4, §6.5) gets its module fetched once more and is validated again; a module is fetched again at most once per run (`refetched` in the walk's issues). A point that still fails is handled by D-023.

## D-008: Default fetch limits

- **Date:** 2026-11-13
- **Decision:** defaults, all configurable:

  | Limit | Default |
  | --- | --- |
  | rsync connect timeout | ~~30 s~~ 10 s (2026-11-15, #88) |
  | rsync I/O timeout | 300 s |
  | Maximum object size (rsync and HTTPS) | 20 MB |
  | Maximum walk depth (RFC 6481 §5) | 32 |
  | HTTPS redirects | HTTPS to HTTPS only, at most 3 |

- **Why:**
  - RFC 6481 §5 says the walk SHOULD support a locally configured maximum chain length.
  - The other limits keep a slow or hostile repository from stalling or filling the relying party.
- **Consequences:** #72 (rsync), #73 (HTTPS) and #75 (walk) implement them.
- **Changed (2026-11-15, maintainer, #88):** the rsync connect timeout drops from 30 s to 10 s. In a live LACNIC sync (2026-11-15) the dead delegated hosts hit it, never completing the TCP connection; a working daemon connects well within a second. It bounds only the TCP connection: a server that accepts the connection and then stays silent is stopped by the I/O timeout (300 s), checked on 2026-11-15 with rsync 3.4.1. With #88 a silent host no longer holds up the rest of the walk, so the timeout only bounds how long its own branch waits.

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
  - A module is fetched again for each TAL in a sync (each TAL is a separate walk); sharing fetches across TALs would be a later improvement. **Done in #102:** `Lumina.Sync` passes each walk's fetched modules, with their outcomes, and the modules already refetched, to the next walk (`Walk.run/3` options and result `:fetched`, `:refetched`), so a module is fetched at most once per sync (plus one mid-update retry), and a failed one isn't retried. The TALs are still walked one after the other.
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
- **As implemented (#113):**
  - The TA is validated when it is retrieved (`Lumina.TA`, with `Lumina.Chain.ta/3`): an invalid TA counts as a failed URI, so D-003 moves on to the next one. A cached TA is offered as stale only if it still validates.
  - Each CA certificate in a walked publication point is validated against that CA (with the CRL its CRLDP names in that publication point, D-015) before `Walk.repository/1` is asked where it points. An invalid one is an `invalid` issue listing its errors; a valid one's warnings are a `warning` issue. Neither fails the sync.
  - `lumina validate` (#114) runs the same per-publication-point validation (`Lumina.Validate.point/5`) over the cache, offline, from the stored TA at `--now`, and adds the EE certificates of signed objects. Its exit code is set by D-022.
  - A `.cer` file is checked as a CA certificate when its Basic Constraints say cA or its Key Usage has keyCertSign (RFC 6487 §4.8.1, §4.8.4), so a CA certificate missing Basic Constraints is reported invalid rather than skipped (#115). Other `.cer` files, such as router certificates (D-020), are skipped.
  - Not validated, and not reported: a certificate with the CA's own key (the CA itself, such as LACNIC's TA in its own publication point, #103), and, until manifests list a CA's files (M5), one whose issuer name and AKI both name another CA.
- **Since #134 (manifests):** a CA's products are the files its current manifest lists, in a publication point RFC 9286 §6 accepts (`Lumina.PublicationPoint`). The two directory rules above are gone: neither the CA's own certificate nor another CA's is on the manifest. A failed point is a `point_failed` walk issue with its reasons and nothing below it is walked (§6.6); like an invalid CA, it doesn't change `lumina sync`'s exit code. In `lumina validate` each point is represented by its manifest's entry (valid when the point is accepted, with every reason when not), and files not on a manifest are only counted.

## D-015: The CRL that decides revocation in M4

- **Date:** 2026-11-13
- **Decision:**
  - In M4, a certificate is revoked if its serial number is on the CRL its CRLDP names, found in the issuer's publication point, valid and signed with the issuer's key (RFC 6487 §7.2 point 5 as originally written).
  - M5 adds RFC 9829's requirement: the CRL must also be the one listed on the issuer's current manifest.
- **Why:** RFC 9829 §3.2 changes RFC 6487 §7.2 point 5 so that the issuer's current CRL is the one "identified by the issuer's current manifest and the CRLDP of the certificate". Manifests are M5. Doing CRLs in M4 without the manifest keeps the milestones apart; the manifest check tightens the rule later without changing the CRL code.
- **Where:** M4 plan.
- **Consequences:** M4's chain validation looks up the CRL by CRLDP. An M5 issue adds the manifest cross-check and cites RFC 9829.
- **Done in M5 (#116):** a certificate's CRL must be on its issuer's current manifest (`PublicationPoint.crl/6`); one in the directory but not listed makes the certificate invalid (`crl_not_on_manifest`, RFC 9829 §3.2). The manifest's hash for it is checked when the point is accepted (RFC 9286 §6.5), so a CRL that doesn't match, an older one replayed for instance (RFC 9829 §5), fails the whole point. The manifest's own EE certificate names the same CRL, so a CRL missing from the manifest already fails the point (`crl_not_listed`, #133).

## D-016: A stale CRL is used with a warning

- **Date:** 2026-11-13
- **Decision:** a CRL whose nextUpdate has passed is still used for revocation checks, and a warning is reported. It isn't treated as invalid in M4.
- **Why:** RFC 6487 and RFC 9829 don't say what a relying party does with a CRL past its nextUpdate. Treating it as invalid would invalidate every certificate it covers because a CA published late. M5's manifest rules (RFC 9286 §6) deal with stale publication points, so this is revisited there.
- **Where:** M4 plan.
- **Consequences:** the CRL checks report `stale_crl` as a warning.
- **Revisited (2026-11-14, M5 plan, #133):** kept. RFC 9286 makes a stale *manifest* a failed fetch but says nothing about a stale CRL on a current manifest, and §4.2.1 expects the CRL to be reissued with the manifest.

## D-017: Revocation fixtures are re-signed by the tests

- **Status:** superseded by D-021.
- **Date:** 2026-11-13
- **Decision:** fixtures that need revoked CRL entries are generated by Barry with keys Lumina supplies (`barry --keys=DIR`, PEM files). Tests add the revoked entries to the CRL and re-sign it with the issuer's key, so the CRL is valid and only revocation is being tested.
- **Why:** Barry (pinned `478ee89`) can't write revoked entries (#52). Re-encoding without re-signing, the earlier workaround, tests a broken signature rather than revocation.
- **Where:** M4 plan, #52.
- **Consequences:** fixture keys live in the repository (test-only keys). If Barry gains revoked entries, the fixtures can switch to descriptors and these tests stay the same.

## D-018: Public key algorithm: rsaEncryption, sha256WithRSAEncryption warned

- **Date:** 2026-11-13
- **Decision:** a certificate's subjectPublicKeyInfo algorithm is rsaEncryption with NULL parameters (RFC 4055 §1.2). sha256WithRSAEncryption, which RFC 7935 §3.1 names there, is accepted with a warning. Any other algorithm is rejected.
- **Why:** RFC 7935 §3.1 and RFC 4055 §1.2 disagree (F-027; erratum 5737 rejected on process). Practice and every Barry fixture use rsaEncryption; rejecting a certificate written to the letter of RFC 7935 would be harsher than either text justifies, and the warning makes the case visible.
- **Where:** PR #118 (#108), for #109.
- **Consequences:** `Lumina.Crypto.rsa_public_key/1` reads both; the certificate profile check (#109) adds the warning.

## D-019: Known extensions outside the certificate profile are treated as unknown

- **Date:** 2026-11-13
- **Decision:** an extension Lumina knows but that isn't part of the certificate profile (RFC 6487 §4.8), such as a CRL Number in a certificate, is handled like an unknown extension. If it's critical, the certificate is rejected; if not, it's accepted with a warning (D-013).
- **Why:** such an extension has no meaning in a resource certificate. RFC 6487 §4 excludes fields it doesn't list, and §4.8's rule for unrecognized extensions is the closest fit. Handling it like an unknown extension keeps one rule for both cases.
- **Where:** #110, PR #120.
- **Consequences:** `Lumina.Profile` checks a certificate's extensions against the list of profile extensions, not against the list of extensions the decoder knows.

## D-020: RFC 8360 and router certificates are out of scope for now

- **Date:** 2026-11-13
- **Decisions:**
  - Certificates under RFC 8360's id-cp-ipAddr-asNumber-v2 policy are rejected as unsupported. Their v2 resource extensions are unknown critical extensions, so they are rejected anyway.
  - BGPsec router certificates (RFC 8209) are out of scope. The `:ee` kind in `Lumina.Profile` means the EE certificate of a signed object, so an Extended Key Usage is always rejected (RFC 6487 §4.8.5).
- **Why:** neither is used for VRPs in today's RPKI, and supporting either is new work beyond the RFC 6487 profile.
- **Where:** #110, PR #120. RFC 8360 support is backlog issue #121.
- **Consequences:** when #121 is done, the `:policy` rule accepts the v2 policy and the decoder learns the v2 extensions. Router certificates would need their own certificate kind.

## D-021: Revocation fixtures use Barry's revokedCertificates

- **Date:** 2026-11-13
- **Decision:** revocation fixtures are ordinary Barry descriptors. A `[node: <ca>.crl]` override sets `obj.tbsCertList.revokedCertificates = [ serial, ... ]`, and Barry signs the CRL. Tests don't supply keys or re-sign anything. Supersedes D-017.
- **Why:** the pinned Barry (`478ee89`) already writes signed revoked entries, though its README lists the field as unimplemented (found during #112, commented on #52). D-017's keys and re-signing code would add test-only keys to the repository and code to maintain, for no gain.
- **Where:** #112, #52.
- **Consequences:**
  - Each entry is revoked at `--now`, and entries can't carry extensions. The entry-extension rule (RFC 6487 §5) stays tested on decoded CRLs.
  - The tree must list the CRL (for example `ca1.crl` under `ca1.cer`) for the override to apply.
  - #52's remaining wish is per-entry revocation dates and extensions (`doc/barry.md`).

## D-022: `lumina validate` fails above a share of invalid certificates

- **Date:** 2026-11-14
- **Decision:**
  - `lumina validate` exits 1 for a TAL with no TA in the cache or an invalid TA, or when more than a share of the certificates validated below the TA (CA and EE, files that don't decode included) are invalid. The share is per TAL, 10% by default, set with `--max-invalid PERCENT` (0 to 100; 0 fails on any invalid certificate).
  - Warnings and publication points missing from the cache are listed but don't affect the exit code.
- **Why:** the live RPKI always holds some invalid objects (in 2026-11, 21 expired manifests at one delegated repository out of about 52,000 certificates under LACNIC). Exiting 1 for any of them would make the exit code useless; a large share points at a real problem, such as a broken cache or the wrong `--now`.
- **Where:** #114, PR #126 (maintainer: "over 10 or 20% of all certificates have to be invalid for an exit 1").
- **Consequences:** `Lumina.Validate.failed?/2` takes the percentage. Missing publication points are a fetch problem, reported by `lumina sync`.
- **Since #131:** the share counts CA certificates and signed objects (a signed object is invalid when its CMS envelope or its EE certificate is).
- **Since #134:** a failed publication point counts once, as its manifest's invalid entry; the objects in it aren't validated, so they don't count.

## D-023: A failed publication point falls back to its last valid copy

- **Date:** 2026-11-14
- **Decision:**
  - After a publication point is accepted (RFC 9286 §6), Lumina keeps its manifest and listed files as the CA's last valid copy (under `<cache>/.valid/`), replacing the previous one.
  - When the point later fails, that copy is used, with a warning saying why, as long as its manifest is still current. Once its manifest is stale, the point is unusable.
  - `lumina validate` applies the same rule offline.
- **Why:** RFC 9286 §6.6 says the RP "SHOULD continue to use cached versions of the objects associated with this CA instance, until such time as they become stale". The rsync cache keeps the last *fetched* copy of a module (D-012), which may be the broken one.
- **Where:** M5 plan, #135 (maintainer accepted the recommendation).
- **Consequences:** a second store in the cache, written when a point is accepted; summaries say which points were served from it.
- **As implemented (#135):** `Lumina.LastValid` keeps one copy per manifest URI (so CA instances sharing a directory keep separate copies) under `<cache>/.valid/<cache path of the manifest URI>/`, copied, not linked, and replaced only when the manifest bytes change. `Lumina.Validate.point/5` processes the live copy first; if it fails, it processes the saved copy the same way at the same time, and uses it if it is accepted (point status `:fallback`, warning `last_valid_copy` naming the live failure), otherwise reports the live failure plus `last_valid_copy_unusable`. `lumina sync` saves (`save: true`); `lumina validate` only reads. The walk reports `point_fallback` and walks on from the copy; summaries count the points served from it.

## D-024: Manifest replay state is kept in the cache and written only by sync

- **Date:** 2026-11-14
- **Decision:**
  - For each CA (by its SKI and manifest URI), Lumina keeps the manifestNumber, thisUpdate and file name of the last accepted manifest under `<cache>/.state/`.
  - `lumina sync` updates it when it accepts a point. `lumina validate` reads it but never writes it, so an offline run at another `--now` can't move it.
  - A manifest whose number or thisUpdate goes backwards is a failed fetch (D-023 then applies), with a warning naming both values. A changed manifest file name resets the number check and gives a warning (RFC 9981 §2-3).
- **Why:** RFC 9286 §4.2.1 requires each RP to check that a new manifest's number and thisUpdate are higher than those of manifests it validated before, which needs state that outlives a run.
- **Where:** M5 plan, #136 (maintainer accepted the recommendation).
- **Consequences:** the cache gains `.state`; deleting the cache resets replay protection.
- **As implemented (#136):** `Lumina.ManifestState` keeps one record per CA, keyed by its SKI alone, in `<cache>/.state/manifests/<SKI hex>.json` (manifest URI, number, thisUpdate). Keying by SKI and manifest URI, as first written above, would make a renamed manifest look like a new CA with no history, so RFC 9981's file-name change could never be noticed. The same manifest seen again (same URI, number and thisUpdate) passes; a new one must have a higher number (`manifest_number_replay`) and a more recent thisUpdate (`manifest_this_update_replay`), except that a changed file name skips the number check with the warning `manifest_name_changed`. A failing check fails the point, so D-023's last valid copy can stand in. Only `lumina sync` records, and only points accepted live; `lumina validate` checks against the record without writing it.

## D-025: Absent rsaEncryption parameters in CMS only warn

- **Date:** 2026-11-14
- **Decision:** a SignerInfo whose signatureAlgorithm is rsaEncryption with absent parameters is accepted with a warning (`signature_algorithm_parameters_absent`). NULL passes; any other value is an error.
- **Why:** RFC 3370 §3.2, which RFC 7935 §2 cites, says the parameters "MUST contain NULL". Every object in the LACNIC repository has NULL, but Barry omits them on every object it writes, and it can override them only on nodes declared in a fixture's tree, which manifests usually aren't. Making it an error would mean declaring the manifests in every fixture and regenerating them all.
- **Where:** #130, PR #140, F-031 (maintainer: "Keep the warning").
- **Consequences:** every Barry-generated signed object carries the warning; tests check errors and this warning separately. Revisit if Barry writes NULL.

## D-026: Inheriting resources the issuer doesn't hold is holding none

- **Date:** 2026-11-14 (revised the same day).
- **Decision:** a certificate that uses `inherit` for an address family, or for AS numbers, whose issuer holds none of that kind (after resolving the issuer's own `inherit`) holds none of it. That is not an error and not a warning.
- **Why:** RFC 3779 §2.2.3.5 and §3.2.3.3 take inherited resources from the issuer, recursively, but don't say what happens when nothing is found (F-033). RFC 9286 §5.1 settles it in practice: a manifest's EE certificate "MUST describe its Internet Number Resources (INRs) using the 'inherit' attribute", and producers write inherit for IPv4, IPv6 and AS numbers whatever the CA holds. Under a CA without IPv6, the manifest inherits IPv6 from nothing, as the RFC requires. A certificate that inherits nothing claims nothing, so nothing can be overclaimed.
- **Superseded first version:** the decision as first accepted made this an error (`inherit_from_empty`), thinking of a CA inheriting what its parent doesn't have. On the LACNIC repository that failed 1,527 manifest EE certificates and about 1,500 publication points (1,540 failed instead of 15). It was revised before anything was merged (maintainer, #153).
- **Where:** M6 plan, #153.
- **Consequences:** no rule for it. Whether a manifest's EE certificate actually uses inherit, as RFC 9286 §5.1 asks RPs to check, is a separate check (#157).
- **As implemented (#153):** `Lumina.Resources.effective(cert, issuer_effective)` returns the certificate's IPv4, IPv6 and AS sets, `inherit` resolved from the issuer's, an empty list for a kind held by nobody. `Lumina.Chain.child/6` returns the child's effective resources as `resources`; `Chain.ta/3` returns the TA's. The walk, `lumina validate` and publication point processing (the manifest's EE certificate) carry each CA's effective resources to its children.

## D-027: Resources are compared as sets

- **Date:** 2026-11-14
- **Decision:** "X encompasses Y" (RFC 6487 §7.1) holds when every IPv4 address, IPv6 address and AS number in Y is also in X. Each kind is compared on its own, and as a set of numbers, not range by range: a range of Y that spans two adjacent ranges of X is encompassed.
- **Why:** RFC 6487 §7.1 words it per range ("the range element is either 'more specific' than or 'equal' to a contiguous range element within the set X"), which read literally rejects a child whose range spans two adjacent ranges of its parent. RFC 3779 §2.3 says the child's addresses "MUST be subsumed by IP addresses in the ... issuer's certificate", which is about addresses, not ranges. The two readings differ only when the parent's set isn't in canonical form (RFC 3779 §2.2.3.6 requires adjacent blocks to be combined), so the set reading is the one that doesn't depend on how the parent happens to be encoded (F-034).
- **Where:** #152 (maintainer, comment on the issue: "compare as sets").
- **Consequences:** in Lumina the profile already rejects a non-canonical resource extension, so a valid parent never has adjacent ranges and the two readings give the same verdict; the set reading keeps the inclusion check correct on its own, whatever the profile does.
- **As implemented (#152):** `Lumina.Resources.intervals/2` turns one kind into sorted, merged integer intervals; `encompasses?/2` and `outside/2` (the part of Y outside X, for reporting) work on `effective/0` sets.

## D-028: An overclaiming certificate is invalid as a whole

- **Date:** 2026-11-14
- **Decision:** a CA or EE certificate whose effective resources aren't encompassed by its issuer's is invalid, whatever share of them lies outside. Nothing below an invalid CA is validated. RFC 8360's reconsidered algorithm (keep the certificate, drop the resources outside) isn't applied.
- **Why:** RFC 6487 §7.2 point 6 makes inclusion a condition of a valid certificate, and RFC 3779 §2.3 and §3.3 say "Validation MUST fail when this is not the case". RFC 8360 applies only to certificates under its own v2 policy, which Lumina rejects as unsupported (D-020).
- **Where:** M6 plan, #154 ("the standard RFC 6487 algorithm only"). RFC 8360 is backlog issue #121.
- **Consequences:** one overclaimed prefix invalidates a CA and its whole subtree; #155 makes overclaims visible to operators.
- **As implemented (#154):** `Lumina.Chain.child/6` compares the child's effective resources with the issuer's (`Lumina.Resources.outside/2`, D-027) and adds the error `resources_not_encompassed` (`6487#7.2`, field `:resources`) naming the resources outside, IPv4 then IPv6 then AS numbers. It applies to CA certificates, the EE certificates of signed objects and the manifest's EE certificate (which fails its publication point).

## D-029: A manifest EE certificate listing resources explicitly only warns

- **Date:** 2026-11-15 (the warning: maintainer, 2026-11-14, on #157; the absent-kind reading: proposed on PR #162, confirmed by the maintainer on 2026-11-15, after an example comparing it with the strict reading that every kind must be present with inherit).
- **Decision:** when a manifest's EE certificate lists IPv4, IPv6 or AS numbers explicitly instead of using inherit, the publication point gets the warning `manifest_ee_resources_not_inherit` (`9286#5.1`), naming those kinds, and is still accepted. A kind the EE certificate leaves out doesn't warn.
- **Why:** RFC 9286 §5.1 requires inherit and asks RPs to verify it, without saying what failing means (F-035). Real data follows the rule: all 148 manifests sampled from the LACNIC repository inherit every kind. Barry doesn't: it writes explicit resources on every manifest a fixture doesn't declare in its tree, so as an error the check would fail every fixture (the same situation as D-025). On absent kinds, §5.1 asks for inherit "rather than an explicit description of a resource set", and an absent kind describes nothing; RFC 6487 §4.8.10 and §4.8.11 allow leaving a kind out.
- **Where:** #157.
- **Consequences:** every Barry manifest not declared in its fixture's tree carries the warning; tests check errors and this warning separately. Make it an error once Barry writes inherit on manifests by default (`doc/barry.md`).
- **As implemented (#157):** `Lumina.PublicationPoint.process/5` adds one warning per manifest (field `:resources`), its message listing the explicit kinds: `the manifest's EE certificate lists IPv4, IPv6, AS numbers explicitly instead of using inherit`. `lumina validate` shows it on the manifest's warning line.

## D-030: ROA encoding SHOULDs only warn

- **Date:** 2026-11-15
- **Decision:** a ROA that breaks a SHOULD of RFC 9582 §4.3 is valid and gets a warning: a maxLength equal to the prefix length (§4.3.2.2), addresses out of canonical order or repeated (§4.3.3). The MUSTs reject the whole ROA (§5): version 0, one ROAIPAddressFamily per AFI and no IPv4-mapped IPv6 prefixes (§4.3.1), maxLength within the prefix length and the address width (§4.3.2.2), and the §5 checks on the EE certificate.
- **Why:** the RFC makes them SHOULDs and only tells CAs to "anticipate" stricter RPs (F-018); rejecting them would drop VRPs the RFC calls valid.
- **Where:** M7 plan (maintainer: "only warn"), #171.

## D-031: `lumina vrps` writes VRPs from the cache

- **Date:** 2026-11-15
- **Decision:** VRPs are written by a new command, `lumina vrps [--cache DIR] [--tal FILE]... [--now TIME] [--max-invalid PERCENT] [--format csv|json] [--output FILE] [--wide]`. Like `lumina validate`, it validates the cache offline from each TAL's stored TA; it doesn't fetch. A one-shot command that syncs and then writes VRPs may come later (it came as `--sync`, D-037).
- **Why:** D-001 (commands are verbs, each with its own flags); fetching and validating stay separate, as in `sync` and `validate`.
- **Where:** M7 plan (maintainer: "Agree"), #165.
- **As implemented (#165):** `Lumina.CLI` `vrps_command`; `--format` takes `csv` (JSON in #167, `--wide` in #166). A short summary goes to stderr (VRPs per TAL, and why a TAL fails); stdout has only the CSV. `--output` writes a temporary file next to FILE and renames it over FILE.

## D-032: VRP CSV in Routinator's columns

- **Date:** 2026-11-15
- **Decision:** the default output is CSV with the columns and value forms of Routinator's CSV output: header `ASN,IP Prefix,Max Length,Trust Anchor`, rows such as `AS13335,1.0.0.0/24,24,apnic`. The trust anchor column is the TAL file's name without `.tal` (`lacnic`, `ripe-ncc`, `apnic-rfc7730-https`); the comparison (D-035) maps names to Routinator's. JSON (`--format json`) is Lumina's own format, documented in `doc/output.md`, with room for ASPA.
- **Why:** there's no RFC for VRP output (`doc/rfc/README.md`); a format operators already read, and that matches the reference used for comparison, makes the comparison a set difference. Only the published format is followed, not any code. Naming the trust anchor after its TAL file works for any TAL a user adds.
- **Where:** M7 plan (maintainer: "Use the same format as routinator"; names kept as the TAL files'), #165, #167.
- **As implemented (#167):** the JSON is an object with `metadata` (`generated`, `validationTime`, `lumina`, `trustAnchors` with each TAL's name, file, `status` and row count, and the total `vrps`) and `roas` (`asn`, `prefix`, `maxLength`, `ta`, and `uri` with `--wide`), the CSV's rows in its order. It's written by `Lumina.VRP.json/3` with OTP's `:json` for each value, members in a fixed order and one element per line, so it's deterministic apart from `generated`.

## D-033: One row per distinct VRP, unless `--wide`

- **Date:** 2026-11-15
- **Decision:** the output has one row per distinct (AS, prefix, maxLength, trust anchor), however many ROAs state it. `--wide` adds a column with the rsync URI of the ROA and lists one row per (VRP, ROA), duplicates included.
- **Why:** a VRP is the same authorization whichever ROA states it; for debugging, knowing which ROAs state it matters.
- **Where:** M7 plan (maintainer: a `--wide` or `--full` flag with the rsync URI and duplicates), #164, #166.
- **As implemented (#166):** `lumina vrps --wide`; `Lumina.VRP.csv(vrps, wide: true)` adds a `URI` column and writes every VRP of `Validate.run/3` (one per ROA), in the VRP order, whose last key is the URI.

## D-034: VRPs are written even above `--max-invalid`

- **Date:** 2026-11-15
- **Decision:** when more than `--max-invalid` percent of a TAL's certificates are invalid (D-022), `lumina vrps` still writes all the VRPs, warns on stderr, and exits 1 as `lumina validate` does. A missing or invalid TA gives no VRPs for that TAL.
- **Why:** the VRPs from valid ROAs are still valid; withholding them would hurt more than the anomaly. The warning and exit code let an operator notice.
- **Where:** M7 plan (maintainer: "Warn"; exit 1 confirmed), #165.

## D-035: VRPs compared with Routinator's live CSV

- **Date:** 2026-11-15
- **Decision:** as a sanity check, Lumina's VRPs are compared with the CSV Routinator publishes for all trust anchors at https://routinator.labs.lacnic.net/csv, downloaded when the comparison runs, never committed. The VRPs only one side has are reported per trust anchor. In the M7 done test they may differ by at most 1% of either side per trust anchor; when that bound is exceeded, the CSV is downloaded again once and compared again, to rule out drift. Only the published output is used, never another validator's code (M7 milestone).
- **Why:** a file supplied in advance would have drifted from the live repositories by the time the tests run.
- **Where:** M7 plan (maintainer; the 1% bound and the re-download, on the plan's follow-up), #168, #170.
- **As implemented (#168):** `Lumina.VRPCompare` parses both CSVs into sets of VRPs per trust anchor (by value, so textual forms and duplicate rows don't matter; lines that aren't VRPs are listed and skipped), maps Lumina's names to Routinator's (`ripe-ncc` → `ripe`, `apnic-rfc7730-https` → `apnic`), and downloads the reference with `Lumina.HTTPS.fetch/2` (up to 128 MiB; the file was about 34 MB on 2026-11-15). `mix lumina.compare_vrps` prints the result. A trust anchor only one side has is reported as missing, not as differences.

## D-036: Every long-running operation reports progress

- **Date:** 2026-11-15
- **Decision:** every operation that can run for more than a few seconds on real data reports progress, **by default**: a status line on stderr when stderr is a terminal, timestamped lines otherwise, nothing only with `--quiet`. Commands that run one get `--progress | --quiet`; `--progress` is the default (maintainer, 2026-11-15: "make sure --progress is the default"), so it changes nothing, and is kept for scripts that give it. The work emits `Lumina.Progress` events through a `:progress` option, free without a listener; stdout carries only the command's output.
- **Why:** the maintainer: "ALL long running operations need progress reports / progress bars". A validation of LACNIC alone takes about 45 s, a sync about a minute, and all five RIRs longer; without a report the user can't tell work from a hang.
- **Where:** maintainer, 2026-11-15, while `lumina vrps` was added (#165); #180 adds it to `lumina vrps` and `lumina validate`, and makes it the default for them and for `lumina sync`, which had it since #96 (then only on a terminal or with `--progress`).
- **Consequences:** a new long-running command or stage (RRDP in M8, for example) isn't done until it reports progress, with tests for its events and for `--progress` / `--quiet`.

## D-037: `lumina vrps --sync` syncs only what needs it

- **Date:** 2026-11-16
- **Decision:** the one-shot mode D-031 left room for is a flag on `lumina vrps`, not a separate command: `lumina vrps --sync [--max-age DURATION]` first syncs, as `lumina sync` does, each TAL that has no trust anchor in the cache or whose last sync is older than `--max-age` (default 1 hour), then validates and writes as without it. The other TALs are validated from the cache as they are.
- **Why:** the maintainer preferred a flag to a new command, and syncing only when the cache is missing, incomplete or too old, so that running `lumina vrps --sync` often (from cron, say) doesn't fetch every time.
- **Where:** maintainer, 2026-11-16 ("i like the idea of a flag rather than a separate command. Only sync when cache empty or tal ta missing, or if cache older than a certain threshold"; "1 hour seems fine"), #185.
- **As implemented (#185):**
  - `Lumina.Sync.run/3` records when each TAL's walk ran, in `<cache>/.state/syncs/<TA SKI hex>.json`; `Sync.last_synced/2` reads it. A walk counts even if some fetches failed, or a delegated host that is always down would force a sync every time. A TAL with no record (synced before #185) is synced.
  - The ages are measured on the clock, not at `--now`.
  - The TALs to sync go to one `Sync.run/3`, so they share modules (#102). The sync takes `lumina sync`'s `--timeout`, `--max-depth`, `--per-host` and `--rsync`, which need `--sync`, as does `--max-age` (usage error, exit 2). `--max-age` takes `90s`, `30m`, `2h`, `1d` or seconds.
  - On stderr: why each TAL is synced, the sync's progress (D-036) and summary. A sync with failures (any failed fetch, as for `lumina sync`), or one that can't run (rsync missing, the cache locked), gives a warning, and the VRPs are written from what the cache holds.
  - **Exit code** (maintainer, 2026-11-16: "if the main module under the TA itself fetches, then exiting with 0 is fine, but obviously keep the warnings"): the sync makes the exit code 1 only if a synced TAL's TA wasn't retrieved, or the TA's own publication point wasn't fetched (`Sync.ta_synced?/1`), or the sync couldn't run. Failures further down warn only. On live LACNIC two delegated modules always fail (2026-11-16); with this rule, those runs exit 0.
  - **`lumina sync` too** (maintainer, 2026-11-16: "lumina sync should follow the same rule", #187): it exits 1 only when a TAL's trust anchor wasn't retrieved, its own publication point wasn't fetched, or the sync couldn't run. A fetch failing further down is listed in the summary as before, which ends with `warning: some fetches below the trust anchors failed (above)`, and the exit code is 0.

## D-038: rpkiNotify in an EE certificate's SIA only warns

- **Date:** 2026-11-16
- **Decision:** an id-ad-rpkiNotify access description in an EE certificate's SIA gives the warning `ee_sia_rpki_notify`; the certificate isn't rejected for it. Any other access method besides id-ad-signedObject still rejects it (`access_method`, RFC 6487 §4.8.8.2).
- **Why:** AFRINIC's manifest EE certificates carry rpkiNotify (TD-002). RFC 6487 §4.8.8.2 forbids any method but signedObject, and verified erratum 7239 confirms RFC 8182 §3.2 asks for rpkiNotify in CA certificates only; but RFC 8182 as published says "resource certificates", the method has no bearing on validation, and rejecting it drops a whole RIR's tree. The warning keeps the deviation visible.
- **Where:** maintainer, 2026-11-16 ("Warn for rpkiNotify"), after the M7 done test's live run (#170); #190.
- **Consequences:** `Lumina.Profile` warns; AFRINIC validates.

## D-039: A module fetch is retried once after a transient failure

- **Date:** 2026-11-16
- **Decision:** a module fetch that fails in a way that may not happen again is tried once more, after a short random delay, in the same sync. Transient: the connection dropped or the protocol data stream broke (rsync exit 12), a socket I/O error (exit 10, other than a refused connection or an unknown host), a connect timeout (`--contimeout`, exit 35). Not retried: an unknown host, a missing module or path, a refused connection, and the I/O timeout (`--timeout`, exit 30). At most one retry per module per sync, beside the one fetch and the at most one mid-update refetch (D-007).
- **Why:** the M7 done test's first five-RIR run (#170) lost ARIN's whole tree to one connection reset; the same module fetched fine minutes later. On a fresh cache there is no last good copy to fall back on. Failures that would recur aren't worth a second try, and a silent server would cost another 300 s per module.
- **Where:** maintainer, 2026-11-16 ("retry once, transient failures only, in M7"), #193.
- **As implemented (#193):**
  - `Lumina.Rsync.transient?/1` classifies a failure.
  - The walk waits 10 to 30 s (random) before the retry, without holding the host's place (D-011): other fetches to the host run meanwhile, and the retry then queues first in line. `Walk.run/3`'s `:retry_delay` option sets the delay (tests).
  - The retry runs into the same staging directory, so rsync fetches only what the first run didn't bring; if it fails too, the staging directory is dropped and the last good copy kept, as for any failed fetch.
  - Reported: the first run is a fetch with outcome `:retried` (the fetch count is the number of rsync runs), a `retried` walk issue with the first error, `retried` in the `lumina sync` summary's fetch line, and the progress event `{:fetch_retrying, uri, host, error}`.
  - Once per sync: a module retried by one TAL's walk isn't fetched again by the next (#102). The mid-update refetch isn't retried.

## D-040: RRDP failure falls back to rsync in the same run

- **Date:** 2026-11-17
- **Decision:** a CA whose certificate names an HTTPS `rpkiNotify` is synced over RRDP. When RRDP fails for its repository, Lumina fetches the CA's rsync module in the same run. The failures that count: notification file unreachable or rejected, snapshot unreachable or rejected, or the repository otherwise left unsynced. Rejected deltas fall back to the snapshot first (RFC 8182 §3.4.2). The repository's last good RRDP store is kept either way. The CA's publication point is read from rsync for this run, and RRDP is tried again on the next run.
- **Why:** RFC 8182 §3.4.5 lets RPs use the other access methods in the SIA when RRDP fails. A man in the middle who breaks RRDP only gets the RP onto rsync, which has no channel security anyway; RPKI object security doesn't depend on the transport (§5). Falling back keeps the data current; the last good RRDP copy alone could go stale.
- **Where:** M8 plan (maintainer, 2026-11-17: "rsync fallback, same run"); #206.

## D-041: RRDP XML is parsed by Lumina's own strict streaming parser

- **Date:** 2026-11-17
- **Decision:** RRDP files are parsed by a parser written for Lumina, streaming from the downloaded file with bounded memory. It accepts what RRDP needs: an optional XML declaration (encoding US-ASCII if given), elements, attributes in any order, character references and the five predefined entities, base64 text, whitespace, and comments (XML 1.0 §2.5: no `--` inside), which are skipped. It rejects a DOCTYPE, processing instructions other than the declaration, CDATA sections, any other entity, and bytes outside US-ASCII. The RFC 8182 §3.5.4 schema is checked as the file is read.
- **Why:** Lumina has no runtime dependencies. Snapshots reach 760 MB (ARIN, 2026-11-16), so the whole file can't be held in memory. OTP's `xmerl_sax_parser` handles full XML, including the DTDs and entities RRDP never needs and that entity-expansion attacks use, and builds charlists. In a survey of 109 live notification files (2026-11-16), none used comments, DOCTYPEs or prefixes.
- **Where:** M8 plan (maintainer, 2026-11-17: "Own strict streaming parser"); #198.
- **Changed (2026-11-17, maintainer, before any code):** comments are accepted and skipped ("I'd relax the comments requirement now. Only that one."). XML allows them anywhere markup may appear, and rejecting them would turn a harmless, well-formed file into an RRDP failure (and a fall back to rsync, D-040). Everything else stays rejected.

## D-042: A session_id that isn't a version 4 UUID only warns

- **Date:** 2026-11-17
- **Decision:** a notification, snapshot or delta whose `session_id` is a UUID of another version (or variant) gives a warning, and RRDP is used. One that isn't a UUID at all (the schema allows `[-0-9a-fA-F]+`, RFC 8182 §3.5.4) is rejected.
- **Why:** RFC 8182 §3.5.1.3 says the session_id MUST be a random version 4 UUID, but RPs never use it alone: §3.4.1 pairs it with the notification URI, so the version nibble has no security bearing. prefixlogic's repository serves a version 5 UUID (2026-11-16, TD-003); rejecting it would push that repository to rsync for no gain. Like D-038, the deviation stays visible.
- **Where:** M8 plan (maintainer, 2026-11-17: "Warn, keep using RRDP"); #199.

## D-043: RRDP limits: 2 GiB files, 300 s idle

- **Date:** 2026-11-17
- **Decision:** defaults, all configurable, extending D-008:

  | Limit | Default |
  | --- | --- |
  | Notification file size | 20 MiB |
  | Snapshot or delta file size | 2 GiB |
  | Download time | no total limit; abort after 300 s without data |
  | Each published object | 20 MiB, as for rsync (D-008) |

- **Why:** ARIN's snapshot was 760 MB on 2026-11-16 and RIPE's 284 MB; 2 GiB leaves room to grow. A total time limit would cut off a large snapshot on a slow link; an idle limit still stops a server that stalls. Objects keep the rsync limit, so the transport doesn't change what is accepted.
- **Where:** M8 plan (maintainer, 2026-11-17: "2 GiB files, 300 s idle"); #200.

## D-044: Releases are 0.<milestone>.<patch>, tagged and published on GitHub

- **Date:** 2026-11-17
- **Decision:**
  - **Version:** `0.<last milestone completed>.<patch>`. The minor number is the last milestone closed; the patch number counts releases between milestones, from 0. `mix.exs` holds the same version (Mix requires three parts).
  - **Tag:** annotated, `v` plus the version (`v0.7.0`), on the merge commit on `main` that carries the version bump.
  - **Release:** a GitHub release per tag, with notes and the `lumina` escript attached; GitHub adds the source archives. The escript needs Erlang/OTP (the version in `.tool-versions`) on the host.
  - **When:** a milestone's release follows its closing; patch releases when the maintainer asks.
- **Why:** the maintainer wants tagged commits and source releases, numbered after the milestones ("convention, 0.<last milestone completed>"). `v0.7.0` rather than `v0.7`, so the tag matches `mix.exs`.
- **Where:** maintainer, 2026-11-17, before starting M8; #211. The procedure is in [releasing.md](releasing.md).
- **First release:** v0.7.0, for M7.
