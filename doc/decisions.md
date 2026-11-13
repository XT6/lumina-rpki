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
| [D-006](#d-006-one-rsync-run-per-module) | One rsync run per rsync module, not per publication point | 2026-11-13 | M3 plan, #70, #72 |
| [D-007](#d-007-manifest-consistency-deferred-to-m5) | Manifest and directory consistency during a fetch is handled in M5 | 2026-11-13 | M3 plan |
| [D-008](#d-008-default-fetch-limits) | Default fetch limits: timeouts, object size, walk depth, redirects | 2026-11-13 | M3 plan, #72, #73, #75 |

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
