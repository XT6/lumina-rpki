# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Lumina is an RPKI relying party (validator) written from scratch in **Elixir on the Erlang VM**. `GOAL.md` is the project charter; read it before starting larger work.

## Commands

Toolchain versions are pinned in `.tool-versions` (Erlang/OTP 29.1.2, Elixir 1.20.5).

```sh
mix compile --warnings-as-errors   # build; warnings fail the build
mix test                           # full test suite (includes doctests)
mix test test/lumina_test.exs      # one test file
mix test test/lumina_test.exs:5    # one test, by line number
mix format                         # format code
mix dialyzer                       # type analysis; PLTs are cached in priv/plts/ (git-ignored)
mix check                          # everything CI runs: compile (warnings as errors), format check, tests, catalog and ASN.1 extraction checks, Dialyzer
mix lumina.rfc_coverage [--rfc N]  # which RFC sections the tests and fixtures cover
mix lumina.fixtures.gen [ID...]    # regenerate Barry fixtures (needs scripts/install-barry.sh)
mix test --only barry              # tests that run the real Barry binary (excluded when it isn't installed)
mix test --only rsync              # tests against a real rsync daemon (Lumina.Test.RsyncDaemon); excluded without rsync >= 3.1.0
mix test --only realrepo           # tests against the local, git-ignored LACNIC repository copy in test/realrepos/ (excluded without it)
mix lumina.test_catalog            # regenerate doc/tests/CATALOG.md after adding or changing a test or fixture
mix escript.build && ./lumina print [--brief] FILE...   # print RPKI objects and .tal files (Lumina.CLI, Lumina.Print)
mix lumina.asn1.extract            # regenerate asn1/rfc/ (verbatim from doc/rfc) and asn1/build/ (with asn1/patches/ applied)
```

## Tests

Every test module needs a `@moduledoc` saying what it covers and why. Every test name states the behaviour checked, and `@tag doc: "..."` adds detail. Write literal `test "..."` blocks, not tests generated in loops. The suite fails on an undocumented module. After adding, renaming or re-documenting tests or fixtures, run `mix lumina.test_catalog`, or CI fails.

Tag every test that checks an RFC requirement with the section it comes from, for example `@tag rfc: "6487#4.8.9"`. Use literal strings, not attributes. References are checked against the section headings in `doc/rfc/`, and an invalid one fails the suite. Full convention: `doc/testing.md`.

Repository fixtures live in `test/fixtures/barry/<id>/`: a hand-written `case.repo` (Barry descriptor) and `case.exs` (metadata), plus generated output that is committed. Every fixture must state its rationale, RFC references and expected outcome, or the suite fails. Fixture objects are valid from 2026-01-01 to 2036-01-01 unless a fixture overrides this, so validate fixtures at a fixed time, never "now". Load fixtures in tests with `Lumina.Test.Fixture.load!("m0-minimal-valid")` (`test/support/`). Test TALs: hand-written cases in `test/fixtures/tals/cases/<id>/` (`case.tal` byte-exact and never normalized, `case.exs` metadata). Their rule vocabulary and line semantics are in `test/fixtures/tals/README.md`, and every rule must keep at least one case. The five RIR TALs are in `test/fixtures/tals/rir/`, byte-exact, with source, date, SHA-256 and terms in its README. Never edit them, and update one only after the maintainer reviews the change. The production TALs in the top-level `tals/` folder (D-004) are byte-exact copies of these; a test fails if the two differ. TALs are parsed by `Lumina.TAL.parse/1` / `decode_file/1` (strict grammar, D-002), giving comments, URIs, the SPKI DER (`public_key`), `subject_key_identifier/1` and `key_bits/1`. `Lumina.TAL.check_ta(tal, cert)` checks a TA certificate against its TAL per RFC 8630 §2.3/§3: exact key, self-issued CA, AKI = SKI, and resources present, non-empty and not inherit. Signature and dates are M4. `Lumina.TAL.uris_by_preference/1` gives the fetch order (D-003): HTTPS first, then rsync, TAL order within each; on failure or key mismatch, try the next. Repository URIs: `Lumina.URI.parse/1` (strict; rejects dot segments, percent-encoding, user info, queries; drops the default port and a trailing slash), `module/1` (first path segment; not the unit of fetching: rsync fetches each publication point not already covered, D-009) and `cache_path/2` (`<root>/<scheme>/<host[:port]>/<path>`, always inside the root). Fetching decisions: D-005, D-007, D-008, D-009, D-010 (D-006 superseded). The cache (`Lumina.Cache`): fetches go into `stage/1`, then `commit/3` swaps them in (removing symlinks and special files) or `discard/1` drops them, so a failure keeps the last good copy; `put_file/3` for single files; `recover/1` repairs an interrupted swap; `record/4`/`status/2` keep each URI's last attempt and success. Working dirs under the root start with a dot (`.staging`, `.aside`, `.status`). rsync: `Lumina.Rsync.fetch_dir/3` (a publication point, recursive, D-009) and `fetch_file/3`, fixed safe flags and D-008 limits, typed error reasons, oversize files skipped and reported. Sources are always `rsync://host/module/./path` so a path can't become a server-side option (F-025). HTTPS: `Lumina.HTTPS.fetch/2` (single files such as TA certificates, RFC 8630 §4): `:ssl` with peer and host name verification against the system CA store (`:cacerts` overrides it, for tests), TLS 1.2+, validation failures logged, wildcard-only matches accepted but warned (D-010), redirects HTTPS-only and at most 3, D-008 size and timeout limits, typed error reasons. It speaks HTTP/1.1 itself because `:httpc` can't bound every body (F-026). Tests use `Lumina.Test.HTTPSServer` with certificates generated per test. TA retrieval: `Lumina.TA.retrieve(tal, root, opts)` tries the TAL's URIs in D-003 order, decodes and `check_ta`s each, accepts the first that passes and stores it at `<root>/.ta/<ski hex>.cer` (with a `.json` note of URI and time); every attempt is listed, and if all fail the error carries the previously accepted TA as `:stale` (`cached/2`). Cache working dirs now include `.ta`. Repository walk: `Lumina.Walk.run(ta_cert, root, opts)` (RFC 6481 §5) fetches each CA's `caRepository` once per run (skipping ones inside a directory already fetched, D-009), follows CA certificates chosen by `Walk.repository/1` (the single D-005 selection point; M4 swaps in validation), stops at `:max_depth` (32) and at loops, keeps the last good copy on failure, and returns `points`, `fetches` and `issues`. `:remap` (tests only) points fixture hosts such as `localhost:8873` at a test daemon. Walk fixtures are `m3-walk-*`.

Lumina has no runtime dependencies. Third-party packages are for development only (`only: [:dev, :test], runtime: false`), pinned to exact versions in `mix.exs`.

Mix's default `.gitignore` ignores `/doc/`. This repo removes that line because `doc/` holds the RFC library. Keep it that way, and send any generated ExDoc output somewhere else.

## Source of truth

- The implementation is derived **only** from the RFC text documents, kept in `doc/rfc/`. Don't rely on other RPKI implementations' behavior or code; cite the RFC and section when making a validation decision.
- ASN.1 modules are extracted verbatim from the RFC texts into `asn1/rfc/`. Compiler workarounds live in `asn1/patches/` (strict unified diffs; each hunk has a `-- LUMINA PATCH (<kind>): <reason>` comment, and its kind limits what it may change), and `asn1/build/` holds the result. Never edit `rfc/` or `build/`, and never apply RFC errata by patching; enforce them in validation. See `asn1/README.md`. `mix compile` turns `asn1/build/` into Erlang in `gen/asn1/` (git-ignored), using the `lumina_asn1` compiler defined in `mix.exs`. Decode and encode only through `Lumina.ASN1` (`decode(:pkix, :Certificate, der)`), which never raises and rejects trailing bytes. Values are maps keyed by ASN.1 field names. `Lumina.ASN1` accepts BER, so check every object from a repository with `Lumina.DER.check/1` (schema-less walk) and, for typed values, `Lumina.DER.check_canonical/3` (decode + re-encode must give identical bytes). DER errors carry the rule, the X.690 clause (02/2021 numbering) and a byte offset. RFC 3779 resources: `Lumina.Resources.decode_ip/1` and `decode_as/1` turn extension values into integer prefixes and ranges. Canonical-form problems are reported by `ip_issues/1` and `as_issues/1`, never enforced during decoding. Certificates: `Lumina.Certificate.decode/1` gives a struct with every field, decoded extensions (`extension_value/2`, `sia_uris/2`, `aia_uris/2`), and the exact signed bytes (`tbs_der`, `issuer_der`, `subject_der`, `public_key.der`). Profile violations decode; only non-DER or unparseable input fails, with the failing layer in the error. `Lumina.CRL.decode/1` does the same for CRLs (`number/1`, `revoked?/2`, exact `tbs_der`/`issuer_der`). Extensions of certificates, CRLs and CRL entries are `Lumina.Extension` structs (`value` is decoded, `:unknown` or `{:malformed, reason}`). Signed objects: `Lumina.SignedObject.decode/1` decodes the CMS envelope (EE certificate with its exact DER, signers with decoded signed attributes and `signed_attrs_der`, the exact SET OF bytes the signature covers). eContent stays raw, and `decode_econtent/1` decodes it through the content-type table, which replaces the patched-out `CONTENT-TYPE` objects. RFC 7935 §2: SignerInfo uses `rsaEncryption`, and RPs accept that or `sha256WithRSAEncryption`. ROAs: `Lumina.ROA.decode/1` (full object) or `decode_econtent/1` (bare payload); `vrps/1` gives AS, prefix and effective maxLength; `issues/1` reports RFC 9582 §4.3 encoding problems without rejecting. Manifests: `Lumina.Manifest.decode/1` (full object) or `decode_econtent/1`; `names/1`, `hash/2`. An empty file list decodes (rejected in M5, #37). Any repository file: `Lumina.Object.decode(file_name, bytes)` / `decode_file(path)` picks the decoder by registered extension (`.cer .crl .mft .roa .gbr .sig .tak`), checks a signed object's eContent type against it, and returns errors whose layer `Lumina.Object.layer/1` names (`:der`, `:asn1`, `:envelope`, `:econtent`, `:type`, `:file`).
- Test cases are developed together with Barry (an RPKI test-case tool; URL still to be filled in `GOAL.md`).

## Design decisions

Maintainer decisions about how Lumina works are recorded in `doc/decisions.md` (D-001, D-002, ...), with the reason and where they were discussed. Record new ones there when the maintainer makes them, and follow them. Example: D-001 sets the CLI model, `lumina <command> [flags] [arguments]`, so new functionality is added as a command with its own flags, never as a top-level `--flag`.

## RFC findings log

Record every RFC erratum, ambiguity, missing or obsolete reference, and tooling incompatibility you run into in `doc/rfc-findings.md`, as you find it. It's talk material for the maintainer.
- Before relying on an RFC's ASN.1 module, worked example or test vector, check its errata at <https://www.rfc-editor.org/errata.json> and record anything relevant.
- Each entry quotes the text, gives the official errata status (ID, or "none found" with the date) and links the issue that resolves it.
- Never submit errata to the RFC Editor yourself. Mark new ones "not reported" and tell the maintainer.
- Our own mistakes don't belong in the entries. If they say something about the process, add them to "Process notes".

## Planned feature scope

1. TAL parsing
2. Repository retrieval: rsync first, RRDP later
3. Cryptographic validation of repository objects
4. Resource-inclusion validation (child resources within parent certificates)
5. Output: VRPs as text; VRPs and ASPA as JSON

## Workflow rules

- Work is tracked on GitHub: milestones for large work packages, atomic and testable issues filed against milestones.
- One PR per issue.
- Unit-test everything that can be unit tested. Each issue defines the tests it must pass.
- An issue can't be closed unless its tests pass, unless the maintainer (Carlos) explicitly acknowledges otherwise. A milestone can't be closed unless all tests pass.
