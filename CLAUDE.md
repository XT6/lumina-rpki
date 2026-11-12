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
mix check                          # everything CI runs: compile (warnings as errors), format check, tests, catalog check, Dialyzer
mix lumina.rfc_coverage [--rfc N]  # which RFC sections the tests and fixtures cover
mix lumina.fixtures.gen [ID...]    # regenerate Barry fixtures (needs scripts/install-barry.sh)
mix test --only barry              # tests that run the real Barry binary (excluded when it isn't installed)
mix lumina.test_catalog            # regenerate doc/tests/CATALOG.md after adding or changing a test or fixture
```

## Tests

Every test module needs a `@moduledoc` saying what it covers and why. Every test name states the behaviour checked, and `@tag doc: "..."` adds detail. Write literal `test "..."` blocks, not tests generated in loops. The suite fails on an undocumented module. After adding, renaming or re-documenting tests or fixtures, run `mix lumina.test_catalog`, or CI fails.

Tag every test that checks an RFC requirement with the section it comes from, for example `@tag rfc: "6487#4.8.9"`. Use literal strings, not attributes. References are checked against the section headings in `doc/rfc/`, and an invalid one fails the suite. Full convention: `doc/testing.md`.

Repository fixtures live in `test/fixtures/barry/<id>/`: a hand-written `case.repo` (Barry descriptor) and `case.exs` (metadata), plus generated output that is committed. Every fixture must state its rationale, RFC references and expected outcome, or the suite fails. Fixture objects are valid from 2026-01-01 to 2036-01-01 unless a fixture overrides this, so validate fixtures at a fixed time, never "now". Load fixtures in tests with `Lumina.Test.Fixture.load!("m0-minimal-valid")` (`test/support/`).

Lumina has no runtime dependencies. Third-party packages are for development only (`only: [:dev, :test], runtime: false`), pinned to exact versions in `mix.exs`.

Mix's default `.gitignore` ignores `/doc/`. This repo removes that line because `doc/` holds the RFC library. Keep it that way, and send any generated ExDoc output somewhere else.

## Source of truth

- The implementation is derived **only** from the RFC text documents, kept in `doc/rfc/`. Don't rely on other RPKI implementations' behavior or code; cite the RFC and section when making a validation decision.
- ASN.1 modules may be extracted from the RFC texts themselves to generate parsers/decoders.
- Test cases are developed together with Barry (an RPKI test-case tool; URL still to be filled in `GOAL.md`).

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
