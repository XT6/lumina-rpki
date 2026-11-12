# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Lumina is an RPKI relying party (validator) written from scratch in **Elixir on the Erlang VM**. `GOAL.md` is the project charter; read it before starting larger work.

Status: pre-code. There is no Mix project, build, or test setup yet. When one is scaffolded, add the build, test, and single-test commands here.

## Source of truth

- The implementation is derived **only** from the RFC text documents, kept in `doc/rfc/`. Don't rely on other RPKI implementations' behavior or code; cite the RFC and section when making a validation decision.
- ASN.1 modules may be extracted from the RFC texts themselves to generate parsers/decoders.
- Test cases are developed together with Barry (an RPKI test-case tool; URL still to be filled in `GOAL.md`).

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
