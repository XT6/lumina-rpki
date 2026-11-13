# Design decisions

Decisions about how Lumina works, made by the maintainer, with the reasoning behind them. Each one has an ID, a date, the decision, the reason, and where it was discussed.

Milestone-scoped decisions (such as which ASN.1 compiler to use, or how to treat an RFC erratum) are also recorded in their GitHub milestone or issue. Problems found in the RFC texts are in [rfc-findings.md](rfc-findings.md).

## Summary

| ID | Decision | Date | Discussed in |
| --- | --- | --- | --- |
| [D-001](#d-001-cli-model) | CLI model: `lumina <command> [flags] [arguments]` | 2026-11-12 | #34, PR #53 |

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
