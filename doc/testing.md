# Testing conventions

## Linking tests to RFC sections

Lumina is built only from the RFC texts in [`doc/rfc/`](rfc/README.md). Every test that checks a requirement says which RFC section the requirement comes from. That makes it possible to see which parts of each RFC are covered, and to trace a failing test back to the text it enforces.

### The `:rfc` tag

Add an `:rfc` tag with a reference of the form `"<rfc>#<section>"`:

| Reference | Points to |
| --- | --- |
| `"6487#4.8.9"` | RFC 6487, section 4.8.9 |
| `"8897#4"` | RFC 8897, section 4 |
| `"3779#B"` | RFC 3779, Appendix B |
| `"5280#A.1"` | RFC 5280, Appendix A.1 |

The value is a single reference or a list of them. Use the most specific section that states the requirement.

```elixir
defmodule Lumina.Example.CertificateTest do
  use ExUnit.Case, async: true

  # Applies to every test in the module.
  @moduletag rfc: "6487#4"

  describe "certificate policies" do
    # Applies to every test in this describe block.
    @describetag rfc: "6487#4.8.9"

    # Applies to the next test only.
    @tag rfc: ["7318#2", "8897#4.4"]
    test "accepts a policy qualifier" do
      # ...
    end
  end
end
```

A test's references are its own `@tag`, plus its `describe` block's `@describetag`, plus the module's `@moduletag`.

Write the values as literal strings, not module attributes or computed values. The references are read from the test source without running the tests, and anything that isn't a literal is reported as an error.

### Validation

`test/rfc_references_test.exs` checks every reference in the test suite. A reference fails, and so does the suite, if:

- it isn't in the `"<rfc>#<section>"` form,
- the RFC isn't in `doc/rfc/`, or
- the RFC has no section with that number.

Sections are found from the headings in the RFC text, so a reference has to name a section, not a paragraph.

### Coverage report

```sh
mix lumina.rfc_coverage            # every covered section, with the tests that cover it
mix lumina.rfc_coverage --rfc 8897 # every section of one RFC, covered or not
```

[RFC 8897](rfc/rfc8897.txt) collects the requirements for relying parties from across the other RFCs. Tagging tests with the 8897 section they satisfy, as well as the RFC that defines the rule, turns `mix lumina.rfc_coverage --rfc 8897` into a checklist of RP requirements.

The report fails, like the test suite, if any reference is invalid.

Barry fixtures take their RFC references from their metadata rather than from `@tag`. Those references use the same format, are checked the same way, and show up in the coverage report as `fixture: <title>`.

## Barry fixtures

Repositories for validation tests are generated with [Barry](barry.md). A validator is defined mostly by what it rejects, so most fixtures describe a repository that is wrong in exactly one way.

### Layout

```
test/fixtures/barry/
  m4-ca-cert-expired/
    case.repo     # Barry Repository Descriptor (written by hand)
    case.exs      # metadata (written by hand)
    case.tal      # generated
    rsync/        # generated
    rrdp/         # generated
```

The generated files are committed with the descriptor, so tests are reproducible and plain CI runs don't need Barry.

### Metadata

`case.exs` is a literal map:

```elixir
%{
  id: "m4-ca-cert-expired",
  title: "CA certificate past its notAfter date",
  milestone: "M4",
  rationale: """
  A validator that doesn't check the validity period would accept objects
  signed by a CA whose certificate has expired. Expiry is checked on every
  certificate in the chain, not only on the EE certificate.
  """,
  rfc: ["5280#6.1.3", "6487#4.6"],
  expected: {:invalid, [%{object: "ta/ca1.cer", reason: "notAfter is in the past"}]},
  barry: [now: "2020-01-01T00:00:00Z", later: "2021-01-01T00:00:00Z"]
}
```

| Key | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Same as the folder name. Starts with the milestone (`m4-`), then lowercase words joined by hyphens. |
| `title` | yes | One line saying what the fixture is. |
| `milestone` | yes | `M0` to `M9`. |
| `rationale` | yes | **Why the test exists:** the mistake it catches, and anything subtle about the setup. |
| `rfc` | yes | RFC sections the fixture checks, in the same format as the `:rfc` tag. |
| `expected` | yes | `:valid`, or `{:invalid, rejects}`. Each reject gives an `object` (a path under `rsync/`, which must exist) and the `reason` a validator must reject it. |
| `barry` | no | Overrides the validity period passed to Barry: `now:` and `later:`, as UTC timestamps. |

The file is read as data. Function calls, variables and string interpolation are rejected, and nothing in it is run.

`test/fixtures_metadata_test.exs` checks every fixture folder. A fixture fails, and so does the suite, if:

- metadata is missing or blank,
- an RFC reference is invalid,
- the `id` doesn't match the folder or milestone,
- a rejected object isn't in `rsync/`, or
- the generated output is missing.

### Generating

```sh
mix lumina.fixtures.gen                    # regenerate every fixture
mix lumina.fixtures.gen m4-ca-cert-expired # regenerate one
```

The task removes the old output, runs Barry on `case.repo`, then runs the metadata check. It needs Barry installed (`scripts/install-barry.sh`).

Validity period: unless the metadata overrides it, every object is valid from `2026-01-01T00:00:00Z` (`--now`) to `2036-01-01T00:00:00Z` (`--later`), so committed fixtures don't expire. Fixtures that test time handling set their own dates. Tests that validate fixtures must use a fixed validation time inside that period, not the current time.

Barry generates fresh keys on every run, so regenerating changes every file byte for byte, but not the test results. Barry can reuse stored keys (`--keys`), and with fixed dates that makes its output byte-for-byte reproducible. We don't use it, for two reasons:

- Barry picks each certificate's key from the folder by hashing the file name. With a small pool, unrelated certificates, even a CA and its child, can end up sharing a key.
- Key order depends on the order the folder is read in, which can differ between macOS and Linux.

### Tests that run Barry

Tests tagged `:barry` run the real Barry binary. They're excluded automatically when `_tools/bin/barry` doesn't exist. CI runs them in the `barry` job with `mix test --only barry`.
