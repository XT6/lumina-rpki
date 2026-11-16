# Testing conventions

Every test is documented, and every requirement it checks is traced to an RFC section. Both rules are enforced by the test suite, and [`doc/tests/CATALOG.md`](tests/CATALOG.md) lists every test with its documentation.

## Documenting unit tests

- **Every test module has a `@moduledoc`.** It says what the module covers and why those tests exist: what would go wrong without them. `@moduledoc false` is not allowed.
- **Every test name is a sentence stating the behaviour checked,** such as `"rejects a ROA whose version is not 0"`, not `"version test"`.
- **`@tag doc: "..."`** adds a reason that doesn't fit in the name: an edge case, a past bug, or why the setup looks odd. It applies to the next test only.
- **Write tests as literal `test "..." do` blocks.** Tests generated in a loop, or with interpolated names, can't be read from source. Put the loop inside one test instead.

```elixir
defmodule Lumina.Example.RoaTest do
  @moduledoc """
  ROA eContent checks from RFC 9582 §4. A validator that accepts a malformed
  ROA would publish VRPs nobody authorized.
  """
  use ExUnit.Case, async: true

  describe "version" do
    @tag rfc: "9582#4.1",
         doc: "Barry writes version 0 by default, so the fixture overrides it explicitly."
    test "rejects a ROA whose version is not 0" do
      # ...
    end
  end
end
```

`test/test_docs_test.exs` enforces this:

- The suite fails if a test module has no `@moduledoc` (or `@moduledoc false`), if a test name is blank, or if a `doc` tag isn't a literal string.
- It also checks that the tests read from source match exactly the tests ExUnit runs, so the catalog can't silently miss one. When a single file is run, only the modules loaded for that run are compared.
- Doctests are left out of the catalog: they are documented by the function docs they come from.

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
  @moduledoc "Resource certificate profile checks (RFC 6487 §4)."
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
| `expected` | yes | `:valid`, or `{:invalid, rejects}`. Each reject gives an `object` (a path under `rsync/`, which must exist) and the `reason` a validator must reject it, and optionally the `rule` (an atom) of the certificate verdict that rejects it: a `Lumina.Chain`/`Lumina.Profile` problem rule, or for a `.crl` the CRL's rule, which makes every certificate in its directory `crl_invalid`. The M4 done test checks that the certificates found invalid are exactly those named by rejects with a rule. |
| `barry` | no | Overrides the validity period passed to Barry: `now:` and `later:`, as UTC timestamps. |
| `vrps` | if the fixture has ROAs | The VRPs a validator must output for the fixture at 2030-01-01, as `lumina vrps` writes them in CSV without the trust anchor column: `["AS64496,1.1.0.0/17,24", "AS64496,101::/16,48"]`, each once, in any order; `[]` when no ROA is valid. Every host the fixture's certificates name counts as reachable. The M7 done test checks that `lumina vrps` gives exactly these. |
| `rsync_modules` | no | Extra rsync modules on `localhost:8873`, besides `rpki` (all of `rsync/`): a map of module name to the directory under `rsync/` it serves, such as `%{"s1" => "s1"}`. `fixture.modules` gives the full set for a test daemon. |

The file is read as data. Function calls, variables and string interpolation are rejected, and nothing in it is run.

`test/fixtures_metadata_test.exs` checks every fixture folder. A fixture fails, and so does the suite, if:

- metadata is missing or blank,
- an RFC reference is invalid,
- the `id` doesn't match the folder or milestone,
- a rejected object isn't in `rsync/`,
- the fixture has a ROA but no `vrps`, or a `vrps` entry isn't `AS<n>,<prefix>,<maxLength>`, or
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

### Using a fixture in a test

```elixir
fixture = Lumina.Test.Fixture.load!("m0-minimal-valid")
fixture.tal_path     # case.tal
fixture.rsync_root   # the rsync tree, laid out by publication point
fixture.expected     # :valid, or {:invalid, rejects}
```

`load!/1` raises if the fixture doesn't exist or fails its metadata check. Shared test helpers live in `test/support/`, which is compiled only in the test environment.

`m0-minimal-valid` (TA → CA → ROA) is the positive baseline. New invalid fixtures should usually be this tree with one field overridden, so a rejection can be traced to that one change.

### Tests that run Barry

Tests tagged `:barry` run the real Barry binary. They're excluded automatically when `_tools/bin/barry` doesn't exist. CI runs them in the `barry` job with `mix test --only barry`.

### Tests that reach the live RPKI

Tests tagged `:network` fetch from the real RPKI (the M3 done test mirrors the live LACNIC repository). They depend on the Internet and take minutes, so they never run by default, in CI or locally. Run them by hand with `mix test --only network`.

## Catalog

[`doc/tests/CATALOG.md`](tests/CATALOG.md) has two parts:

- **Barry fixtures:** grouped by milestone, with each fixture's rationale, RFC references and expected outcome.
- **Unit tests:** grouped by module, with the module's `@moduledoc`, then each test's name, `describe` block, RFC references and `doc` tag.

It is generated from the fixture metadata and the test sources, so never edit it by hand:

```sh
mix lumina.test_catalog           # regenerate after adding or changing a fixture or test
mix lumina.test_catalog --check   # what CI and `mix check` run: fail if the catalog is out of date
```

The catalog doesn't record line numbers, so editing a test's body doesn't make it stale. Adding, removing or renaming a test, or changing its documentation or RFC references, does.
