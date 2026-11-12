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

### Fixture-driven tests

Tests generated from Barry fixtures take their RFC references from each fixture's metadata rather than from `@tag`. Those references use the same format and are checked by the fixture metadata check (#7).
