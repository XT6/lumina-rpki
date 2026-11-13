%{
  id: "invalid-empty-key",
  title: "URIs and the blank line, but no key",
  rationale: """
  The key section is required. The problem is found at the end of the
  file, line 3.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 3, rule: :empty_key}}
}
