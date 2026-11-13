%{
  id: "invalid-two-blank-lines",
  title: "Two blank lines before the key",
  rationale: """
  The grammar has exactly one line break between the URIs and the key.
  By D-002 an extra blank line is an error.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 3, rule: :extra_blank_line}}
}
