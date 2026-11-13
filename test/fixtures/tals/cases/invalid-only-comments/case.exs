%{
  id: "invalid-only-comments",
  title: "Only comments",
  rationale: """
  Comments alone are not a TAL: the URI section requires at least one
  URI. The problem is found at the end of the file, line 3.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 3, rule: :no_uri}}
}
