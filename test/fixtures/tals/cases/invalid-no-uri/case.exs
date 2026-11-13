%{
  id: "invalid-no-uri",
  title: "Comments, then the blank line and key, but no URI",
  rationale: """
  The URI section has one or more URIs. Here the first non-comment line
  is already the separator, so there is no URI.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 2, rule: :no_uri}}
}
