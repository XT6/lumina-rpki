%{
  id: "invalid-relative-uri",
  title: "A relative reference instead of a URI",
  rationale: """
  A TA URI must be absolute, with a scheme; a path on its own isn't a TA
  URI.
  """,
  rfc: ["8630#2.2", "3986#4.2"],
  expected: {:invalid, %{line: 1, rule: :invalid_uri}}
}
