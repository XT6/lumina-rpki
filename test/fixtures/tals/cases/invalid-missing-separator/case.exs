%{
  id: "invalid-missing-separator",
  title: "No blank line between the URIs and the key",
  rationale: """
  Without the separating line break, the first key line sits in the URI
  section. A parser must recognize it as the key and report the missing
  separator, rather than an odd URI.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 2, rule: :missing_separator}}
}
