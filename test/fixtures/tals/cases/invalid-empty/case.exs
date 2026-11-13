%{
  id: "invalid-empty",
  title: "Empty file",
  rationale: """
  A TAL must contain at least one URI and a key. An empty file must be
  rejected, not treated as an empty TAL.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 1, rule: :empty}}
}
