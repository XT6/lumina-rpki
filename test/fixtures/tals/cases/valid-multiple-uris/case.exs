%{
  id: "valid-multiple-uris",
  title: "Two TA URIs, rsync then HTTPS",
  rationale: """
  The URI section can hold several URIs, which must be kept in TAL order
  (the preference order is a separate decision, D-003).
  """,
  rfc: ["8630#2.2", "8630#3"],
  expected: :valid
}
