%{
  id: "valid-https-only",
  title: "A single HTTPS URI",
  rationale: """
  A TA URI may be HTTPS rather than rsync; a TAL need not contain an
  rsync URI at all.
  """,
  rfc: ["8630#2.2", "8630#4"],
  expected: :valid
}
