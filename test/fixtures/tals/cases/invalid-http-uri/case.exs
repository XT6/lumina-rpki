%{
  id: "invalid-http-uri",
  title: "A plain HTTP URI",
  rationale: """
  A TA URI MUST be rsync or HTTPS. Plain HTTP offers no integrity, so it
  must be rejected even though it looks almost right.
  """,
  rfc: ["8630#2.2", "8630#4"],
  expected: {:invalid, %{line: 1, rule: :unsupported_scheme}}
}
