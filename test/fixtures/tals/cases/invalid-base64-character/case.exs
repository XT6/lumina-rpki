%{
  id: "invalid-base64-character",
  title: "An illegal character in the base64 key",
  rationale: """
  The key is base64 (RFC 4648 section 4); "@" is outside the alphabet.
  """,
  rfc: ["8630#2.2", "4648#4"],
  expected: {:invalid, %{line: 3, rule: :bad_base64}}
}
