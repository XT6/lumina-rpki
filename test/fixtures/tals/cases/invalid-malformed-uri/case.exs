%{
  id: "invalid-malformed-uri",
  title: "A URI containing a space",
  rationale: """
  A URI must have valid RFC 3986 syntax; an unencoded space makes it
  invalid.
  """,
  rfc: ["8630#2.2", "3986#3"],
  expected: {:invalid, %{line: 1, rule: :invalid_uri}}
}
