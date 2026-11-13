%{
  id: "invalid-key-not-spki",
  title: "A key that is DER but not a SubjectPublicKeyInfo",
  rationale: """
  Valid base64 of a valid DER INTEGER: well formed, but not a
  subjectPublicKeyInfo.
  """,
  rfc: ["8630#2.2", "5280#4.1.2.7"],
  expected: {:invalid, %{line: 3, rule: :not_spki}}
}
