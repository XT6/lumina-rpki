%{
  id: "invalid-key-not-der",
  title: "A key that decodes but isn't DER",
  rationale: """
  Valid base64 of a BER encoding with an indefinite length: it isn't
  DER, which the subjectPublicKeyInfo must be.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 3, rule: :not_der}}
}
