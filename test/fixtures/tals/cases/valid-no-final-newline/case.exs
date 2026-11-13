%{
  id: "valid-no-final-newline",
  title: "No line break after the key",
  rationale: """
  The grammar ends with the key and doesn't require a final line break.
  A parser must not demand one.
  """,
  rfc: ["8630#2.2"],
  expected: :valid
}
