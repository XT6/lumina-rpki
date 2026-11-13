%{
  id: "invalid-blank-line-after-key",
  title: "A blank line after the key",
  rationale: """
  After the key the file ends; a further empty line is outside the
  grammar. By D-002 it is an error, not something to skip silently.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 4, rule: :extra_blank_line}}
}
