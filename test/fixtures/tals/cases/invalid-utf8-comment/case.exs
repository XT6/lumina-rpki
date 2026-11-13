%{
  id: "invalid-utf8-comment",
  title: "A comment that isn't valid UTF-8",
  rationale: """
  Comment text must be UTF-8. The Latin-1 byte 0xE9 on its own is
  invalid UTF-8.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 1, rule: :invalid_utf8}}
}
