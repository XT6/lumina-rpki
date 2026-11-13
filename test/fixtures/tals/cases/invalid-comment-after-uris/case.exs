%{
  id: "invalid-comment-after-uris",
  title: "A comment after the last URI",
  rationale: """
  Same rule as a comment between URIs, at the end of the URI section.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 2, rule: :comment_after_uris}}
}
