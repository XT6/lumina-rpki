%{
  id: "invalid-comment-between-uris",
  title: "A comment between the URIs",
  rationale: """
  Comments are only allowed in the comment section, before the URIs. By
  D-002 a comment among the URIs is an error.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 2, rule: :comment_after_uris}}
}
