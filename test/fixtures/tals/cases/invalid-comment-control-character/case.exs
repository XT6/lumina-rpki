%{
  id: "invalid-comment-control-character",
  title: "A control character in a comment",
  rationale: """
  Comment text must conform to RFC 5198 section 2, which excludes
  control characters such as BEL (0x07). RFC 5198 isn't in the library,
  so this follows RFC 8630's reference to it.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 1, rule: :invalid_comment_text}}
}
