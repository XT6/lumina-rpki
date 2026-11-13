%{
  id: "valid-comments",
  title: "Comment section before the URIs",
  rationale: """
  The optional comment section: lines starting with "#" before the URIs,
  with non-ASCII UTF-8 text. A parser must skip them and keep them as
  comments.
  """,
  rfc: ["8630#2.2"],
  expected: :valid
}
