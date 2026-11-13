%{
  id: "valid-minimal",
  title: "One rsync URI and the key on one line",
  rationale: """
  The smallest TAL the grammar allows: no comments, one TA URI, the
  separating blank line, and the base64 key on a single line. A parser
  must accept it.
  """,
  rfc: ["8630#2.2"],
  expected: :valid
}
