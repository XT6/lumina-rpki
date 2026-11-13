%{
  id: "valid-crlf",
  title: "CRLF line ends throughout",
  rationale: """
  Line breaks may be CRLF or LF. A parser that splits only on LF would
  see a stray CR at the end of every line, in URIs and in the base64
  key.
  """,
  rfc: ["8630#2.2"],
  expected: :valid
}
