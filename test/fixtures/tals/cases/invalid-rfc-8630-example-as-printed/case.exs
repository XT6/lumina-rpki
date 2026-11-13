%{
  id: "invalid-rfc-8630-example-as-printed",
  title: "The RFC 8630 section 2.4 example, indented as printed in the RFC",
  rationale: """
  Copied verbatim from the RFC, the example keeps the document's nine-
  space indentation. The first line then doesn't start with "#", so it's
  neither a comment nor a URI. The RFC's own example isn't a valid TAL
  as printed.
  """,
  rfc: ["8630#2.4", "8630#2.2"],
  expected: {:invalid, %{line: 1, rule: :invalid_uri}}
}
