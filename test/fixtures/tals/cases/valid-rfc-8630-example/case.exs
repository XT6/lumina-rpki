%{
  id: "valid-rfc-8630-example",
  title: "The RFC 8630 section 2.4 example, without the RFC's indentation",
  rationale: """
  The example TAL from RFC 8630 section 2.4, with the document's
  indentation removed. It's the reference example, and must parse with
  two comments, two URIs and a 2048-bit RSA key.
  """,
  rfc: ["8630#2.4", "8630#2.2"],
  expected: :valid
}
