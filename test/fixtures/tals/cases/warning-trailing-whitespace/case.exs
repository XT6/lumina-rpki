%{
  id: "warning-trailing-whitespace",
  title: "Trailing whitespace on a comment, a URI and a key line",
  rationale: """
  The grammar doesn't mention whitespace. By D-002, trailing whitespace
  is accepted with a warning per line, because editors add it and it
  carries no meaning. Without stripping it, the URI and the base64 would
  be wrong.
  """,
  rfc: ["8630#2.2"],
  expected:
    {:valid,
     warnings: [
       %{line: 1, rule: :trailing_whitespace},
       %{line: 2, rule: :trailing_whitespace},
       %{line: 4, rule: :trailing_whitespace}
     ]}
}
