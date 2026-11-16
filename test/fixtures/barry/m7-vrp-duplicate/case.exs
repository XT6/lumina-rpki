%{
  id: "m7-vrp-duplicate",
  title: "Two ROAs stating the same VRP",
  milestone: "M7",
  rationale: """
  ca1 publishes roa1.roa and roa2.roa, both authorizing AS64496 to originate 1.1.0.0/16, each with its own EE certificate holding that prefix. Both are valid (RFC 9582 section 5). The VRP is one authorization, so the default output lists it once; collecting VRPs (#164) keeps one per ROA, each with its URI, so `lumina vrps --wide` can show both (D-033).
  """,
  rfc: ["9582#5"],
  expected: :valid,
  vrps: ["AS64496,1.1.0.0/16,16"]
}
