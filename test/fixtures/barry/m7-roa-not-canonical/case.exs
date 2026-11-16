%{
  id: "m7-roa-not-canonical",
  title: "ROA whose prefixes are not in canonical order",
  milestone: "M7",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: roa1.roa lists 1.1.128.0/24 before 1.1.0.0/24. RFC 9582 section 4.3.3 says ipAddrBlocks SHOULD be in canonical form, sorted by the comparator of section 4.3.3.1. A SHOULD only warns (D-030, F-018): the ROA is valid, with the warning not_canonical_order.

  ROA content validation (#171).
  """,
  rfc: ["9582#4.3.3", "9582#4.3.3.1"],
  expected: :valid,
  vrps: ["AS1234,1.1.0.0/24,24", "AS1234,1.1.128.0/24,24", "AS1234,101::/16,16"]
}
