%{
  id: "m7-roa-max-length-superfluous",
  title: "ROA with a maxLength equal to its prefix length",
  milestone: "M7",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: roa1.roa encodes a maxLength of 16 for 1.1.0.0/16. RFC 9582 section 4.3.2.2: "The maxLength element SHOULD NOT be encoded if the maximum length is equal to the prefix length", and CAs "SHOULD anticipate that future Relying Parties will become increasingly stringent". A SHOULD only warns (D-030, F-018): the ROA is valid, with the warning superfluous_max_length.

  ROA content validation (#171).
  """,
  rfc: ["9582#4.3.2.2"],
  expected: :valid
}
