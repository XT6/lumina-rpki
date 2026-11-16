%{
  id: "m7-roa-max-length-below-prefix",
  title: "ROA whose maxLength is below its prefix length",
  milestone: "M7",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: roa1.roa gives 1.1.0.0/16 a maxLength of 12. RFC 9582 section 4.3.2.2: maxLength MUST be "an integer greater than or equal to the length of the accompanying prefix". The ROA decodes (only a maxLength above the address width fails at decoding, F-012), and section 5 makes it invalid as a whole.

  ROA content validation (#171).
  """,
  rfc: ["9582#4.3.2.2", "9582#5"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "1.1.0.0/16: maxLength 12 is outside 16..32",
         rule: :max_length_out_of_range
       }
     ]},
  vrps: []
}
