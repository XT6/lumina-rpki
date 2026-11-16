%{
  id: "m6-overclaim-roa-ee",
  title: "ROA whose EE certificate claims addresses its CA doesn't hold",
  milestone: "M6",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the EE certificate of roa1.roa also claims 2.0.0.0/16, outside ca1's 1.0.0.0/8. RFC 6488 section 3 item 3 validates a signed object's EE certificate per RFC 6487, so section 7.2 point 6 applies to it as to a CA certificate, and the ROA is invalid. Whether the ROA's prefixes are within the EE certificate's resources (RFC 9582) is M7; here they are.

  Resource inclusion (#154).
  """,
  rfc: ["6487#7.2", "6488#3", "3779#2.3"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "2.0.0.0/16 not held by the issuer",
         rule: :resources_not_encompassed
       }
     ]},
  vrps: []
}
