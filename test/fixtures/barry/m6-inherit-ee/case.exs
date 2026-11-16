%{
  id: "m6-inherit-ee",
  title: "ROA whose EE certificate inherits its addresses",
  milestone: "M6",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the EE certificate of roa1.roa uses inherit for its IP addresses. RFC 6487 section 4.8.10 allows inherit in any resource certificate, EE certificates included; the EE certificate then holds ca1's addresses (RFC 3779 section 2.2.3.5).

  Effective resources (#153): the EE certificate validates, holding ca1's addresses.

  ROA content validation (#171): RFC 9582 section 5 narrows this for ROAs: "The EE certificate's IP address delegation extension MUST NOT contain 'inherit' elements". The ROA is invalid as a whole.
  """,
  rfc: ["3779#2.2.3.5", "6487#4.8.10", "9582#5"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "the EE certificate's IP address delegation extension uses inherit",
         rule: :roa_ee_ip_inherit
       }
     ]},
  vrps: []
}
