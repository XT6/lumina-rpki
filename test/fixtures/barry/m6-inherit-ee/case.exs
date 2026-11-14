%{
  id: "m6-inherit-ee",
  title: "ROA whose EE certificate inherits its addresses",
  milestone: "M6",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the EE certificate of roa1.roa uses inherit for its IP addresses. RFC 6487 section 4.8.10 allows inherit in any resource certificate, EE certificates included; the EE certificate then holds ca1's addresses (RFC 3779 section 2.2.3.5).

  Effective resources (#153): everything validates.
  """,
  rfc: ["3779#2.2.3.5", "6487#4.8.10"],
  expected: :valid
}
