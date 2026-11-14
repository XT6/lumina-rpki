%{
  id: "m4-crl-number-negative",
  title: "CRL whose CRL Number is negative",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's CRL Number is -2^159. RFC 9829 section 3.1 has relying parties
  check that it is a non-negative integer no larger than 2^159-1.

  CRL profile check (#111): validation must reject the CRL with this
  one reason, and accept everything else.
  """,
  rfc: ["9829#3.1", "5280#5.2.3"],
  expected: {:invalid, [%{object: "ca1/ca1.crl", reason: "the CRL Number is negative"}]}
}
