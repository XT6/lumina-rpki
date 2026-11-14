%{
  id: "m4-crl-number-critical",
  title: "CRL whose CRL Number is critical",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's CRL marks its CRL Number extension critical. RFC 9829 section 3.1
  has relying parties check that it is non-critical.

  CRL profile check (#111): validation must reject the CRL with this
  one reason, and accept everything else.
  """,
  rfc: ["9829#3.1"],
  expected: {:invalid, [%{object: "ca1/ca1.crl", reason: "the CRL Number is critical"}]}
}
