%{
  id: "m4-crl-aki-mismatch",
  title: "CRL whose AKI doesn't match the issuer's SKI",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's CRL has an Authority Key Identifier that is not ca1's Subject Key
  Identifier. RFC 9829 section 3.1 requires RPs to process the AKI, and
  RFC 5280 section 5.2.1 says it identifies the CRL signer's key.

  CRL profile check (#111): validation must reject the CRL with this
  one reason, and accept everything else.
  """,
  rfc: ["9829#3.1", "5280#5.2.1", "6487#4.8.3"],
  expected: {:invalid, [%{object: "ca1/ca1.crl", reason: "the AKI is not the issuer's SKI"}]}
}
