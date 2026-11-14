%{
  id: "m4-crl-issuer-mismatch",
  title: "CRL whose issuer isn't the CA's subject",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's CRL names an issuer other than ca1's subject. RFC 6487 section 5
  says the CRL issuer is the CA.

  CRL profile check (#111): validation must reject the CRL with this
  one reason, and accept everything else.
  """,
  rfc: ["6487#5", "5280#5.1.2.3"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.crl",
         reason: "the CRL issuer is not the CA's subject",
         rule: :crl_issuer_mismatch
       }
     ]}
}
