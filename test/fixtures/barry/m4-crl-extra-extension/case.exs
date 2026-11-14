%{
  id: "m4-crl-extra-extension",
  title: "CRL with a third extension",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's CRL carries a third, non-critical extension with an unknown
  OID. RFC 9829 section 3.1 requires exactly two extensions, AKI and CRL
  Number; unlike in certificates, a non-critical one is not allowed.

  CRL profile check (#111): validation must reject the CRL with this
  one reason, and accept everything else.
  """,
  rfc: ["9829#3.1", "6487#5"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.crl",
         reason: "a CRL extension other than AKI and CRL Number",
         rule: :crl_extension
       }
     ]}
}
