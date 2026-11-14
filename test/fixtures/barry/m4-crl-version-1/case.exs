%{
  id: "m4-crl-version-1",
  title: "CRL with version 1",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's CRL is version 1. RFC 6487 section 5 requires version 2 CRLs, and
  relying parties need not process v1.

  CRL profile check (#111): validation must reject the CRL with this
  one reason, and accept everything else.
  """,
  rfc: ["6487#5", "5280#5.1.2.1"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.crl",
         reason: "the CRL is version 1; RPKI CRLs are v2",
         rule: :crl_version
       }
     ]}
}
