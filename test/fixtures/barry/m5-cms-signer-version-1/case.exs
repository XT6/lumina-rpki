%{
  id: "m5-cms-signer-version-1",
  title: "SignerInfo version 1",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: The SignerInfo version of roa1.roa is 1. RFC 6488 section 2.1.6.1 requires 3 (the version that goes with a subjectKeyIdentifier sid), checked by section 3 item 1.e.

  CMS profile (#129): validation must reject roa1.roa with this one
  reason. Its EE certificate is valid.
  """,
  rfc: ["6488#2.1.6.1", "6488#3"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "the SignerInfo version is 1; RFC 6488 requires 3",
         rule: :signer_version
       }
     ]}
}
