%{
  id: "m5-cms-signature-algorithm",
  title: "SignerInfo signature algorithm sha1WithRSAEncryption",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: The SignerInfo signatureAlgorithm of roa1.roa is sha1WithRSAEncryption. RFC 7935 section 2 lets relying parties accept rsaEncryption or sha256WithRSAEncryption only (RFC 6488 section 3 item 1.k).

  CMS profile (#129): validation must reject roa1.roa with this one
  reason. Its EE certificate is valid.
  """,
  rfc: ["6488#2.1.6.5", "6488#3", "7935#2"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "the signature algorithm is sha1WithRSAEncryption",
         rule: :signature_algorithm
       }
     ]}
}
