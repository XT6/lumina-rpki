%{
  id: "m4-cert-inner-signature-algorithm",
  title: "CA certificate whose inner signature algorithm differs from the outer one",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the signature algorithm inside the CA certificate's tbsCertificate is
  sha384WithRSAEncryption, while the outer signatureAlgorithm (and the
  signature) are sha256WithRSAEncryption. RFC 5280 section 4.1.1.2 requires
  the two to be the same, and RFC 7935 section 2 allows only
  sha256WithRSAEncryption.

  Certificate profile check (#109): validation must reject the CA
  certificate with this one reason, and accept everything else.
  """,
  rfc: ["6487#4.3", "5280#4.1.1.2", "7935#2"],
  expected:
    {:invalid,
     [
       %{
         object: "ta/ca1.cer",
         reason: "the tbsCertificate signature algorithm is not the outer one",
         rule: :signature_algorithm_mismatch
       }
     ]}
}
