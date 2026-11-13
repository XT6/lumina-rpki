%{
  id: "m1-cert-unknown-critical-extension",
  title: "CA certificate with an unrecognized critical extension",
  milestone: "M1",
  rationale: """
  The baseline tree with one change: the CA certificate carries an extra,
  critical extension with an OID no validator knows (1.3.6.1.4.1.99999.1).
  RFC 6487 section 4.8 says a certificate-using system MUST reject a
  certificate with a critical extension it does not recognize.

  The extension is critical on purpose: for an unknown non-critical
  extension the RFCs allow either ignoring or rejecting it (F-015 in
  doc/rfc-findings.md), so that case is left for M4.

  In M1 it checks that unknown extensions are kept, with their criticality,
  instead of being dropped or failing the decode.
  """,
  rfc: ["6487#4.8", "5280#4.2"],
  expected:
    {:invalid,
     [
       %{
         object: "ta/ca1.cer",
         reason: "unrecognized critical extension 1.3.6.1.4.1.99999.1; RFC 6487 section 4.8"
       }
     ]}
}
