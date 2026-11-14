%{
  id: "m4-cert-ca-no-basic-constraints",
  title: "CA certificate without Basic Constraints",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate has no Basic Constraints extension. RFC 6487
  section 4.8.1 requires it, critical with cA set, in every CA certificate.

  Certificate profile check (#110): validation must reject the CA
  certificate with this one reason, and accept everything else.
  """,
  rfc: ["6487#4.8.1"],
  expected: {:invalid, [%{object: "ta/ca1.cer", reason: "basic_constraints is missing"}]}
}
