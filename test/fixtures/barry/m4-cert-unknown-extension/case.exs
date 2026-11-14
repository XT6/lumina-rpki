%{
  id: "m4-cert-unknown-extension",
  title: "CA certificate with an unknown non-critical extension",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate carries an extension with an unknown OID
  (1.3.6.1.4.1.99999.2), marked non-critical. RFC 6487 section 4.8 lets
  an RP ignore it; D-013 accepts it with a warning naming the OID (#42).
  The counterpart of m1-cert-unknown-critical-extension.

  Certificate profile check (#110): the repository is valid; the
  CA certificate gets one warning.
  """,
  rfc: ["6487#4.8", "5280#4.2"],
  expected: :valid
}
