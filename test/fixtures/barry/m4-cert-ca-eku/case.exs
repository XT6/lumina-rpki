%{
  id: "m4-cert-ca-eku",
  title: "CA certificate with an Extended Key Usage",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate carries an Extended Key Usage extension. RFC 6487
  section 4.8.5 says it MUST NOT appear in any CA certificate.

  Certificate profile check (#110): validation must reject the CA
  certificate with this one reason, and accept everything else.
  """,
  rfc: ["6487#4.8.5"],
  expected:
    {:invalid,
     [
       %{
         object: "ta/ca1.cer",
         reason: "extended_key_usage must not be present",
         rule: :extension_present
       }
     ]}
}
