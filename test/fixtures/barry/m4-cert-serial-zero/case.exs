%{
  id: "m4-cert-serial-zero",
  title: "CA certificate with serial number 0",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate's serial number is 0. RFC 6487 section 4.2 and RFC
  5280 section 4.1.2.2 require a positive integer.

  Certificate profile check (#109): validation must reject the CA
  certificate with this one reason, and accept everything else.
  """,
  rfc: ["6487#4.2", "5280#4.1.2.2"],
  expected:
    {:invalid, [%{object: "ta/ca1.cer", reason: "serial number is 0; it must be positive"}]}
}
