%{
  id: "m4-cert-key-usage-not-critical",
  title: "CA certificate whose Key Usage is not critical",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate's Key Usage extension is not marked critical. RFC
  6487 section 4.8.4 requires it to be.

  Certificate profile check (#110): validation must reject the CA
  certificate with this one reason, and accept everything else.
  """,
  rfc: ["6487#4.8.4"],
  expected:
    {:invalid,
     [%{object: "ta/ca1.cer", reason: "key_usage must be critical", rule: :not_critical}]}
}
