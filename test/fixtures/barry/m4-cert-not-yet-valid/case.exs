%{
  id: "m4-cert-not-yet-valid",
  title: "CA certificate not yet valid at validation time",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate's notBefore is 2031-01-01, after the validation time the
  tests use (2030-01-01).

  Certificate profile check (#109): validation must reject the CA
  certificate with this one reason, and accept everything else.
  """,
  rfc: ["6487#4.6", "6487#7.2", "5280#4.1.2.5"],
  expected:
    {:invalid,
     [%{object: "ta/ca1.cer", reason: "not yet valid: notBefore is after the validation time"}]}
}
