%{
  id: "m4-cert-expired",
  title: "CA certificate already expired at validation time",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate's notAfter is 2029-01-01, before the validation time the
  tests use (2030-01-01).

  Certificate profile check (#109): validation must reject the CA
  certificate with this one reason, and accept everything else.
  """,
  rfc: ["6487#4.6", "6487#7.2", "5280#4.1.2.5"],
  expected:
    {:invalid,
     [
       %{
         object: "ta/ca1.cer",
         reason: "expired: notAfter is before the validation time",
         rule: :expired
       }
     ]}
}
