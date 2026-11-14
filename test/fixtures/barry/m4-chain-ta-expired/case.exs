%{
  id: "m4-chain-ta-expired",
  title: "TA certificate already expired at validation time",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the TA certificate's notAfter is 2029-01-01, before the validation time
  the tests use (2030-01-01). TAL checks (M2) leave dates to validation;
  RFC 6487 section 7.2 point 2 makes the TA invalid.

  Chain validation (#112): validation must reject this certificate with
  this one reason.
  """,
  rfc: ["6487#7.2", "8630#3"],
  expected:
    {:invalid, [%{object: "ta.cer", reason: "expired: notAfter is before the validation time"}]}
}
