%{
  id: "m4-chain-ta-expired",
  title: "TA certificate already expired at validation time",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the TA certificate's notAfter is
  2026-06-01, before every validation time the tests use (2026-11-13 for
  retrieval and sync, 2030-01-01 for chain validation). TAL checks (M2)
  leave dates to validation; RFC 6487 section 7.2 point 2 makes the TA
  invalid, so it is never accepted (#113).

  Chain validation (#112): validation must reject this certificate with
  this one reason.
  """,
  rfc: ["6487#7.2", "8630#3"],
  expected:
    {:invalid,
     [
       %{
         object: "ta.cer",
         reason: "expired: notAfter is before the validation time",
         rule: :expired
       }
     ]}
}
