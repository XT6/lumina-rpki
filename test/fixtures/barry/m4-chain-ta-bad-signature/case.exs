%{
  id: "m4-chain-ta-bad-signature",
  title: "TA certificate whose self-signature doesn't verify",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the TA certificate's signature doesn't verify with its own key, which the
  TAL names. RFC 6487 section 7.2 point 1 and RFC 8630 section 3 make it
  invalid, and nothing below it is validated.

  Chain validation (#112): validation must reject this certificate with
  this one reason.
  """,
  rfc: ["6487#7.2", "8630#3", "7935#2"],
  expected:
    {:invalid,
     [%{object: "ta.cer", reason: "the self-signature doesn't verify", rule: :bad_signature}]}
}
