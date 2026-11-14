%{
  id: "m4-chain-ca-bad-signature",
  title: "CA certificate whose signature doesn't verify with the TA's key",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's signature doesn't verify with the TA's key, as if another key had
  signed it. RFC 6487 section 7.2 points 1 and 7 make it invalid.

  Chain validation (#112): validation must reject this certificate with
  this one reason.
  """,
  rfc: ["6487#7.2", "8017#8.2.2"],
  expected:
    {:invalid,
     [
       %{
         object: "ta/ca1.cer",
         reason: "the signature doesn't verify with the issuer's key",
         rule: :bad_signature
       }
     ]}
}
