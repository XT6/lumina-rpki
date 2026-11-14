%{
  id: "m4-chain-issuer-mismatch",
  title: "CA certificate whose issuer isn't the TA's subject",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1 names an issuer other than the TA's subject, though the TA signs it.
  RFC 6487 section 7.2 point 1 requires the subject of each certificate to
  be the issuer of the next.

  Chain validation (#112): validation must reject this certificate with
  this one reason.
  """,
  rfc: ["6487#7.2", "5280#6.1.3"],
  expected:
    {:invalid,
     [
       %{
         object: "ta/ca1.cer",
         reason: "the issuer is not the parent's subject",
         rule: :issuer_mismatch
       }
     ]}
}
