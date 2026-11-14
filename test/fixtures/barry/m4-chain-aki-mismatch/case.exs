%{
  id: "m4-chain-aki-mismatch",
  title: "CA certificate whose AKI isn't the TA's key identifier",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's Authority Key Identifier isn't the TA's key identifier. RFC 6487
  section 4.8.3 defines it as the SHA-1 of the issuer's public key.

  Chain validation (#112): validation must reject this certificate with
  this one reason.
  """,
  rfc: ["6487#4.8.3", "6487#7.2"],
  expected:
    {:invalid, [%{object: "ta/ca1.cer", reason: "the AKI is not the parent's key identifier"}]}
}
