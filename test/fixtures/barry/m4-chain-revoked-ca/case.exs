%{
  id: "m4-chain-revoked-ca",
  title: "One of two CA certificates revoked by the TA's CRL",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the TA's CRL lists ca1's serial (10). RFC 6487 section 7.2 point 5
  makes ca1 invalid; its sibling ca2 (serial 20) stays valid. Serials are
  set explicitly so the CRL entry doesn't depend on Barry's numbering.

  Chain validation (#112): validation must reject this certificate with
  this one reason.
  """,
  rfc: ["6487#7.2", "9829#3.2", "6487#5"],
  expected:
    {:invalid, [%{object: "ta/ca1.cer", reason: "revoked by the issuer's CRL", rule: :revoked}]}
}
