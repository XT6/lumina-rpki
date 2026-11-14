%{
  id: "m4-chain-crl-missing",
  title: "CA certificate whose CRLDP names a CRL that isn't published",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's CRL Distribution Point names ta/missing.crl, which isn't
  published. RFC 6487 section 7.2 point 5 (as updated by RFC 9829 section
  3.2) needs that CRL to decide revocation, so ca1 is invalid (D-015).

  Chain validation (#112): validation must reject this certificate with
  this one reason.
  """,
  rfc: ["6487#7.2", "9829#3.2", "6487#4.8.6"],
  expected: {:invalid, [%{object: "ta/ca1.cer", reason: "the CRL named by the CRLDP is missing"}]}
}
