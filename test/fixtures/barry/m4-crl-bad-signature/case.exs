%{
  id: "m4-crl-bad-signature",
  title: "CRL with a signature that doesn't verify",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's CRL carries a signature that doesn't verify with ca1's key. RFC
  6487 section 7.2 needs a valid CRL to decide revocation.

  CRL profile check (#111): validation must reject the CRL with this
  one reason, and accept everything else.
  """,
  rfc: ["6487#7.2", "8017#8.2.2", "7935#2"],
  expected:
    {:invalid,
     [%{object: "ca1/ca1.crl", reason: "the CRL signature doesn't verify", rule: :bad_signature}]}
}
