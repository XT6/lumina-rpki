%{
  id: "m4-chain-crl-missing",
  title: "CA certificate whose CRLDP names a CRL that isn't published",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CRL Distribution Point of the
  TA's children, ca1 and the EE certificate of ta.mft, names
  ta/missing.crl, which isn't published. RFC 6487 section 7.2 point 5 (as updated by RFC 9829 section
  3.2) needs that CRL to decide revocation, so both are invalid (D-015).

  Chain validation (#112): validation must reject both certificates with
  this one reason. Since manifests decide publication points (#134), the
  invalid ta.mft fails the TA's point (RFC 9286 §6.2), and its CRL isn't
  on the manifest either (§6), so ca1 is never reached.
  """,
  rfc: ["6487#7.2", "9829#3.2", "6487#4.8.6", "9286#6.2"],
  expected:
    {:invalid,
     [
       %{object: "ta/ca1.cer", reason: "the CRL named by the CRLDP is missing"},
       %{
         object: "ta/ta.mft",
         reason: "the CRL named by the CRLDP is missing",
         rule: :crl_missing
       },
       %{
         object: "ta/ta.mft",
         reason: "the CRL missing.crl is not on the manifest",
         rule: :crl_not_listed
       }
     ]}
}
