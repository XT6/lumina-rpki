%{
  id: "m5-cms-bad-signature",
  title: "Signed object whose signature doesn't verify",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the SignerInfo
  signature of roa1.roa is replaced by 256 octets that aren't a signature
  of its signed attributes. RFC 6488 section 3 item 2 requires the EE
  certificate's key to verify it.

  CMS signature (#130): validation must reject roa1.roa with this one
  reason. Its EE certificate and the rest of its envelope are valid.
  """,
  rfc: ["6488#3", "5652#5.4", "8017#8.2.2"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "the signature doesn't verify with the EE certificate's key",
         rule: :bad_signature
       }
     ]},
  vrps: []
}
