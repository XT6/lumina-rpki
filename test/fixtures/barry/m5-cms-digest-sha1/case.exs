%{
  id: "m5-cms-digest-sha1",
  title: "SignerInfo digest algorithm SHA-1",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: The SignerInfo digestAlgorithm of roa1.roa is SHA-1. RFC 6488 section 3 item 1.j and RFC 7935 section 2 require SHA-256.

  CMS profile (#129): validation must reject roa1.roa with this one
  reason. Its EE certificate is valid.
  """,
  rfc: ["6488#2.1.6.3", "6488#3", "7935#2"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "the SignerInfo digest algorithm is SHA-1, not SHA-256",
         rule: :digest_algorithm
       }
     ]},
  vrps: []
}
