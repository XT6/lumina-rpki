%{
  id: "m5-pp-manifest-revoked",
  title: "Manifest whose EE certificate is revoked by the CA's CRL",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: ca1's CRL revokes the EE certificate of ca1.mft (serial 77). RFC 9286 section 6: a revoked current manifest is a serious CA error and the fetch fails; the manifest is also invalid (RFC 6488 section 3 item 3).

  Publication point processing (#133): ca1's publication point must fail
  with exactly these reasons.
  """,
  rfc: ["9286#6", "9286#6.2", "6488#3"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the manifest's EE certificate is revoked",
         rule: :revoked
       }
     ]},
  vrps: []
}
