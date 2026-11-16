%{
  id: "m7-shared-point",
  title: "Two CAs sharing one publication point directory, each with its own manifest",
  milestone: "M7",
  rationale: """
  The TA certifies ca1 and ca2, and both name rsync://localhost:8873/rpki/ca1 as their caRepository. The directory holds two manifests, ca1.mft and ca2.mft, each listing only its own CA's products: ca1's CRL and roa1.roa, ca2's CRL and roa2.roa (RFC 9286 section 1: "each manifest describes only the collection of published products of its associated CA instance"; RFC 6481 section 2.2 lets related CAs share a publication point). A walk that marks the directory visited after ca1 skips ca2 as a duplicate and loses roa2.roa's VRPs, as Lumina did with JPNIC and many APNIC members in the M7 done test's live run (#195). Each CA's point is its manifest, so both are walked and validated.
  """,
  rfc: ["9286#1", "6481#2.2", "6481#5"],
  expected: :valid,
  vrps: [
    "AS1234,1.1.0.0/16,16",
    "AS1234,2.1.0.0/16,16",
    "AS1234,101::/16,16",
    "AS1234,201::/16,16"
  ]
}
