%{
  id: "m5-mft-hash-sha1",
  title: "Manifest fileHashAlg SHA-1",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the fileHashAlg of ca1.mft is SHA-1. RFC 9286 section 4.2.1 requires the algorithm of RFC 7935, which is SHA-256 (section 2).

  Manifest content checks (#132): validation must reject ca1.mft with
  this one reason. Its envelope and EE certificate are valid.
  """,
  rfc: ["9286#4.2.1", "7935#2"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the file hash algorithm is SHA-1, not SHA-256",
         rule: :manifest_hash_algorithm
       }
     ]},
  vrps: []
}
