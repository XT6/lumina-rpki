%{
  id: "m5-pp-hash-mismatch",
  title: "Manifest hash that doesn't match the file",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: ca1.mft lists roa1.roa with a hash that isn't the SHA-256 of the published file. RFC 9286 section 6.5: a hash mismatch is a failed fetch.

  Publication point processing (#133): ca1's publication point must fail
  with exactly these reasons.
  """,
  rfc: ["9286#6.5", "9286#6.6"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the hash of roa1.roa doesn't match the manifest",
         rule: :hash_mismatch
       }
     ]}
}
