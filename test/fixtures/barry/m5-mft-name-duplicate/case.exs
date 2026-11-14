%{
  id: "m5-mft-name-duplicate",
  title: "Manifest listing the same file name twice",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: ca1.mft lists roa1.roa twice (the second entry replaces ca1.crl). RFC 9286 section 4.2.1 has one entry per file, and a name can't have two hashes.

  Manifest content checks (#132): validation must reject ca1.mft with
  this one reason. Its envelope and EE certificate are valid.
  """,
  rfc: ["9286#4.2.1", "9286#4.2.2"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "roa1.roa is listed twice",
         rule: :manifest_duplicate_name
       }
     ]}
}
