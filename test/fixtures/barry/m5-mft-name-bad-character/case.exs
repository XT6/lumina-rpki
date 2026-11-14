%{
  id: "m5-mft-name-bad-character",
  title: "Manifest file name with a character outside the allowed set",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: ca1.mft lists its ROA as roa+1.roa. RFC 9286 section 4.2.2 allows only a-z, A-Z, 0-9, hyphen and underscore before the dot.

  Manifest content checks (#132): validation must reject ca1.mft with
  this one reason. Its envelope and EE certificate are valid.
  """,
  rfc: ["9286#4.2.2"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the file name roa+1.roa has a character outside a-z A-Z 0-9 - _",
         rule: :manifest_file_name
       }
     ]}
}
