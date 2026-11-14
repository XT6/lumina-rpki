%{
  id: "m5-mft-name-unregistered-extension",
  title: "Manifest file name with an unregistered extension",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: ca1.mft lists its ROA as roa1.xyz. RFC 9286 section 4.2.2 requires an extension from the IANA "RPKI Repository Name Schemes" registry, which has no .xyz.

  Manifest content checks (#132): validation must reject ca1.mft with
  this one reason. Its envelope and EE certificate are valid.
  """,
  rfc: ["9286#4.2.2", "6481#7.2"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the extension .xyz is not in the RPKI Repository Name Schemes registry",
         rule: :manifest_file_extension
       }
     ]}
}
