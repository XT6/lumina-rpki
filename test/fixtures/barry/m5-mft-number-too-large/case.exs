%{
  id: "m5-mft-number-too-large",
  title: "Manifest number of 21 octets",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the manifestNumber of ca1.mft is 2^160, 21 octets. RFC 9286 section 4.2.1 says issuers MUST NOT use values longer than 20 octets.

  Manifest content checks (#132): validation must reject ca1.mft with
  this one reason. Its envelope and EE certificate are valid.
  """,
  rfc: ["9286#4.2.1"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the manifest number is longer than 20 octets",
         rule: :manifest_number_range
       }
     ]}
}
