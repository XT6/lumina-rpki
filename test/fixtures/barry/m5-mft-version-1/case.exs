%{
  id: "m5-mft-version-1",
  title: "Manifest version 1",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the version of ca1.mft is 1. RFC 9286 section 4.2.1 requires 0, and section 4.4 item 2 makes a relying party check it.

  Manifest content checks (#132): validation must reject ca1.mft with
  this one reason. Its envelope and EE certificate are valid.
  """,
  rfc: ["9286#4.2.1", "9286#4.4"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the manifest version is 1; RFC 9286 requires 0",
         rule: :manifest_version
       }
     ]},
  vrps: []
}
