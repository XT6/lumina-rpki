%{
  id: "m5-mft-dates-reversed",
  title: "Manifest thisUpdate after nextUpdate",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the thisUpdate of ca1.mft (2027-01-01) is after its nextUpdate (2026-06-01). RFC 9286 section 4.4 item 3 requires thisUpdate to precede nextUpdate.

  Manifest content checks (#132): validation must reject ca1.mft with
  this one reason. Its envelope and EE certificate are valid.
  """,
  rfc: ["9286#4.2.1", "9286#4.4"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "thisUpdate is not before nextUpdate",
         rule: :manifest_dates
       }
     ]},
  vrps: []
}
