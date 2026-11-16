%{
  id: "m5-cms-version-1",
  title: "SignedData version 1",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: The SignedData version of roa1.roa is 1. RFC 6488 section 2.1.1 requires 3, and section 3 item 1.b makes a relying party check it.

  CMS profile (#129): validation must reject roa1.roa with this one
  reason. Its EE certificate is valid.
  """,
  rfc: ["6488#2.1.1", "6488#3"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "the SignedData version is 1; RFC 6488 requires 3",
         rule: :signed_data_version
       }
     ]},
  vrps: []
}
