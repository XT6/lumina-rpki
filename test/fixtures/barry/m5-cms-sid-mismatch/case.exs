%{
  id: "m5-cms-sid-mismatch",
  title: "Signer SKI that isn't the EE certificate's",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: The sid of roa1.roa names a key identifier other than the EE certificate's SKI. RFC 6488 section 3 item 1.c requires them to match.

  CMS profile (#129): validation must reject roa1.roa with this one
  reason. Its EE certificate is valid.
  """,
  rfc: ["6488#2.1.6.2", "6488#3"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "the sid is not the EE certificate's SKI",
         rule: :sid_mismatch
       }
     ]},
  vrps: []
}
