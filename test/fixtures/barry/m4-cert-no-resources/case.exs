%{
  id: "m4-cert-no-resources",
  title: "CA certificate with neither IP nor AS resources",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate has neither an IP Resources nor an AS Resources
  extension. RFC 6487 sections 4.8.10 and 4.8.11 require at least one.

  Certificate profile check (#110): validation must reject the CA
  certificate with this one reason, and accept everything else.
  """,
  rfc: ["6487#4.8.10", "6487#4.8.11"],
  expected:
    {:invalid,
     [
       %{
         object: "ta/ca1.cer",
         reason: "neither IP nor AS resources are present",
         rule: :no_resources
       }
     ]}
}
