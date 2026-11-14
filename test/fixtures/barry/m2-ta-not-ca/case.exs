%{
  id: "m2-ta-not-ca",
  title: "Trust anchor certificate that is not a CA (cA = false)",
  milestone: "M2",
  rationale: """
  A TA certificate whose Basic Constraints say cA = false. RFC 8630
  section 2.3 requires the TA to be a self-signed CA certificate; a
  certificate that isn't a CA can't issue the rest of the tree, whatever
  key it carries.

  The key matches the TAL exactly, so only the CA check catches it.
  """,
  rfc: ["8630#2.3", "6487#4.8.1"],
  expected:
    {:invalid,
     [
       %{
         object: "ta.cer",
         reason: "Basic Constraints cA is false; RFC 8630 section 2.3 requires a CA certificate",
         rule: :not_ca
       }
     ]}
}
