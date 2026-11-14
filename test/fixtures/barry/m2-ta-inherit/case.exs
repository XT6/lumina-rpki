%{
  id: "m2-ta-inherit",
  title: "Trust anchor certificate that inherits its IP resources",
  milestone: "M2",
  rationale: """
  A TA certificate whose IP Address Delegation extension uses "inherit"
  for both address families. RFC 8630 section 2.3 says the TA's INR
  extensions MUST NOT use the inherit form: a self-signed certificate has
  no issuer to inherit from. The TA, and so everything under it, must be
  rejected.

  It checks that the TA check looks at the resources and not just the key:
  the TAL key matches this certificate exactly.
  """,
  rfc: ["8630#2.3", "3779#2.2.3.5"],
  expected:
    {:invalid,
     [
       %{
         object: "ta.cer",
         reason: "IP resources are inherit; RFC 8630 section 2.3 forbids it in a TA",
         rule: :inherit_resources
       }
     ]}
}
