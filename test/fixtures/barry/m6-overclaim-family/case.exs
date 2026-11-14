%{
  id: "m6-overclaim-family",
  title: "CA certificate claiming an address family its issuer doesn't have",
  milestone: "M6",
  rationale: """
  ta, ca1 and ca2 below it, with two changes: ca1 holds only IPv4 (1.0.0.0/8), and ca2 claims 1.1.0.0/16 and 101::/16. ca1 has no IPv6 at all, so ca2's IPv6 prefix isn't encompassed, however small. A check that compares only the families both certificates list would miss it. Barry copies ca1's override to the EE certificate of ca1's manifest, which stays within ca1's resources.

  Resource inclusion (#154): RFC 6487 section 7.2 point 6 requires a certificate's resources to be encompassed by its issuer's, and RFC 3779 says "Validation MUST fail when this is not the case". The whole certificate is invalid (no RFC 8360 reconsideration, #121), so nothing below it is validated.
  """,
  rfc: ["6487#7.2", "6487#7.1", "3779#2.3", "6487#4.8.10"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca2.cer",
         reason: "101::/16 not held by the issuer",
         rule: :resources_not_encompassed
       }
     ]}
}
