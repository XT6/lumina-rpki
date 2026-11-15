%{
  id: "m6-overclaim-ipv4",
  title: "CA certificate claiming an IPv4 prefix its issuer doesn't hold",
  milestone: "M6",
  rationale: """
  ta, ca1 and ca2 below it, with Barry's default resources (ca1: 1.0.0.0/8, 100::/8, AS16777216-AS33554431; ca2: 1.1.0.0/16, 101::/16, AS16842752-AS16908287), with one change: ca2 also claims 2.0.0.0/16, outside ca1's IPv4 space. ca2's other resources are within ca1's, so the reason names only that prefix.

  Resource inclusion (#154): RFC 6487 section 7.2 point 6 requires a certificate's resources to be encompassed by its issuer's, and RFC 3779 says "Validation MUST fail when this is not the case". The whole certificate is invalid (no RFC 8360 reconsideration, #121), so nothing below it is validated.
  """,
  rfc: ["6487#7.2", "6487#7.1", "3779#2.3", "6487#4.8.10"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca2.cer",
         reason: "2.0.0.0/16 not held by the issuer",
         rule: :resources_not_encompassed
       }
     ]}
}
