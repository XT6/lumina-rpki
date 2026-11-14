%{
  id: "m6-overclaim-as-range",
  title: "CA certificate claiming an AS range partly outside its issuer's",
  milestone: "M6",
  rationale: """
  ta, ca1 and ca2 below it, with Barry's default resources (ca1: 1.0.0.0/8, 100::/8, AS16777216-AS33554431; ca2: 1.1.0.0/16, 101::/16, AS16842752-AS16908287), with one change: ca2's AS numbers are the range AS33554176-AS33554687, which crosses the upper end of ca1's range. Half of it is held, so a check that only compares the range's start, or asks for any overlap, would accept it. The reason names only the part outside, AS33554432-AS33554687. Barry can't write IP address ranges in certificates (only prefixes), so the partial range is an AS range; m6-overclaim-ipv4-partial is the address counterpart.

  Resource inclusion (#154): RFC 6487 section 7.2 point 6 requires a certificate's resources to be encompassed by its issuer's, and RFC 3779 says "Validation MUST fail when this is not the case". The whole certificate is invalid (no RFC 8360 reconsideration, #121), so nothing below it is validated.
  """,
  rfc: ["6487#7.2", "6487#7.1", "3779#3.3", "6487#4.8.11"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca2.cer",
         reason: "AS33554432-AS33554687 not held by the issuer",
         rule: :resources_not_encompassed
       }
     ]}
}
