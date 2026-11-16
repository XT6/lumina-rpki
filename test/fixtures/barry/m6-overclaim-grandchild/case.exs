%{
  id: "m6-overclaim-grandchild",
  title: "Overclaim deep in an otherwise valid chain",
  milestone: "M6",
  rationale: """
  ta > ca1 > ca2, and below ca2 two CAs with a ROA each: ca3 (roa1) and ca4 (roa2). One change: ca3 also claims 1.2.0.0/24, which ca1 holds but ca2, its issuer, doesn't (ca2 holds 1.1.0.0/16). Inclusion is checked against the direct issuer, so a check against the TA or any ancestor would accept it. ca3 is invalid and nothing below it is validated (roa1 is never reached); ta, ca1, ca2, ca4 and roa2 stay valid.

  Resource inclusion (#154): RFC 6487 section 7.2 point 6 requires a certificate's resources to be encompassed by its issuer's, and RFC 3779 says "Validation MUST fail when this is not the case". The whole certificate is invalid (no RFC 8360 reconsideration, #121), so nothing below it is validated.
  """,
  rfc: ["6487#7.2", "3779#2.3"],
  expected:
    {:invalid,
     [
       %{
         object: "ca2/ca3.cer",
         reason: "1.2.0.0/24 not held by the issuer",
         rule: :resources_not_encompassed
       }
     ]},
  vrps: ["AS1234,1.1.2.1/32,32", "AS1234,101:201::/32,32"]
}
