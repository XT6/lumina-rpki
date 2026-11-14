%{
  id: "m6-encompass-equal",
  title: "CA certificate holding exactly its issuer's resources",
  milestone: "M6",
  rationale: """
  ta, ca1 and ca2 below it, with one change: ca2 claims exactly ca1's resources (1.0.0.0/8, 100::/8, AS16777216-AS33554431) instead of a part of them. Encompassing includes equality (RFC 6487 section 7.1), so a strict-subset check would wrongly reject ca2.

  Resource inclusion (#154): everything validates.
  """,
  rfc: ["6487#7.1", "6487#7.2", "3779#2.3", "3779#3.3"],
  expected: :valid
}
