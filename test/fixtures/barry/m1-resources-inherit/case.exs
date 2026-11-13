%{
  id: "m1-resources-inherit",
  title: "CA certificate that inherits all its resources",
  milestone: "M1",
  rationale: """
  A three-level tree, TA -> ca1 -> ca2, where ca2's IP address blocks (IPv4
  and IPv6) and AS numbers are all "inherit". By RFC 3779 the actual
  resources come from the issuer, ca1, and the certificate is valid.

  In M1 it checks that inherit is decoded as its own value (:inherit), not
  as an empty resource list, for both extensions. M6 reuses it for
  resource inclusion, where inherit must resolve up the chain.
  """,
  rfc: ["3779#2.2.3.5", "3779#3.2.3.3", "6487#4.8.10", "6487#4.8.11"],
  expected: :valid
}
