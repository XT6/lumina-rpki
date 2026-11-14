%{
  id: "m6-inherit-from-empty",
  title: "Inheriting an address family the issuer doesn't hold",
  milestone: "M6",
  rationale: """
  ca1 holds IPv4 addresses (1.0.0.0/8) and AS numbers but no IPv6; ca2 inherits both address families. RFC 3779 section 2.2.3.5 takes inherited resources from the issuer, and ca1 has no IPv6 to take, so ca2 holds no IPv6: inheriting nothing is holding nothing (D-026). Real repositories depend on this: RFC 9286 section 5.1 requires every manifest's EE certificate to inherit its resources, so under a CA without IPv6 the manifest inherits IPv6 from nothing.

  Effective resources (#153): everything validates, and ca2 holds ca1's IPv4 addresses only.
  """,
  rfc: ["3779#2.2.3.5", "9286#5.1"],
  expected: :valid
}
