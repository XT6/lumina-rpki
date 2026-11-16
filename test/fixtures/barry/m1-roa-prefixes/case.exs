%{
  id: "m1-roa-prefixes",
  title: "ROA with IPv4 and IPv6 prefixes, with and without maxLength",
  milestone: "M1",
  rationale: """
  A valid ROA for AS64496 with three prefixes: 1.1.0.0/17 with maxLength
  24, 1.1.128.0/24 without maxLength, and 0101::/16 with maxLength 48. All
  lie inside the EE certificate's resources and are in canonical order.

  It checks that ROA decoding handles both address families, keeps an
  absent maxLength distinct from a present one, and turns each address
  into the right VRP: the maximum length is the prefix length when
  maxLength is absent. M7 reuses it as a positive case producing exactly
  these three VRPs.
  """,
  rfc: ["9582#4.3", "9582#4.3.2.1", "9582#4.3.2.2", "9582#4.3.3"],
  expected: :valid,
  vrps: ["AS64496,1.1.0.0/17,24", "AS64496,1.1.128.0/24,24", "AS64496,101::/16,48"]
}
