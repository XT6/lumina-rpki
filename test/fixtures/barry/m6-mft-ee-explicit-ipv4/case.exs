%{
  id: "m6-mft-ee-explicit-ipv4",
  title: "Manifest whose EE certificate lists IPv4 explicitly and leaves IPv6 out",
  milestone: "M6",
  rationale: """
  The baseline tree (m0-minimal-valid) with ca1's manifest declared in the tree and its EE certificate changed: IPv4 is an explicit 1.2.0.0/16, IPv6 is absent, and AS numbers are inherited. RFC 9286 section 5.1 wants the 'inherit' attribute "rather than an explicit description of a resource set", so IPv4 gets the manifest_ee_resources_not_inherit warning, naming IPv4 only. An absent kind isn't an explicit description and doesn't warn (D-029); inherited AS numbers conform.

  Manifest EE inherit check (#157, D-029): a warning only, so the point is accepted and everything validates.
  """,
  rfc: ["9286#5.1"],
  expected: :valid
}
