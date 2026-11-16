%{
  id: "m6-mft-ee-inherit",
  title: "Manifest whose EE certificate inherits every resource kind",
  milestone: "M6",
  rationale: """
  The baseline tree (m0-minimal-valid) with ca1's manifest declared in the tree, so that its EE certificate can use inherit for IPv4, IPv6 and AS numbers, as RFC 9286 section 5.1 requires ("MUST describe its Internet Number Resources (INRs) using the 'inherit' attribute ... RPs are required to verify this"). ca1.mft gets no manifest_ee_resources_not_inherit warning. The TA's manifest isn't declared, so Barry gives its EE certificate explicit resources and it keeps the warning: both cases in one repository.

  Manifest EE inherit check (#157, D-029): everything validates; only ta.mft warns.
  """,
  rfc: ["9286#5.1", "3779#2.2.3.5", "3779#3.2.3.3"],
  expected: :valid,
  vrps: ["AS1234,1.3.0.0/16,16", "AS1234,103::/16,16"]
}
