%{
  id: "m0-minimal-valid",
  title: "Minimal valid repository: TA, one CA, one ROA",
  milestone: "M0",
  rationale: """
  The smallest repository that exercises a full chain: a trust anchor that
  certifies one CA, which issues one ROA. Each publication point has the CRL
  and manifest Barry generates. Only the TA's serial number is overridden
  (Barry gives it 0, F-029), so every object is correct.

  In M0 it proves the fixture pipeline works end to end: descriptor,
  generation, metadata check, catalog and test helper. In later milestones
  it is the positive baseline: every stage of the validator must accept it
  and produce exactly one VRP. Invalid fixtures should differ from it in
  one field, so a rejection can be traced to that one change.
  """,
  rfc: ["6481#2", "8630#2.2", "6487#4", "9286#4", "9582#4"],
  expected: :valid
}
