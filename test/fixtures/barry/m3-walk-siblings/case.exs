%{
  id: "m3-walk-siblings",
  title: "Eight sibling CAs, each with its own publication point on one host",
  milestone: "M3",
  rationale: """
  The TA certifies eight CAs, each publishing in its own directory beside
  the TA's, so no fetched directory covers another: each needs its own
  rsync run. This is how registro.br publishes under LACNIC, with
  thousands of member CAs (#85). The walk fetches them concurrently, at
  most a fixed number at once per host (D-011).
  """,
  rfc: ["6481#5"],
  expected: :valid
}
