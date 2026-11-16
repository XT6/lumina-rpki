%{
  id: "m3-walk-unreachable",
  title: "A child CA whose publication point is on an unreachable host",
  milestone: "M3",
  rationale: """
  The TA certifies two CAs. ca1's caRepository is on unreachable.invalid,
  a name that can never resolve (RFC 6761 reserves .invalid); ca2 is
  normal. The walk must report the failed fetch, keep any last good copy
  of ca1's publication point (RFC 8897 §7), and still mirror ca2. ca1's
  files are generated under rsync/unreachable/ so a test can first serve
  them, to have a last good copy, and then take the host away.
  """,
  rfc: ["6481#5", "8897#7"],
  expected: :valid,
  vrps: [
    "AS1234,1.1.0.0/16,16",
    "AS1234,2.1.0.0/16,16",
    "AS1234,101::/16,16",
    "AS1234,201::/16,16"
  ]
}
