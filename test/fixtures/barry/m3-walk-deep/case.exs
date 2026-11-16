%{
  id: "m3-walk-deep",
  title: "A chain of four CAs below the TA",
  milestone: "M3",
  rationale: """
  TA, ca1, ca2, ca3, ca4 and a ROA: five publication points, depths 0 to 4.
  RFC 6481 §5 says the walk SHOULD support a locally configured maximum
  chain length (D-008: 32 by default). With a test-sized limit of 2 the
  walk must stop before ca3 and report it; with the default it must reach
  ca4.
  """,
  rfc: ["6481#5"],
  expected: :valid,
  vrps: ["AS1234,1.1.1.1/32,32", "AS1234,101:101:100::/40,40"]
}
