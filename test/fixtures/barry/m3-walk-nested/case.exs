%{
  id: "m3-walk-nested",
  title: "A CA publication point nested inside the TA's",
  milestone: "M3",
  rationale: """
  ca1's caRepository is a subdirectory of the TA's publication point
  (rpki/ta/ca1). The recursive fetch of the TA's publication point already
  brings it, so the walk must read it from that copy and make no rsync run
  of its own (D-009). This is the common shape of RIR repositories, where
  one fetch covers most of the tree.
  """,
  rfc: ["6481#5", "6481#2"],
  expected: :valid
}
