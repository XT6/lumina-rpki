%{
  id: "m3-walk-loop",
  title: "A CA that names its parent's publication point as its own",
  milestone: "M3",
  rationale: """
  ca2 is issued by ca1 and published in ca1's directory, and its
  caRepository is that same directory. Walking ca2 leads back to the
  publication point that holds ca2.cer, so a naive walk never ends. The
  walk must notice that the publication point belongs to an ancestor,
  report the loop and carry on (D-008). The objects themselves are
  well formed; the loop is a property of the walk.
  """,
  rfc: ["6481#5"],
  expected: :valid
}
