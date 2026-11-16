%{
  id: "m3-walk-loop",
  title: "A CA that names its parent's publication point as its own",
  milestone: "M3",
  rationale: """
  ca2 is issued by ca1 and published in ca1's directory, and its SIA
  names ca1's publication point as its own: that same directory and
  ca1's manifest. Walking ca2 leads back to the manifest that lists
  ca2.cer, so a naive walk never ends. The walk must notice that the
  publication point belongs to an ancestor, report the loop and carry on
  (D-008). A CA that only shares its parent's directory, with a manifest
  of its own, isn't a loop (m7-shared-point, #195). The objects
  themselves are well formed; the loop is a property of the walk.
  """,
  rfc: ["6481#5"],
  expected: :valid
}
