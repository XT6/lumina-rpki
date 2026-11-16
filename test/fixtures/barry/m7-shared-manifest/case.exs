%{
  id: "m7-shared-manifest",
  title: "Two CAs naming the same manifest as their publication point",
  milestone: "M7",
  rationale: """
  The TA certifies ca1 and ca2, and ca2's SIA names ca1's directory and ca1's manifest. A publication point is identified by its CA's manifest (#195), so ca2's point is ca1's, reached a second time: the walk reports it as a duplicate and doesn't walk it again (RFC 6481 section 5). Contrast m7-shared-point, where the two CAs share the directory but each has its own manifest, and both are walked. ca2's own products, roa2.roa among them, are generated under ca1/ but listed on no manifest the walk reads, so only roa1.roa gives VRPs.
  """,
  rfc: ["6481#5", "9286#1"],
  expected: :valid
}
