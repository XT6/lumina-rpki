%{
  id: "m3-walk-shared-module",
  title: "Two sibling CAs publishing in the same rsync module",
  milestone: "M3",
  rationale: """
  The TA certifies ca1, which certifies ca2 and ca3, each with a ROA. All of them publish under the TA's module (rpki), so the walk fetches the module once (D-012) and finds ca2's and ca3's publication points at the same level, covered by that fetch. A level's points are validated in parallel before they are reported (#169); this is the shape where a refetch of the module caused by one sibling must be seen by the other (RFC 6481 section 5, #137).
  """,
  rfc: ["6481#5"],
  expected: :valid
}
