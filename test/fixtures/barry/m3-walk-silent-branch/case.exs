%{
  id: "m3-walk-silent-branch",
  title: "A silent host on one branch, a deep branch elsewhere",
  milestone: "M3",
  rationale: """
  The TA certifies ca1 and ca2. ca1 publishes on silent.example, which tests point at a server that accepts TCP connections and never answers, as some delegated repositories do (#88): each fetch from it waits for rsync's connect timeout (D-008). ca2, ca3 and ca4 form a chain, each publishing in a module of its own, so every level of that branch needs an rsync run. A walk that waits for a whole level before going on holds the deep branch up for the silent host's timeout; the walk must instead go down the deep branch while the silent fetch is still waiting (#88).
  """,
  rfc: ["6481#5"],
  expected: :valid,
  rsync_modules: %{"d2" => "d2", "d3" => "d3", "d4" => "d4"},
  vrps: [
    "AS1234,1.1.0.0/16,16",
    "AS1234,2.1.1.1/32,32",
    "AS1234,101::/16,16",
    "AS1234,201:101::/32,32"
  ]
}
