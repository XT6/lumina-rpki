%{
  id: "m3-walk-siblings",
  title: "Eight CAs, each publishing in its own rsync module on one host",
  milestone: "M3",
  rationale: """
  The TA certifies eight CAs, each publishing in a module of its own on the
  TA's host (s1 to s8), so each needs its own rsync run even though whole
  modules are fetched (D-012). This is the shape where per-host parallelism
  still matters: many separately fetched units on one server, as
  registro.br's thousands of member CAs were under D-009 (#85). The walk
  fetches them concurrently, at most a fixed number at once per host
  (D-011).
  """,
  rfc: ["6481#5"],
  expected: :valid,
  rsync_modules: %{
    "s1" => "s1",
    "s2" => "s2",
    "s3" => "s3",
    "s4" => "s4",
    "s5" => "s5",
    "s6" => "s6",
    "s7" => "s7",
    "s8" => "s8"
  }
}
