%{
  id: "m5-pp-manifest-premature",
  title: "Manifest whose thisUpdate is in the future",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the thisUpdate of ca1.mft is 2031-01-01, after the tests' validation time (2030-01-01). RFC 9286 section 6.3: a prematurely issued manifest is a failed fetch.

  Publication point processing (#133): ca1's publication point must fail
  with exactly these reasons.
  """,
  rfc: ["9286#6.3", "9286#6.6"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the manifest is premature: thisUpdate is after the validation time",
         rule: :manifest_premature
       }
     ]},
  vrps: []
}
