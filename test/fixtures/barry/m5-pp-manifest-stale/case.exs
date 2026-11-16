%{
  id: "m5-pp-manifest-stale",
  title: "Manifest past its nextUpdate",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the nextUpdate of ca1.mft is 2027-01-01, before the tests' validation time (2030-01-01). RFC 9286 section 6.3: a stale manifest is a failed fetch. Its EE certificate (valid to 2036) and content are otherwise valid.

  Publication point processing (#133): ca1's publication point must fail
  with exactly these reasons.
  """,
  rfc: ["9286#6.3", "9286#6.6"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the manifest is stale: nextUpdate is before the validation time",
         rule: :manifest_stale
       }
     ]},
  vrps: []
}
