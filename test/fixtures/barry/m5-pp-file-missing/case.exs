%{
  id: "m5-pp-file-missing",
  title: "Manifest listing a file that isn't published",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: ca1.mft lists roa2.roa, which isn't in the publication point (the ROA is published as roa1.roa). RFC 9286 section 6.4: a listed file that can't be retrieved is a failed fetch.

  Publication point processing (#133): ca1's publication point must fail
  with exactly these reasons.
  """,
  rfc: ["9286#6.4", "9286#6.6"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "roa2.roa is listed but not published",
         rule: :file_missing
       }
     ]}
}
