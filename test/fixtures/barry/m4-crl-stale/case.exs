%{
  id: "m4-crl-stale",
  title: "CRL past its nextUpdate",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: ca1's CRL has a nextUpdate of 2029-01-01, before the validation time the
  tests use (2030-01-01). D-016: a stale CRL is still used, with a
  warning.

  CRL profile check (#111): the CRL is accepted, with a stale_crl
  warning.
  """,
  rfc: ["5280#5.1.2.5", "6487#5"],
  expected: :valid
}
