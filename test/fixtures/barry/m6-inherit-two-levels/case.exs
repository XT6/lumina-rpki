%{
  id: "m6-inherit-two-levels",
  title: "Resources inherited through two levels",
  milestone: "M6",
  rationale: """
  ta, ca1 with Barry's default resources, then ca2 and ca3 that both inherit every address family and their AS numbers, and a ROA under ca3 whose EE certificate lists ca1's addresses explicitly (Barry's default there would inherit, which RFC 9582 section 5 forbids in a ROA, #171). RFC 3779 sections 2.2.3.5 and 3.2.3.3: inherited resources are taken "from the issuer's certificate, or from the issuer's issuer's certificate, recursively", so ca3 and the EE certificate hold ca1's resources.

  Effective resources (#153): everything validates.
  """,
  rfc: ["3779#2.2.3.5", "3779#3.2.3.3", "6487#4.8.10", "6487#4.8.11"],
  expected: :valid,
  vrps: ["AS1234,1.0.0.0/8,8", "AS1234,100::/8,8"]
}
