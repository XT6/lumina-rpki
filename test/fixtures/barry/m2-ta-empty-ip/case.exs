%{
  id: "m2-ta-empty-ip",
  title: "Trust anchor certificate with an empty IP resource extension",
  milestone: "M2",
  rationale: """
  A TA certificate whose IP Address Delegation extension is present but
  empty: an IPAddrBlocks with no address families. Its AS resources are
  normal. RFC 8630 section 2.3 requires the TA's INR extension(s) to
  contain a non-empty set of resources.

  Whether "a non-empty set" means the union of both extensions or each
  extension is ambiguous (F-023 in doc/rfc-findings.md). Lumina reads it as
  each present extension, so this TA is rejected even though its AS set
  is not empty.
  """,
  rfc: ["8630#2.3", "6487#4.8.10"],
  expected:
    {:invalid,
     [%{object: "ta.cer", reason: "the IP resource extension is empty; RFC 8630 section 2.3"}]}
}
