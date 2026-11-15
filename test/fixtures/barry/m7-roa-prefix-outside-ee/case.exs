%{
  id: "m7-roa-prefix-outside-ee",
  title: "ROA with a prefix outside its EE certificate's addresses",
  milestone: "M7",
  rationale: """
  The baseline tree (m0-minimal-valid) with a second ROA, roa2.roa, as Barry writes it by default, and one change: roa1.roa also lists 1.2.0.0/16, while its EE certificate holds 1.1.0.0/16 and 101::/16. RFC 9582 section 5 requires "every IP address prefix in the ROA payload is contained within the set of IP addresses specified by the EE certificate's IP address delegation extension"; if not, "the ROA in its entirety MUST be considered invalid", so the ROA's other prefixes give no VRPs either. roa2.roa, at the same publication point, stays valid. The EE certificate itself is within ca1's resources, so this is not an overclaim (RFC 6487 section 7.2).

  ROA content validation (#171).
  """,
  rfc: ["9582#5"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "1.2.0.0/16 not in the EE certificate's addresses",
         rule: :roa_prefix_outside_ee
       }
     ]}
}
