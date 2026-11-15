%{
  id: "m1-roa-version-2",
  title: "ROA with version 2",
  milestone: "M1",
  rationale: """
  The baseline tree with one change: the ROA's version is 2. RFC 9582
  section 4.1 says it MUST be 0, so validation must reject the ROA. This is
  the incorrect repository from Barry's own tutorial.

  In M1 it checks that the decoder doesn't treat the wrong version as a
  decoding error: the ROA decodes with version 2 visible, and the version
  is explicitly encoded (it isn't the DEFAULT), so the object is still DER.

  ROA content validation (#171): the ROA is invalid, rule roa_version.
  """,
  rfc: ["9582#4.1"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "version is 2; RFC 9582 section 4.1 requires 0",
         rule: :roa_version
       }
     ]}
}
