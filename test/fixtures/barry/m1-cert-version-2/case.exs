%{
  id: "m1-cert-version-2",
  title: "CA certificate with X.509 version 2",
  milestone: "M1",
  rationale: """
  The baseline tree with one change: the CA certificate's version field is
  1, meaning X.509 v2. RFC 6487 section 4.1 requires version 3, and RFC 8897
  section 3.1 requires relying parties to check the profile, so validation
  must reject it.

  In M1 it checks that decoding is structural: the certificate must still
  decode, with version 2 visible, so that M4 can reject it with a precise
  reason instead of a generic decode error.
  """,
  rfc: ["6487#4.1", "8897#3.1", "5280#4.1.2.1"],
  expected:
    {:invalid,
     [%{object: "ta/ca1.cer", reason: "version is 2; RFC 6487 section 4.1 requires version 3"}]}
}
