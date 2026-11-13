%{
  id: "m4-cert-sia-no-manifest",
  title: "CA certificate whose SIA has no rpkiManifest",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate's Subject Information Access names the caRepository
  but no rpkiManifest. RFC 6487 section 4.8.8.1 requires an rsync URI for
  both.

  Certificate profile check (#110): validation must reject the CA
  certificate with this one reason, and accept everything else.
  """,
  rfc: ["6487#4.8.8.1"],
  expected: {:invalid, [%{object: "ta/ca1.cer", reason: "no rpki_manifest rsync URI"}]}
}
