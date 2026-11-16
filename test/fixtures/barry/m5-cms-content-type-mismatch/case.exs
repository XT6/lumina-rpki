%{
  id: "m5-cms-content-type-mismatch",
  title: "content-type attribute that isn't the eContentType",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: The content-type signed attribute of roa1.roa names id-ct-rpkiManifest while its eContentType is the ROA type. RFC 6488 section 2.1.6.4.1 and section 3 item 1.h require them to match.

  CMS profile (#129): validation must reject roa1.roa with this one
  reason. Its EE certificate is valid.
  """,
  rfc: ["6488#2.1.6.4.1", "6488#3"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "the content-type attribute is not the eContentType",
         rule: :content_type_mismatch
       }
     ]},
  vrps: []
}
