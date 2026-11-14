%{
  id: "m5-mft-empty-file-list",
  title: "Manifest with an empty fileList",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: ca1.mft lists no files. RFC 9286 section 7: "A CA's manifest will always contain at least one entry"; verified erratum 7118 corrects the ASN.1 module's fileList from SIZE (0..MAX) to SIZE (1..MAX). The module is kept as published, so the manifest decodes (F-001 in doc/rfc-findings.md).

  Empty manifests (#37, maintainer decision of 2026-11-12): validation must reject ca1.mft as empty. Since the manifest doesn't list the CA's CRL, the publication point also fails for that (RFC 9286 section 6).
  """,
  rfc: ["9286#7", "9286#6"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "manifest has no entries (RFC 9286 section 7, erratum 7118)",
         rule: :manifest_empty
       },
       %{
         object: "ca1/ca1.mft",
         reason: "the CRL ca1.crl is not on the manifest",
         rule: :crl_not_listed
       }
     ]}
}
