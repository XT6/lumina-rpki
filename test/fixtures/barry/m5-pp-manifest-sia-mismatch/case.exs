%{
  id: "m5-pp-manifest-sia-mismatch",
  title: "Manifest EE certificate naming another URI",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: the signedObject URI in the SIA of ca1.mft's EE certificate is rsync://localhost:8873/rpki/ca1/other.mft, not the URI it is fetched from (ca1's rpkiManifest). RFC 9981 section 4: the fetch fails.

  Publication point processing (#133): ca1's publication point must fail
  with exactly these reasons.
  """,
  rfc: ["9981#4", "9286#6.6"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the EE certificate's signedObject URI isn't the manifest's URI",
         rule: :manifest_uri_mismatch
       }
     ]}
}
