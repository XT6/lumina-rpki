%{
  id: "m5-pp-crl-renamed",
  title: "Manifest that lists the CA's CRL under another name",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: ca1.mft lists the CRL as ca2.crl (Barry writes an empty hash for the renamed entry), so the CRL its EE certificate's CRLDP names, ca1.crl, isn't on the manifest, and ca2.crl isn't published. RFC 9286 section 6: a CRL not on the manifest is considered missing and the fetch fails; section 6.4: so does a listed file that isn't there.

  Publication point processing (#133): ca1's publication point must fail
  with exactly these reasons.
  """,
  rfc: ["9286#6", "9286#6.4", "9829#3.2"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the CRL ca1.crl is not on the manifest",
         rule: :crl_not_listed
       },
       %{
         object: "ca1/ca1.mft",
         reason: "ca2.crl is listed but not published",
         rule: :file_missing
       }
     ]},
  vrps: []
}
