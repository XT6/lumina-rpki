%{
  id: "m5-pp-crl-hash-mismatch",
  title: "Manifest whose hash for the CA's CRL doesn't match the CRL",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: ca1.mft lists
  ca1.crl with a hash that isn't the SHA-256 of the published CRL. RFC
  9829 §3.2 makes the issuer's current CRL the one the current manifest
  identifies, and §5 relies on the manifest's hash to rule out an older
  CRL being replayed; RFC 9286 §6.5 makes the mismatch a failed fetch.

  CRL on the manifest (#116): ca1's publication point must fail with this
  one reason, so nothing in it is validated against that CRL.
  """,
  rfc: ["9829#3.2", "9829#5", "9286#6.5"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/ca1.mft",
         reason: "the hash of ca1.crl doesn't match the manifest",
         rule: :hash_mismatch
       }
     ]}
}
