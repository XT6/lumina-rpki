%{
  id: "m4-cert-name-extra-attribute",
  title: "CA certificate whose subject has an organizationName",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate's subject holds an organizationName besides its
  commonName. RFC 6487 sections 4.4 and 4.5 allow only one commonName and
  an optional serialNumber. The subject becomes the issuer of the CA's own
  CRL, manifest and ROA certificates, so their issuer names break the same
  rule.

  Certificate profile check (#109): validation must reject the CA
  certificate and the two EE certificates for their names, and the CRL
  profile check (#111) the CRL, whose issuer name is ca1's subject.
  """,
  rfc: ["6487#4.4", "6487#4.5"],
  expected:
    {:invalid,
     [
       %{object: "ta/ca1.cer", reason: "the subject holds an organizationName"},
       %{object: "ca1/ca1.crl", reason: "the CRL's issuer holds an organizationName"},
       %{object: "ca1/ca1.mft", reason: "the EE certificate's issuer holds an organizationName"},
       %{object: "ca1/roa1.roa", reason: "the EE certificate's issuer holds an organizationName"}
     ]}
}
