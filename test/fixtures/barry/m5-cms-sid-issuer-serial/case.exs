%{
  id: "m5-cms-sid-issuer-serial",
  title: "Signer identified by issuer and serial number",
  milestone: "M5",
  rationale: """
  The baseline tree (m0-minimal-valid) with one change: The signer of roa1.roa is identified by issuerAndSerialNumber. RFC 6488 section 2.1.6.2 requires the subjectKeyIdentifier choice, matching the EE certificate's SKI (section 3 item 1.c).

  CMS profile (#129): validation must reject roa1.roa with this one
  reason. Its EE certificate is valid.
  """,
  rfc: ["6488#2.1.6.2", "6488#3"],
  expected:
    {:invalid,
     [
       %{
         object: "ca1/roa1.roa",
         reason: "the signer is identified by issuer and serial number, not by SKI",
         rule: :sid_not_ski
       }
     ]}
}
