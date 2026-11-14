%{
  id: "m4-cert-serial-too-long",
  title: "CA certificate with a 21-octet serial number",
  milestone: "M4",
  rationale: """
  The baseline tree with one change: the CA certificate's serial number takes 21 octets. RFC 5280 section
  4.1.2.2 forbids CAs to use more than 20.

  Certificate profile check (#109): validation must reject the CA
  certificate with this one reason, and accept everything else.
  """,
  rfc: ["5280#4.1.2.2", "6487#4.2"],
  expected:
    {:invalid,
     [
       %{
         object: "ta/ca1.cer",
         reason: "serial number is 21 octets; at most 20 are allowed",
         rule: :serial_too_long
       }
     ]}
}
