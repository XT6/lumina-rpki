%{
  id: "m1-cert-no-ski",
  title: "CA certificate without a Subject Key Identifier",
  milestone: "M1",
  rationale: """
  The baseline tree with one change: the CA certificate has no Subject Key
  Identifier extension. RFC 6487 section 4.8.2 says it MUST appear in all
  resource certificates; it is also how children find their issuer (AKI),
  so validation must reject the certificate.

  In M1 it checks that a missing mandatory extension is not a decoding
  error: the certificate decodes and simply has no SKI.
  """,
  rfc: ["6487#4.8.2", "6487#4.8", "8897#3.1"],
  expected:
    {:invalid,
     [
       %{
         object: "ta/ca1.cer",
         reason: "no Subject Key Identifier; RFC 6487 section 4.8.2 requires it"
       }
     ]}
}
