# Warnings Dialyzer may ignore. Keep each entry specific and explained.
[
  # RFC 9582's ROA module constrains addressFamily with an information
  # object set (IPv4, IPv6). asn1ct generates lookup functions that exit for
  # any other AFI; Lumina.ASN1 turns that exit into {:error, ...}.
  {"gen/asn1/RPKI-ROA-2023.erl", :no_return}
]
