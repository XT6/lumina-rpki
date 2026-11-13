%{
  id: "invalid-ftp-uri",
  title: "An FTP URI",
  rationale: """
  Any scheme other than rsync or HTTPS is unsupported.
  """,
  rfc: ["8630#2.2"],
  expected: {:invalid, %{line: 1, rule: :unsupported_scheme}}
}
