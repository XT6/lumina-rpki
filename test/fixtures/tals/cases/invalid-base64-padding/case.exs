%{
  id: "invalid-base64-padding",
  title: "Base64 key with a character missing at the end",
  rationale: """
  The last character of the key is removed, so the base64 length is no
  longer a multiple of four and the padding is wrong. Length and padding
  errors aren't tied to one key line, so they are reported at the first
  key line.
  """,
  rfc: ["8630#2.2", "4648#4"],
  expected: {:invalid, %{line: 3, rule: :bad_base64}}
}
