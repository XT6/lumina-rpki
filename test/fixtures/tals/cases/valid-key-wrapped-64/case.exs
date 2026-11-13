%{
  id: "valid-key-wrapped-64",
  title: "The key wrapped at 64 characters per line",
  rationale: """
  Line breaks MAY be inserted into the base64 key. This uses a Barry TA
  key wrapped at 64 characters, the width Barry and most tools use, as
  opposed to the RFC example's 57.
  """,
  rfc: ["8630#2.2", "4648#4"],
  expected: :valid
}
