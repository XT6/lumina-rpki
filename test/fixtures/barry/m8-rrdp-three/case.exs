%{
  id: "m8-rrdp-three",
  title: "RRDP repository with two deltas: a ROA added, then one withdrawn and one replaced",
  milestone: "M8",
  rationale: """
  Two deltas in a row (#204). Serial 1 is a TA, one CA and two ROAs.
  Delta 2 publishes the new roa3.roa and replaces ca1.mft. Delta 3
  withdraws roa1.roa, replaces roa3.roa (re-signed, so new bytes under
  the same URI) and replaces ca1.mft again; every other file is kept
  byte for byte (Barry's shield marker). An RP at serial 1 must apply
  both deltas in order, each replace and withdraw naming the hash of the
  object it holds, and end with exactly serial 3's snapshot; an RP at
  serial 2 applies delta 3 only.
  """,
  rfc: ["8182#3.4.2", "8182#3.5.3.3"],
  expected: :valid,
  rrdp_versions: %{
    1 => "TA, ca1, roa1.roa and roa2.roa (snapshot-1.xml, notification-1.xml)",
    2 => "roa3.roa added, ca1.mft replaced (snapshot-2.xml, delta-2.xml, notification-2.xml)",
    3 =>
      "roa1.roa withdrawn, roa3.roa and ca1.mft replaced (snapshot.xml, delta-3.xml, notification.xml)"
  },
  # roa2.roa and the re-signed roa3.roa hold the same prefixes, so
  # lumina vrps lists them once.
  vrps: ["AS1234,1.2.0.0/16,16", "AS1234,102::/16,16"]
}
