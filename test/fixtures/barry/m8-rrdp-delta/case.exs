%{
  id: "m8-rrdp-delta",
  title: "RRDP repository with one delta: a ROA withdrawn, one added",
  milestone: "M8",
  rationale: """
  The baseline for RRDP deltas (#202). Serial 1 is a TA, one CA and two
  ROAs. Serial 2 withdraws roa2.roa, publishes the new roa3.roa and
  replaces ca1.mft, whose file list changed; every other file is kept
  byte for byte (Barry's shield marker), so the delta holds exactly those
  three changes. An RP that syncs serial 1 from its snapshot and then
  applies delta 2 must end with exactly the objects of serial 2's
  snapshot, and the same VRPs as an RP that fetched serial 2's snapshot.
  """,
  rfc: ["8182#3.4.2", "8182#3.5.3.3", "6481#2"],
  expected: :valid,
  rrdp_versions: %{
    1 => "TA, ca1, roa1.roa and roa2.roa (snapshot-1.xml, notification-1.xml)",
    2 =>
      "roa2.roa withdrawn, roa3.roa added, ca1.mft replaced (snapshot.xml, delta-2.xml, notification.xml)"
  },
  vrps: [
    "AS1234,1.1.0.0/16,16",
    "AS1234,101::/16,16",
    "AS1234,1.2.0.0/16,16",
    "AS1234,102::/16,16"
  ]
}
