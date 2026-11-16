%{
  id: "m3-walk-delegation",
  title: "A CA whose publication point is on a second rsync host",
  milestone: "M3",
  rationale: """
  The TA certifies two CAs. ca1 publishes beside the TA, on the same host;
  ca2's caRepository is on another host, rsync://other.example:8873/repo/ca2.
  This is how LACNIC delegates to registro.br and to an Amazon-hosted
  directory. The walk must fetch ca2's publication point from the host its
  certificate names, as its own rsync run, and not from the TA's host
  (D-009). Its files are generated under rsync/other/, which tests serve
  from a second daemon.
  """,
  rfc: ["6481#5", "6487#4.8.8.1"],
  expected: :valid,
  vrps: [
    "AS1234,1.1.0.0/16,16",
    "AS1234,2.1.0.0/16,16",
    "AS1234,101::/16,16",
    "AS1234,201::/16,16"
  ]
}
