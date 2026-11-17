# Live RRDP notification files

Byte-exact copies of notification files served by live RRDP repositories, fetched on 2026-11-16 for the M8 plan's survey of the 126 notification URIs in the five RIRs' CA certificates. `RRDP.XMLTest` parses them to check that the XML parser (D-041, #198) accepts the shapes real servers send. Never edit them; replace one only with a fresh copy, and update its row.

| File | Source | Bytes | SHA-256 | Shape |
| --- | --- | ---: | --- | --- |
| `declaration.xml` | https://krill.rpki-measurement.site/rrdp/notification.xml | 371 | `c0b3b6b91bd406416227193a863e6fde02e4f19206480286c3d5db0a85314270` | An XML declaration with single quotes and `encoding='US-ASCII'`; the root on one line, with no trailing newline |
| `one-line.xml` | https://rpki-rrdp.us-east-2.amazonaws.com/rrdp/517f3ed7-58b5-4796-be37-14d62e48f056/notification.xml | 23,971 | `f00eeabab99757e9b17ea8424c9496defec7e46f44969a8eef977836481e6bb2` | No newlines at all; `session_id` first and `xmlns` last among the root's attributes |
| `lacnic.xml` | https://rrdp.lacnic.net/rrdp/notification.xml | 9,771 | `4d75a41b57e071c435469c55db003731b18d64219983b3c67691a79e6f0dcb10` | One element per line, indented; `xmlns` first |
