# RRDP file cases

Hand-written RRDP files, one per case, each accepted or rejected for one stated reason (#199). `Lumina.RRDP.FilesTest` decodes every one and checks its outcome.

- `<id>.xml`: the file, byte for byte as a server would send it.
- `cases.exs`: one map per file, read as data:
  - `id`, `kind` (`:notification`, `:snapshot` or `:delta`)
  - `rfc`: the sections the case checks, in the `:rfc` tag format
  - `rationale`: why the case exists
  - `expected`: `:ok`, `{:warning, rule}` (decoded, with that warning) or `{:error, rule}`

The test checks that every file has metadata, that every case has a file, and that every RFC reference exists.

Conventions:
- **Notifications** are decoded as fetched from `https://rrdp.example.net/notification.xml`.
- **Snapshots and deltas** are decoded as the notification's session `9df4b597-af9e-4dca-bdda-719cce2c4e28`, serial 3.
- Hashes that only need to be well-formed are 64 `a`s.
