# RRDP sync cases

Scenarios for `Lumina.RRDP.sync/3` over the Barry fixture `m8-rrdp-three`
(three serials of one session), run by `Lumina.M8DoneTest` (#209): the
RFC 9697 desync, a new session, a serial gap, each snapshot and delta
rejection, and the cross-origin cases of RFC 9674.

`cases.exs` holds one map per case:

- `id`: also the name of the test's builder, which makes the files served.
- `from`: the serial the store holds before the sync (synced from the
  fixture's own files), or `nil` for an empty cache.
- `rationale` and `rfc`: why the case exists and the sections it checks.
- `expected`:
  - `outcome`: `:snapshot`, `{:deltas, n}`, `:unchanged` or `{:failed, reason}`
  - optionally `fallback` (why the deltas gave way to the snapshot)
  - optionally `error` (the rule or `reason` of the error behind a
    failure or fallback)
  - optionally `warning` (a warning rule)
  - `store`: the store after the sync, either `:snapshot` (the files of
    the final snapshot) or `:kept` (as before the sync).

The files are built in the test, from the fixture's own files with one
change each, so no case has XML of its own here. The RRDP files'
structure is tested case by case in `test/fixtures/rrdp/cases/`.
