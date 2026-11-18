defmodule Lumina.RRDP.SyncDeltasTest do
  @moduledoc """
  Catching up with deltas (#204, `Lumina.RRDP.Sync.run/3`): RFC 8182
  §3.4.2 with the publish-hash rule of erratum 6919 (F-037), against the
  delta fixtures `m8-rrdp-three` (serials 1 to 3) and `m8-rrdp-delta`
  (1 and 2) served by `Lumina.Test.RRDPServer`.

  A store at serial K must reach serial N by fetching only deltas K+1 to
  N, and end with exactly serial N's snapshot. Every rejected delta, and
  every element that would touch an object the store doesn't hold with
  the hash it names, must drop the half-applied copy and fall back to
  the snapshot (§3.4.2); if the snapshot fails too, the last good store
  stays. Withdraws and replaces only ever reach the repository's own
  store, so one repository can't remove or change objects another
  published under the same rsync URIs (§3.4.2).
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Lumina.RRDP.{State, Sync}
  alias Lumina.Test.{Fixture, RRDPServer}

  @moduletag :tmp_dir
  @base "https://localhost:8443/rrdp/"
  @roa1 "rsync://localhost:8873/rpki/ca1/roa1.roa"
  @roa2 "rsync://localhost:8873/rpki/ca1/roa2.roa"

  defp three, do: Fixture.load!("m8-rrdp-three")

  defp read(fixture, name), do: File.read!(Path.join(fixture.rrdp_root, name))

  # A cache synced from the snapshot of `fixture`'s serial `serial`, and
  # the server, now serving the last serial.
  defp at(dir, fixture, serial) do
    server = RRDPServer.start!(RRDPServer.routes(fixture, serial))
    root = Path.join(dir, "cache")

    assert %{outcome: :snapshot, serial: ^serial} =
             Sync.run(fixture.notification_uri, root, server.opts)

    RRDPServer.serve(server, RRDPServer.routes(fixture))
    {server, root}
  end

  defp sync(server, root, fixture), do: Sync.run(fixture.notification_uri, root, server.opts)

  defp store(root, fixture), do: RRDPServer.store_files(root, fixture.notification_uri)

  # Serial 3 of m8-rrdp-three with delta 3 replaced by `delta` (bytes),
  # served as d3.xml; the snapshot is the real one.
  defp serve_delta3(server, fixture, delta) do
    notification =
      RRDPServer.notification(
        fixture.session_id,
        3,
        {@base <> "snapshot.xml", read(fixture, "snapshot.xml")},
        [{3, @base <> "d3.xml", delta}]
      )

    RRDPServer.serve(
      server,
      RRDPServer.routes(fixture)
      |> Map.put("/rrdp/notification.xml", {200, [], notification})
      |> Map.put("/rrdp/d3.xml", {200, [], delta})
    )
  end

  # A hand-made delta 3 for a store at serial 2: first a valid withdraw of
  # roa2.roa, so the copy is changed before `element` is reached.
  defp delta3(root, fixture, element) do
    roa2 = store(root, fixture)["rsync/localhost:8873/rpki/ca1/roa2.roa"]
    RRDPServer.delta(fixture.session_id, 3, [{:withdraw, @roa2, roa2}, element])
  end

  # The delta was rejected for `rule` (or `reason`), and the snapshot gave
  # the store serial 3.
  defp assert_fell_back(result, root, fixture, reason, rule) do
    assert result.outcome == :snapshot
    assert result.serial == 3
    assert result.fallback.reason == reason
    if rule, do: assert(result.fallback.error.rule == rule)
    assert store(root, fixture) == RRDPServer.snapshot_files(fixture)
  end

  @tag rfc: ["8182#3.4.1", "8182#3.4.2"]
  test "from serial 1, serial 3 is reached by deltas 2 and 3 alone, and equals its snapshot",
       %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 1)

    result = sync(server, root, fixture)

    assert result.outcome == {:deltas, 2}
    assert result.serial == 3
    assert result.fallback == nil
    # Delta 2: roa3.roa added, ca1.mft replaced; delta 3: roa1.roa
    # withdrawn, roa3.roa and ca1.mft replaced.
    assert result.objects == 5

    assert RRDPServer.requested(server) ==
             ["/rrdp/notification.xml", "/rrdp/delta-2.xml", "/rrdp/delta-3.xml"]

    assert store(root, fixture) == RRDPServer.snapshot_files(fixture)

    state = State.load(root, fixture.notification_uri)
    assert {state.serial, state.outcome} == {3, :ok}
    assert Map.keys(state.deltas) == [2, 3]
  end

  @tag rfc: "8182#3.4.2"
  test "from serial 2, only delta 3 is fetched", %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)

    assert %{outcome: {:deltas, 1}, serial: 3, objects: 3} = sync(server, root, fixture)
    assert RRDPServer.requested(server) == ["/rrdp/notification.xml", "/rrdp/delta-3.xml"]
    assert store(root, fixture) == RRDPServer.snapshot_files(fixture)
  end

  @tag rfc: "8182#3.4.2",
       doc: """
       For the sync summary (#233): `previous` is the store's session_id
       and serial before the run (none on a first sync), and `bytes` the
       size of every file received, here the notification and the
       snapshot, then the notification and deltas 2 and 3. A sync that
       downloads nothing counts no bytes.
       """
  test "the result gives the store's serial before the sync and the bytes received",
       %{tmp_dir: dir} do
    fixture = three()
    size = &byte_size(read(fixture, &1))
    server = RRDPServer.start!(RRDPServer.routes(fixture, 1))
    root = Path.join(dir, "cache")

    first = sync(server, root, fixture)
    assert {first.outcome, first.previous} == {:snapshot, nil}
    assert first.bytes == size.("notification-1.xml") + size.("snapshot-1.xml")

    RRDPServer.serve(server, RRDPServer.routes(fixture))
    second = sync(server, root, fixture)
    assert second.outcome == {:deltas, 2}
    assert second.previous == %{session_id: fixture.session_id, serial: 1}
    assert {second.session_id, second.serial} == {fixture.session_id, 3}

    assert second.bytes ==
             size.("notification.xml") + size.("delta-2.xml") + size.("delta-3.xml")

    recent = Sync.run(fixture.notification_uri, root, Keyword.delete(server.opts, :min_interval))
    assert recent.outcome == :recent
    assert recent.previous == %{session_id: fixture.session_id, serial: 3}
    assert recent.bytes == 0
  end

  @tag rfc: "8182#3.4.2"
  test "m8-rrdp-delta's serial 1 store reaches serial 2 by its delta", %{tmp_dir: dir} do
    fixture = Fixture.load!("m8-rrdp-delta")
    {server, root} = at(dir, fixture, 1)

    assert %{outcome: {:deltas, 1}, serial: 2, objects: 3} = sync(server, root, fixture)
    assert store(root, fixture) == RRDPServer.snapshot_files(fixture)
  end

  @tag rfc: "8182#3.4.2", doc: "Delta 2's file served where delta 3 is announced."
  test "a delta whose hash isn't the notification's falls back to the snapshot", %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)

    RRDPServer.serve(
      server,
      Map.put(
        RRDPServer.routes(fixture),
        "/rrdp/delta-3.xml",
        {:file, Path.join(fixture.rrdp_root, "delta-2.xml")}
      )
    )

    result = sync(server, root, fixture)
    assert_fell_back(result, root, fixture, :delta_hash_mismatch, :delta_hash_mismatch)
    assert List.last(RRDPServer.requested(server)) == "/rrdp/snapshot.xml"
  end

  @tag rfc: ["8182#3.4.2", "8182#3.5.3.3"]
  test "a delta of another session_id falls back to the snapshot", %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    other = "6d3a1f6e-2c4b-4d8e-9f1a-0b2c3d4e5f60"
    delta = String.replace(read(fixture, "delta-3.xml"), fixture.session_id, other)
    serve_delta3(server, fixture, delta)

    result = sync(server, root, fixture)
    assert_fell_back(result, root, fixture, :delta_rejected, :session_mismatch)
  end

  @tag rfc: ["8182#3.4.2", "8182#3.5.3.3"],
       doc: "Delta 3's file with serial 4: not one more than the store's serial 2."
  test "a delta of another serial falls back to the snapshot", %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    delta = String.replace(read(fixture, "delta-3.xml"), ~s(serial="3"), ~s(serial="4"))
    serve_delta3(server, fixture, delta)

    result = sync(server, root, fixture)
    assert_fell_back(result, root, fixture, :delta_rejected, :serial_mismatch)
  end

  @tag rfc: "8182#3.4.1",
       doc: """
       The store is at serial 1 and the notification lists only delta 3:
       deltas can't reach serial 3, so the snapshot is used and no delta
       is fetched. Not a delta rejection, so there is no fallback.
       """
  test "a gap in the listed deltas goes straight to the snapshot", %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 1)
    serve_delta3(server, fixture, read(fixture, "delta-3.xml"))

    assert %{outcome: :snapshot, serial: 3, fallback: nil} = sync(server, root, fixture)
    assert RRDPServer.requested(server) == ["/rrdp/notification.xml", "/rrdp/snapshot.xml"]
    assert store(root, fixture) == RRDPServer.snapshot_files(fixture)
  end

  @tag rfc: "8182#3.4.2"
  test "a withdraw of a URI the store doesn't hold falls back to the snapshot", %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    missing = "rsync://localhost:8873/rpki/ca1/missing.roa"
    serve_delta3(server, fixture, delta3(root, fixture, {:withdraw, missing, "x"}))

    result = sync(server, root, fixture)
    assert_fell_back(result, root, fixture, :delta_rejected, :withdraw_not_held)
  end

  @tag rfc: "8182#3.4.2"
  test "a withdraw whose hash isn't the stored object's falls back to the snapshot",
       %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    serve_delta3(server, fixture, delta3(root, fixture, {:withdraw, @roa1, "not roa1"}))

    result = sync(server, root, fixture)
    assert_fell_back(result, root, fixture, :delta_rejected, :withdraw_hash_mismatch)
  end

  @tag rfc: "8182#3.4.2"
  test "a publish replacing an object with a wrong hash falls back to the snapshot",
       %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    serve_delta3(server, fixture, delta3(root, fixture, {:publish, @roa1, "new", "not roa1"}))

    result = sync(server, root, fixture)
    assert_fell_back(result, root, fixture, :delta_rejected, :replace_hash_mismatch)
  end

  @tag rfc: "8182#3.4.2", doc: "Erratum 6919 (F-037): an overwrite must give the old hash."
  test "a publish without a hash for an object the store holds falls back to the snapshot",
       %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    serve_delta3(server, fixture, delta3(root, fixture, {:publish, @roa1, "new"}))

    result = sync(server, root, fixture)
    assert_fell_back(result, root, fixture, :delta_rejected, :publish_without_hash)
  end

  @tag rfc: "8182#3.4.2", doc: "Erratum 6919 (F-037): a new object has no hash."
  test "a publish with a hash for a URI the store doesn't hold falls back to the snapshot",
       %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    missing = "rsync://localhost:8873/rpki/ca1/missing.roa"
    serve_delta3(server, fixture, delta3(root, fixture, {:publish, missing, "new", "old"}))

    result = sync(server, root, fixture)
    assert_fell_back(result, root, fixture, :delta_rejected, :replace_not_held)
  end

  @tag rfc: ["8182#3.4.2", "8182#3.4.3"],
       doc: """
       Delta 3 withdraws roa2.roa and then fails; the snapshot is a 404.
       The half-applied copy is dropped, so roa2.roa is still there.
       """
  test "a rejected delta whose snapshot fails too leaves the store at its serial",
       %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    before = store(root, fixture)
    serve_delta3(server, fixture, delta3(root, fixture, {:withdraw, @roa1, "not roa1"}))

    RRDPServer.serve(
      server,
      Map.delete(Agent.get(server.agent, & &1.routes), "/rrdp/snapshot.xml")
    )

    result = sync(server, root, fixture)

    assert result.outcome == {:failed, :snapshot_failed}
    assert result.fallback.error.rule == :withdraw_hash_mismatch
    assert result.serial == 2
    assert store(root, fixture) == before
    assert before == RRDPServer.snapshot_files(fixture, "snapshot-2.xml")
    assert State.load(root, fixture.notification_uri).serial == 2
  end

  @tag rfc: "9674#3.2"
  test "a cross-origin redirect of a delta fails the sync without the snapshot",
       %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    before = store(root, fixture)

    RRDPServer.serve(
      server,
      Map.put(
        RRDPServer.routes(fixture),
        "/rrdp/delta-3.xml",
        {302, [{"location", "https://127.0.0.1:8443/rrdp/delta-3.xml"}], ""}
      )
    )

    log =
      capture_log(fn ->
        assert %{outcome: {:failed, :cross_origin}, fallback: nil} = sync(server, root, fixture)
      end)

    assert log =~ "RFC 9674"
    refute "/rrdp/snapshot.xml" in RRDPServer.requested(server)
    assert store(root, fixture) == before
  end

  @tag rfc: "8182#3.4.2",
       doc: """
       Repository A (m8-rrdp-three) holds roa2.roa. Repository B, another
       notification URI on the same server, starts from a snapshot of one
       object, then sends a delta that withdraws A's roa2.roa, and then one
       that replaces it, each naming A's hash. Neither reaches A's store:
       B's store doesn't hold the object, so each delta is rejected and B
       takes its snapshot.
       """
  test "a repository can't withdraw or replace another repository's objects", %{tmp_dir: dir} do
    a = three()
    {server, root} = at(dir, a, 3)
    a_files = store(root, a)
    roa2 = a_files["rsync/localhost:8873/rpki/ca1/roa2.roa"]

    {:ok, b} = Lumina.URI.parse("https://localhost:8443/b/notification.xml")
    session = "6d3a1f6e-2c4b-4d8e-9f1a-0b2c3d4e5f60"
    own = "rsync://localhost:8873/rpki/b/own.roa"
    b_base = "https://localhost:8443/b/"

    serve_b = fn serial, delta ->
      snapshot = RRDPServer.snapshot(session, serial, [{own, "own #{serial}"}])
      deltas = if delta, do: [{serial, b_base <> "d.xml", delta}], else: []

      RRDPServer.serve(server, %{
        "/b/notification.xml" =>
          {200, [],
           RRDPServer.notification(session, serial, {b_base <> "s.xml", snapshot}, deltas)},
        "/b/s.xml" => {200, [], snapshot},
        "/b/d.xml" => {200, [], delta || ""}
      })
    end

    serve_b.(1, nil)
    assert %{outcome: :snapshot, serial: 1} = Sync.run(b, root, server.opts)

    serve_b.(2, RRDPServer.delta(session, 2, [{:withdraw, @roa2, roa2}]))
    result = Sync.run(b, root, server.opts)
    assert result.outcome == :snapshot
    assert result.fallback.error.rule == :withdraw_not_held

    serve_b.(3, RRDPServer.delta(session, 3, [{:publish, @roa2, "evil", roa2}]))
    result = Sync.run(b, root, server.opts)
    assert result.outcome == :snapshot
    assert result.fallback.error.rule == :replace_not_held

    assert store(root, a) == a_files
    assert RRDPServer.store_files(root, b) == %{"rsync/localhost:8873/rpki/b/own.roa" => "own 3"}
  end
end
