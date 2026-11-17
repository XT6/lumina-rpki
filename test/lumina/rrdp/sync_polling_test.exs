defmodule Lumina.RRDP.SyncPollingTest do
  @moduledoc """
  Session desynchronization (RFC 9697) and polling (RFC 8182 §3.4.4) in
  `Lumina.RRDP.Sync.run/3` (#205), against the delta fixture
  `m8-rrdp-three` served by `Lumina.Test.RRDPServer`.

  A server can rewrite a delta it already published, and an RP that keeps
  applying deltas would then drift from the repository without noticing.
  RFC 9697 has the RP compare the hash of every delta serial it saw in
  the last notification with the new one, and take the snapshot when any
  changed. RFC 8182 §3.4.4 forbids polling a notification more than once
  a minute and requires `If-Modified-Since`, so a run from cron, or two
  runs in a row, must not hammer a repository: a store synced less than
  60 s ago is used without any request, and a 304 changes nothing.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Lumina.RRDP.{State, Sync}
  alias Lumina.Test.{Fixture, RRDPServer}

  @moduletag :tmp_dir
  @base "https://localhost:8443/rrdp/"
  @t0 ~U[2030-01-01 00:00:00Z]

  defp three, do: Fixture.load!("m8-rrdp-three")

  defp read(fixture, name), do: File.read!(Path.join(fixture.rrdp_root, name))

  defp at(dir, fixture, serial) do
    server = RRDPServer.start!(RRDPServer.routes(fixture, serial))
    root = Path.join(dir, "cache")

    assert %{outcome: :snapshot, serial: ^serial} =
             Sync.run(fixture.notification_uri, root, server.opts)

    {server, root}
  end

  defp sync(server, root, fixture, opts \\ []),
    do: Sync.run(fixture.notification_uri, root, Keyword.merge(server.opts, opts))

  defp store(root, fixture), do: RRDPServer.store_files(root, fixture.notification_uri)

  # Serial `serial` of m8-rrdp-three, its real snapshot, listing the real
  # deltas 2..serial except those in `mutated`, whose hash is changed.
  defp serve_notification(server, fixture, serial, mutated) do
    snapshot = if serial == 3, do: "snapshot.xml", else: "snapshot-#{serial}.xml"

    deltas =
      for k <- 2..serial//1 do
        file = read(fixture, "delta-#{k}.xml")
        {k, @base <> "delta-#{k}.xml", if(k in mutated, do: "mutated " <> file, else: file)}
      end

    notification =
      RRDPServer.notification(
        fixture.session_id,
        serial,
        {@base <> snapshot, read(fixture, snapshot)},
        deltas
      )

    RRDPServer.serve(
      server,
      Map.put(RRDPServer.routes(fixture), "/rrdp/notification.xml", {200, [], notification})
    )
  end

  defp desync(result), do: Enum.find(result.warnings, &(&1[:rule] == :rrdp_desync))

  @tag rfc: ["9697#3.1", "9697#4", "9697#5"],
       doc: """
       RFC 9697 §3.1's scenario on m8-rrdp-three: the store is at serial 2,
       having seen delta 2's hash. The notification at serial 3 lists
       delta 2 with another hash. A warning names serial 2, and the
       snapshot is used, not delta 3.
       """
  test "a delta hash that changed for a serial seen before is a desync: warned, then the snapshot",
       %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    serve_notification(server, fixture, 3, [2])

    log =
      capture_log(fn ->
        result = sync(server, root, fixture)
        assert result.outcome == :snapshot
        assert result.serial == 3
        assert %{serials: [2], rfc: "9697#4"} = desync(result)
      end)

    assert log =~ "RFC 9697"
    assert RRDPServer.requested(server) == ["/rrdp/notification.xml", "/rrdp/snapshot.xml"]
    assert store(root, fixture) == RRDPServer.snapshot_files(fixture)

    # The new notification's hashes are the ones remembered.
    state = State.load(root, fixture.notification_uri)
    assert state.deltas[2] == :crypto.hash(:sha256, "mutated " <> read(fixture, "delta-2.xml"))
  end

  @tag rfc: ["9697#3", "8182#3.4.2"]
  test "unchanged hashes for every serial seen before let the deltas be used", %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 2)
    serve_notification(server, fixture, 3, [])

    result = sync(server, root, fixture)
    assert result.outcome == {:deltas, 1}
    assert desync(result) == nil
    assert RRDPServer.requested(server) == ["/rrdp/notification.xml", "/rrdp/delta-3.xml"]
  end

  @tag rfc: ["9697#4", "8182#3.4.3"],
       doc: """
       The store is at serial 3, and the notification, still at serial 3,
       lists delta 3 with another hash. The desync is warned, but the
       snapshot isn't processed: its serial isn't greater than the last
       processed (F-042).
       """
  test "a desync at the store's serial is warned, and the store stays", %{tmp_dir: dir} do
    fixture = three()
    {server, root} = at(dir, fixture, 3)
    before = store(root, fixture)
    serve_notification(server, fixture, 3, [3])

    capture_log(fn ->
      result = sync(server, root, fixture)
      assert result.outcome == :unchanged
      assert %{serials: [3]} = desync(result)
    end)

    assert RRDPServer.requested(server) == ["/rrdp/notification.xml"]
    assert store(root, fixture) == before
  end

  @tag rfc: "8182#3.4.4",
       doc: """
       A 304 to If-Modified-Since: nothing else is downloaded, the store
       is as it was, and so is the state but for its times.
       """
  test "a 304 leaves the store and the state as they were", %{tmp_dir: dir} do
    fixture = three()
    stamp = "Tue, 01 Jan 2030 00:00:00 GMT"
    body = read(fixture, "notification.xml")

    conditional = fn request ->
      case List.keyfind(request.headers, "if-modified-since", 0) do
        {_, ^stamp} -> {304, [], ""}
        _ -> {200, [{"last-modified", stamp}], body}
      end
    end

    routes = Map.put(RRDPServer.routes(fixture), "/rrdp/notification.xml", conditional)
    server = RRDPServer.start!(routes)
    root = Path.join(dir, "cache")
    assert %{outcome: :snapshot} = sync(server, root, fixture)
    before = {store(root, fixture), State.load(root, fixture.notification_uri)}

    RRDPServer.serve(server, routes)
    later = DateTime.add(@t0, 120)
    assert %{outcome: :unchanged, serial: 3} = sync(server, root, fixture, now: later)
    assert RRDPServer.requested(server) == ["/rrdp/notification.xml"]

    {files, state} = before
    assert store(root, fixture) == files
    after_304 = State.load(root, fixture.notification_uri)

    assert Map.drop(after_304, [:last_attempt, :last_success]) ==
             Map.drop(state, [:last_attempt, :last_success])

    assert after_304.last_success == later
  end

  @tag rfc: "8182#3.4.4",
       doc: """
       Synced at T: a sync at T + 30 s and at T + 59 s makes no request
       at all and uses the store (:recent); at T + 60 s the notification
       is fetched again.
       """
  test "a second sync within a minute makes no request", %{tmp_dir: dir} do
    fixture = three()
    server = RRDPServer.start!(RRDPServer.routes(fixture))
    root = Path.join(dir, "cache")
    polite = [min_interval: 60]

    assert %{outcome: :snapshot} = sync(server, root, fixture, polite ++ [now: @t0])

    RRDPServer.serve(server, RRDPServer.routes(fixture))

    assert %{outcome: :recent, serial: 3, session_id: session} =
             sync(server, root, fixture, polite ++ [now: DateTime.add(@t0, 30)])

    assert session == fixture.session_id

    assert %{outcome: :recent} =
             sync(server, root, fixture, polite ++ [now: DateTime.add(@t0, 59)])

    assert RRDPServer.requested(server) == []

    assert %{outcome: :unchanged} =
             sync(server, root, fixture, polite ++ [now: DateTime.add(@t0, 60)])

    assert RRDPServer.requested(server) == ["/rrdp/notification.xml"]
  end

  @tag rfc: "8182#3.4.4",
       doc: "A last success later than now means the clock went back; it doesn't hold the fetch."
  test "a last success in the future doesn't stop a fetch", %{tmp_dir: dir} do
    fixture = three()
    server = RRDPServer.start!(RRDPServer.routes(fixture))
    root = Path.join(dir, "cache")

    assert %{outcome: :snapshot} = sync(server, root, fixture, min_interval: 60, now: @t0)
    RRDPServer.serve(server, RRDPServer.routes(fixture))

    assert %{outcome: :unchanged} =
             sync(server, root, fixture, min_interval: 60, now: DateTime.add(@t0, -10))

    assert RRDPServer.requested(server) == ["/rrdp/notification.xml"]
  end

  @tag rfc: "8182#3.4.4"
  test "the once-a-minute limit doesn't apply to a store never synced", %{tmp_dir: dir} do
    fixture = three()
    server = RRDPServer.start!(%{})
    root = Path.join(dir, "cache")

    assert %{outcome: {:failed, :notification_failed}} =
             sync(server, root, fixture, min_interval: 60, now: @t0)

    RRDPServer.serve(server, RRDPServer.routes(fixture))

    assert %{outcome: :snapshot} =
             sync(server, root, fixture, min_interval: 60, now: DateTime.add(@t0, 5))
  end
end
