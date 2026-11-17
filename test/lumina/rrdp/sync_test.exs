defmodule Lumina.RRDP.SyncTest do
  @moduledoc """
  Syncing one RRDP repository from its snapshot (#203,
  `Lumina.RRDP.Sync.run/3`), against #202's fixtures served over HTTPS by
  `Lumina.Test.HTTPSServer`.

  A sync must leave the store holding exactly the snapshot's objects,
  byte for byte, download nothing more when the notification hasn't moved
  (RFC 8182 §3.4.1, §3.4.4), follow a new session_id whatever its serial
  but reject an older serial of the same session (§3.4.1, §3.4.3), and
  refuse cross-origin URIs and redirects (RFC 9674 §3.2). Every rejection
  must keep the last good store, so a broken or hostile server can't make
  Lumina lose the repository it already has, and record the failure in
  the state.

  The server's routes live in an Agent, so a test can change what is
  served between syncs and see which paths were requested.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Lumina.RRDP.{Snapshot, State, Store, Sync}
  alias Lumina.Test.{Fixture, HTTPSServer}
  alias Mix.Lumina.Fixtures

  @moduletag :tmp_dir
  @base "https://localhost:8443/rrdp/"
  @now ~U[2030-01-01 00:00:00Z]

  # A server whose routes (path => response) can be replaced, logging the
  # paths requested since.
  defp server(routes) do
    agent = start_supervised!({Agent, fn -> %{routes: routes, log: []} end})
    pki = HTTPSServer.pki()

    port =
      HTTPSServer.start!(pki, fn request ->
        route =
          Agent.get_and_update(agent, fn state ->
            {Map.get(state.routes, request.path, {404, [], "not found"}),
             %{state | log: state.log ++ [request.path]}}
          end)

        if is_function(route, 1), do: route.(request), else: route
      end)

    %{
      agent: agent,
      port: port,
      opts: [cacerts: pki.cacerts, remap: %{"localhost:8443" => "localhost:#{port}"}, now: @now]
    }
  end

  defp serve(server, routes), do: Agent.update(server.agent, &%{&1 | routes: routes, log: []})

  defp requested(server), do: Agent.get(server.agent, & &1.log)

  defp routes(fixture), do: HTTPSServer.dir_routes(fixture.rrdp_root, "/rrdp/")

  defp sync(server, root), do: Sync.run(notify(), root, server.opts)

  defp notify, do: Fixture.load!("m8-rrdp-delta").notification_uri

  defp hash(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  defp notification(session, serial, snapshot_uri, snapshot_hash) do
    """
    <notification xmlns="http://www.ripe.net/rpki/rrdp" version="1" \
    session_id="#{session}" serial="#{serial}">
      <snapshot uri="#{snapshot_uri}" hash="#{snapshot_hash}"/>
    </notification>
    """
  end

  # The store's files: path relative to the store => bytes.
  defp store_files(root) do
    store = Store.path(root, notify())

    for path <- Path.wildcard(Path.join(store, "**/*"), match_dot: true),
        File.regular?(path),
        into: %{},
        do: {Path.relative_to(path, store), File.read!(path)}
  end

  # The objects of a fixture's snapshot (serial K's, or the last), as the
  # store lays them out.
  defp snapshot_files(fixture, file \\ "snapshot.xml") do
    path = Path.join(fixture.rrdp_root, file)
    xml = File.read!(path)
    [_, serial] = Regex.run(~r/serial="(\d+)"/, xml)
    expected = %{session_id: fixture.session_id, serial: String.to_integer(serial)}

    collect = fn {:publish, uri, bytes}, acc ->
      {:cont, Map.put(acc, Path.relative_to(Store.object_path("/s", uri), "/s"), bytes)}
    end

    {:ok, files} = Snapshot.stream(path, expected, collect, %{})
    files
  end

  # A cache synced to m8-rrdp-delta's serial 2, and its store's files.
  defp synced(dir) do
    fixture = Fixture.load!("m8-rrdp-delta")
    server = server(routes(fixture))
    root = Path.join(dir, "cache")
    assert %{outcome: :snapshot, serial: 2} = sync(server, root)
    {server, root, store_files(root)}
  end

  # The failure left the store and its serial as they were, and recorded
  # the attempt.
  defp assert_kept(root, before, reason) do
    assert store_files(root) == before
    state = State.load(root, notify())
    assert state.serial == 2
    assert state.session_id == Fixtures.session_id("m8-rrdp-delta")
    assert {:error, text} = state.outcome
    assert text =~ "#{reason}"
  end

  @tag rfc: ["8182#3.4.3", "8182#3.5.2.3"],
       doc: """
       Every Barry fixture's repository, each into a fresh cache. The store
       must hold exactly the snapshot's objects, and they must be the files
       of the fixture's rsync tree (less the TA certificate, which isn't
       published in the repository), byte for byte.
       """
  test "a fresh cache syncs every fixture's repository, and the store holds its rsync tree's files",
       %{tmp_dir: dir} do
    {fixtures, _} = Fixtures.load_all()
    server = server(%{})

    for %{id: id} <- fixtures do
      fixture = Fixture.load!(id)
      serve(server, routes(fixture))
      root = Path.join(dir, id)

      result = sync(server, root)
      expected = snapshot_files(fixture)

      assert result.outcome == :snapshot, id
      assert result.session_id == fixture.session_id, id
      assert result.serial == map_size(fixture.versions), id
      assert result.objects == map_size(expected), id
      assert result.error == nil
      assert store_files(root) == expected, id

      rsync =
        for path <- Path.wildcard(Path.join(fixture.rsync_root, "**/*")),
            File.regular?(path),
            path != Path.join(fixture.rsync_root, "ta.cer"),
            do: File.read!(path)

      assert Enum.sort(Map.values(store_files(root))) == Enum.sort(rsync), id

      state = State.load(root, notify())

      assert {state.session_id, state.serial, state.outcome} ==
               {fixture.session_id, result.serial, :ok}

      assert state.last_success == @now
    end
  end

  @tag rfc: "8182#3.4.1"
  test "a second sync of the same notification downloads only the notification", %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    serve(server, routes(Fixture.load!("m8-rrdp-delta")))

    assert %{outcome: :unchanged, serial: 2, objects: nil} = sync(server, root)
    assert requested(server) == ["/rrdp/notification.xml"]
    assert store_files(root) == before
  end

  @tag rfc: "8182#3.4.4",
       doc: """
       The notification's Last-Modified is saved with a successful sync and
       sent as If-Modified-Since on the next; a 304 is unchanged.
       """
  test "a 304 to If-Modified-Since leaves the repository unchanged", %{tmp_dir: dir} do
    fixture = Fixture.load!("m8-rrdp-delta")
    stamp = "Wed, 01 Jan 2030 00:00:00 GMT"
    body = File.read!(Path.join(fixture.rrdp_root, "notification.xml"))

    conditional = fn request ->
      case List.keyfind(request.headers, "if-modified-since", 0) do
        {_, ^stamp} -> {304, [], ""}
        _ -> {200, [{"last-modified", stamp}], body}
      end
    end

    server = server(Map.put(routes(fixture), "/rrdp/notification.xml", conditional))
    root = Path.join(dir, "cache")

    assert %{outcome: :snapshot} = sync(server, root)
    assert State.load(root, notify()).last_modified == stamp

    serve(server, Map.put(routes(fixture), "/rrdp/notification.xml", conditional))
    assert %{outcome: :unchanged, serial: 2} = sync(server, root)
    assert requested(server) == ["/rrdp/notification.xml"]
  end

  @tag rfc: "8182#3.4.1",
       doc: """
       The state names serial 2, but its store is gone: the repository is
       synced from its snapshot again rather than reported unchanged.
       """
  test "a missing store is synced again from the snapshot", %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    File.rm_rf!(Store.path(root, notify()))

    assert %{outcome: :snapshot, serial: 2} = sync(server, root)
    assert store_files(root) == before
  end

  @tag rfc: "8182#3.4.1",
       doc: """
       m0-minimal-valid's notification, at the same URI, has another
       session_id and serial 1, below the store's 2. A new session is
       processed from its snapshot whatever its serial.
       """
  test "a new session with a lower serial is accepted, and its session recorded", %{tmp_dir: dir} do
    {server, root, _before} = synced(dir)
    other = Fixture.load!("m0-minimal-valid")
    serve(server, routes(other))

    assert %{outcome: :snapshot, session_id: session, serial: 1} = sync(server, root)
    assert session == other.session_id
    assert store_files(root) == snapshot_files(other)
    assert %{session_id: ^session, serial: 1} = State.load(root, notify())
  end

  @tag rfc: "8182#3.4.3"
  test "the same session with a lower serial is rejected without downloading the snapshot",
       %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    fixture = Fixture.load!("m8-rrdp-delta")

    serve(
      server,
      Map.put(
        routes(fixture),
        "/rrdp/notification.xml",
        {:file, Path.join(fixture.rrdp_root, "notification-1.xml")}
      )
    )

    assert %{outcome: {:failed, :serial_not_greater}, serial: 2, error: error} =
             sync(server, root)

    assert error.rule == :serial_not_greater
    assert requested(server) == ["/rrdp/notification.xml"]
    assert_kept(root, before, :serial_not_greater)
  end

  @tag rfc: "8182#3.4.3"
  test "a snapshot whose hash isn't the notification's is rejected and the store kept",
       %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    session = Fixtures.session_id("m8-rrdp-delta")
    snapshot = File.read!(Path.join(Fixture.load!("m8-rrdp-delta").rrdp_root, "snapshot.xml"))

    serve(server, %{
      "/rrdp/notification.xml" =>
        {200, [], notification(session, 3, @base <> "s3.xml", hash("something else"))},
      "/rrdp/s3.xml" => {200, [], snapshot}
    })

    assert %{outcome: {:failed, :snapshot_hash_mismatch}} = sync(server, root)
    assert_kept(root, before, :snapshot_hash_mismatch)
  end

  @tag rfc: "8182#3.5.2.3",
       doc: "m0-minimal-valid's snapshot, announced under m8-rrdp-delta's session_id."
  test "a snapshot of another session_id than the notification's is rejected and the store kept",
       %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    session = Fixtures.session_id("m8-rrdp-delta")
    other = File.read!(Path.join(Fixture.load!("m0-minimal-valid").rrdp_root, "snapshot.xml"))

    serve(server, %{
      "/rrdp/notification.xml" =>
        {200, [], notification(session, 3, @base <> "s3.xml", hash(other))},
      "/rrdp/s3.xml" => {200, [], other}
    })

    assert %{outcome: {:failed, :snapshot_rejected}, error: %{rule: :session_mismatch}} =
             sync(server, root)

    assert_kept(root, before, :snapshot_rejected)
  end

  @tag rfc: "8182#3.5.2.3", doc: "m8-rrdp-delta's serial 2 snapshot, announced as serial 3."
  test "a snapshot of another serial than the notification's is rejected and the store kept",
       %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    session = Fixtures.session_id("m8-rrdp-delta")
    snapshot = File.read!(Path.join(Fixture.load!("m8-rrdp-delta").rrdp_root, "snapshot.xml"))

    serve(server, %{
      "/rrdp/notification.xml" =>
        {200, [], notification(session, 3, @base <> "s3.xml", hash(snapshot))},
      "/rrdp/s3.xml" => {200, [], snapshot}
    })

    assert %{outcome: {:failed, :snapshot_rejected}, error: %{rule: :serial_mismatch}} =
             sync(server, root)

    assert_kept(root, before, :snapshot_rejected)
  end

  @tag rfc: "8182#3.5.2.3",
       doc: "The first half of a snapshot, with its hash in the notification."
  test "a truncated snapshot is rejected and the store kept", %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    session = Fixtures.session_id("m8-rrdp-delta")
    snapshot = File.read!(Path.join(Fixture.load!("m8-rrdp-delta").rrdp_root, "snapshot.xml"))
    half = binary_part(snapshot, 0, div(byte_size(snapshot), 2))
    half = String.replace(half, ~r/serial="2"/, ~s(serial="3"))

    serve(server, %{
      "/rrdp/notification.xml" =>
        {200, [], notification(session, 3, @base <> "s3.xml", hash(half))},
      "/rrdp/s3.xml" => {200, [], half}
    })

    assert %{outcome: {:failed, :snapshot_rejected}} = sync(server, root)
    assert_kept(root, before, :snapshot_rejected)
  end

  @tag rfc: "8182#3.5.2.3",
       doc: """
       RFC 8182 doesn't say a URI appears once in a snapshot, but one
       published twice has no single content (F-041).
       """
  test "a snapshot publishing one URI twice is rejected and the store kept", %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    session = Fixtures.session_id("m8-rrdp-delta")

    snapshot = """
    <snapshot xmlns="http://www.ripe.net/rpki/rrdp" version="1" session_id="#{session}" serial="3">
      <publish uri="rsync://localhost:8873/rpki/a.cer">AAAA</publish>
      <publish uri="rsync://localhost:8873/rpki/a.cer">BBBB</publish>
    </snapshot>
    """

    serve(server, %{
      "/rrdp/notification.xml" =>
        {200, [], notification(session, 3, @base <> "s3.xml", hash(snapshot))},
      "/rrdp/s3.xml" => {200, [], snapshot}
    })

    assert %{outcome: {:failed, :snapshot_rejected}, error: %{rule: :duplicate_publish}} =
             sync(server, root)

    assert_kept(root, before, :snapshot_rejected)
  end

  @tag rfc: "9674#3.2"
  test "a cross-origin snapshot URI rejects the notification and the store is kept",
       %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    session = Fixtures.session_id("m8-rrdp-delta")
    elsewhere = "https://elsewhere.example/rrdp/snapshot.xml"

    serve(server, %{
      "/rrdp/notification.xml" => {200, [], notification(session, 3, elsewhere, hash("x"))}
    })

    log =
      capture_log(fn ->
        assert %{outcome: {:failed, :cross_origin}, error: %{rule: :cross_origin}} =
                 sync(server, root)
      end)

    assert log =~ "elsewhere.example"
    assert requested(server) == ["/rrdp/notification.xml"]
    assert_kept(root, before, :cross_origin)
  end

  @tag rfc: "9674#3.2"
  test "a cross-origin redirect of the notification is refused and the store kept",
       %{tmp_dir: dir} do
    {server, root, before} = synced(dir)

    serve(server, %{
      "/rrdp/notification.xml" =>
        {302, [{"location", "https://localhost:9443/rrdp/notification.xml"}], ""}
    })

    log =
      capture_log(fn ->
        assert %{outcome: {:failed, :cross_origin}, error: %{reason: :cross_origin_redirect}} =
                 sync(server, root)
      end)

    assert log =~ "RFC 9674"
    assert_kept(root, before, :cross_origin)
  end

  @tag rfc: "9674#3.2",
       doc: "The snapshot redirects to another host on the same port: another origin."
  test "a cross-origin redirect of the snapshot is refused and the store kept", %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    session = Fixtures.session_id("m8-rrdp-delta")

    serve(server, %{
      "/rrdp/notification.xml" =>
        {200, [], notification(session, 3, @base <> "s3.xml", hash("x"))},
      "/rrdp/s3.xml" => {302, [{"location", "https://127.0.0.1:8443/rrdp/s3.xml"}], ""}
    })

    log =
      capture_log(fn ->
        assert %{outcome: {:failed, :cross_origin}, error: %{reason: :cross_origin_redirect}} =
                 sync(server, root)
      end)

    assert log =~ "RFC 9674"
    assert_kept(root, before, :cross_origin)
  end

  @tag rfc: "9674#3.2"
  test "a same-origin redirect of the snapshot is followed", %{tmp_dir: dir} do
    fixture = Fixture.load!("m8-rrdp-delta")

    server =
      server(
        routes(fixture)
        |> Map.put("/rrdp/snapshot.xml", {302, [{"location", "/rrdp/moved/snapshot.xml"}], ""})
        |> Map.put(
          "/rrdp/moved/snapshot.xml",
          {:file, Path.join(fixture.rrdp_root, "snapshot.xml")}
        )
      )

    root = Path.join(dir, "cache")
    assert %{outcome: :snapshot, serial: 2} = sync(server, root)
    assert store_files(root) == snapshot_files(fixture)
  end

  test "a missing snapshot fails the sync and the store is kept", %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    session = Fixtures.session_id("m8-rrdp-delta")

    serve(server, %{
      "/rrdp/notification.xml" =>
        {200, [], notification(session, 3, @base <> "s3.xml", hash("x"))}
    })

    assert %{outcome: {:failed, :snapshot_failed}, error: %{reason: :http_status, detail: 404}} =
             sync(server, root)

    assert_kept(root, before, :snapshot_failed)
  end

  test "a missing notification fails the sync and the store is kept", %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    serve(server, %{})

    assert %{outcome: {:failed, :notification_failed}, error: %{reason: :http_status}} =
             sync(server, root)

    assert_kept(root, before, :notification_failed)
  end

  @tag rfc: "8182#3.4.1"
  test "a notification that doesn't check is rejected and the store kept", %{tmp_dir: dir} do
    {server, root, before} = synced(dir)
    session = Fixtures.session_id("m8-rrdp-delta")

    bad =
      String.replace(
        notification(session, 3, @base <> "s3.xml", hash("x")),
        ~s(version="1"),
        ~s(version="2")
      )

    serve(server, %{"/rrdp/notification.xml" => {200, [], bad}})

    assert %{outcome: {:failed, :notification_rejected}} = sync(server, root)
    assert requested(server) == ["/rrdp/notification.xml"]
    assert_kept(root, before, :notification_rejected)
  end

  test "a first sync that fails leaves no store, and records the attempt", %{tmp_dir: dir} do
    server = server(%{})
    root = Path.join(dir, "cache")

    assert %{outcome: {:failed, :notification_failed}, session_id: nil, serial: nil} =
             sync(server, root)

    refute File.exists?(Store.path(root, notify()))

    assert %{serial: nil, last_attempt: @now, last_success: nil, outcome: {:error, _}} =
             State.load(root, notify())
  end

  @tag doc: """
       D-036: the run is reported to the :progress function, from start to
       finish, with the files downloaded and the objects written.
       """
  test "a sync reports its progress", %{tmp_dir: dir} do
    fixture = Fixture.load!("m8-rrdp-delta")
    server = server(routes(fixture))
    test = self()
    opts = Keyword.put(server.opts, :progress, &send(test, {:event, &1}))
    notify = notify()
    notification_size = File.stat!(Path.join(fixture.rrdp_root, "notification.xml")).size
    snapshot_size = File.stat!(Path.join(fixture.rrdp_root, "snapshot.xml")).size
    count = map_size(snapshot_files(fixture))

    Sync.run(notify, Path.join(dir, "cache"), opts)

    events = collect([])

    assert events == [
             {:rrdp_started, notify},
             {:rrdp_downloaded, notify, :notification, notification_size},
             {:rrdp_downloaded, notify, :snapshot, snapshot_size},
             {:rrdp_objects, notify, count},
             {:rrdp_finished, notify, :snapshot}
           ]
  end

  defp collect(acc) do
    receive do
      {:event, event} -> collect([event | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end
