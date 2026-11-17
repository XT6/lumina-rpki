defmodule Lumina.WalkRRDPTest do
  @moduledoc """
  RRDP in the repository walk (#206, D-040): a CA whose certificate names
  an HTTPS rpkiNotify is synced over RRDP (`Lumina.RRDP.Sync`) and its
  publication point read from the repository's store; when RRDP fails,
  the CA's rsync module is fetched in the same run and the point read
  from rsync (RFC 8182 §3.4.5).

  Every Barry fixture names `https://localhost:8443/rrdp/notification.xml`
  in its certificates; `Lumina.Test.RRDPServer` serves the fixture's
  `rrdp/` there (through `:remap`), and `Lumina.Test.RsyncDaemon` its
  rsync modules as `localhost:8873` where a test needs rsync. The unit of
  fetching over RRDP is the notification URI: synced once per run (and,
  through `:fetched`, once per sync) however many CAs name it. RRDP and
  rsync must give the same walk: the same points, verdicts and objects.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Lumina.{Certificate, Object, Source, TAL, Walk}
  alias Lumina.Test.{Fixture, RRDPServer, RsyncDaemon}
  alias Mix.Lumina.Fixtures

  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]
  @module "rsync://localhost:8873/rpki"
  @notify "https://localhost:8443/rrdp/notification.xml"
  @rrdp_kinds [:rrdp_failed, :rrdp_fallback, :rrdp_warning]

  defp ta!(fixture) do
    {:ok, %Object{value: %Certificate{} = cert}} =
      Object.decode_file(Path.join(fixture.rsync_root, "ta.cer"))

    cert
  end

  # Walk options with RRDP on, served by `server`, and rsync remapped to
  # `rsync` ("host:port"; a closed port when the test serves no rsync).
  defp opts(server, rsync, extra \\ []) do
    remap = Map.put(server.opts[:remap], "localhost:8873", rsync)

    [
      now: @now,
      rrdp: true,
      remap: remap,
      rrdp_opts: Keyword.take(server.opts, [:cacerts, :min_interval]),
      retry_delay: 0
    ] ++ extra
  end

  defp closed, do: "127.0.0.1:#{RsyncDaemon.closed_port()}"

  defp daemon!(dir, fixture) do
    daemon = RsyncDaemon.start!(Path.join(dir, "rsyncd"), fixture.modules)
    "127.0.0.1:#{daemon.port}"
  end

  defp kinds(result), do: Enum.map(result.issues, & &1.kind)

  # A point's files, path relative to the point => bytes.
  defp files(point) do
    for path <- Path.wildcard(Path.join(point.path, "**/*"), match_dot: true),
        File.regular?(path),
        into: %{},
        do: {Path.relative_to(path, point.path), File.read!(path)}
  end

  defp source(point), do: elem(point.source, 0)

  @tag rfc: ["8182#3.4.1", "8182#3.4.3"],
       doc: """
       m3-walk-nested (a CA's point nested in the TA's) over HTTPS only:
       every rsync connection would fail (closed port). Every point is read from the RRDP store, the one
       repository is synced from its snapshot, and no rsync runs.
       """
  test "a fixture served only over HTTPS is walked completely over RRDP", %{tmp_dir: dir} do
    fixture = Fixture.load!("m3-walk-nested")
    server = RRDPServer.start!(RRDPServer.routes(fixture))
    cache = Path.join(dir, "cache")

    result = Walk.run(ta!(fixture), cache, opts(server, closed()))

    assert result.fetches == []
    assert [%{outcome: :snapshot}] = result.rrdp

    assert [%{uri: @module <> "/ta", depth: 0}, %{uri: @module <> "/ta/ca1", depth: 1}] =
             result.points

    assert Enum.all?(result.points, &(&1.status == :accepted and not &1.stale))
    assert Enum.all?(result.points, &(source(&1) == :rrdp))
    assert Enum.all?(result.points, &(&1.covered_by == @notify))
    refute Enum.any?(kinds(result), &(&1 in [:fetch_failed, :missing, :point_failed]))

    # Each accepted point's source is recorded for offline validation.
    ta = ta!(fixture)
    {:ok, pp} = Walk.repository(ta)
    assert %{source: {:rrdp, notify}} = Source.load(cache, Walk.point_key(ta, pp))
    assert to_string(notify) == @notify
  end

  # The fixture over RRDP with `routes` replacing the good ones, and over
  # rsync; RRDP fails, and the walk falls back to rsync.
  defp fallback(dir, routes) do
    fixture = Fixture.load!("m3-walk-nested")
    server = RRDPServer.start!(Map.merge(RRDPServer.routes(fixture), routes))
    rsync = daemon!(dir, fixture)
    Walk.run(ta!(fixture), Path.join(dir, "cache"), opts(server, rsync))
  end

  defp assert_fell_back(result, reason) do
    assert [%{kind: :rrdp_failed, uri: @notify, detail: %{reason: ^reason}}] =
             Enum.filter(result.issues, &(&1.kind == :rrdp_failed))

    assert [%{kind: :rrdp_fallback, uri: @module, detail: %{notify: @notify}}] =
             Enum.filter(result.issues, &(&1.kind == :rrdp_fallback))

    assert [%{uri: @module, outcome: :ok}] = result.fetches
    assert Enum.all?(result.points, &(&1.status == :accepted and source(&1) == :rsync))
    refute Enum.any?(kinds(result), &(&1 in [:fetch_failed, :missing, :point_failed]))
  end

  @tag :rsync
  @tag rfc: "8182#3.4.5", doc: "D-040: the notification is a 404; the module is fetched instead."
  test "an unreachable notification falls back to rsync in the same run", %{tmp_dir: dir} do
    result = fallback(dir, %{"/rrdp/notification.xml" => {404, [], "gone"}})
    assert_fell_back(result, :notification_failed)
  end

  @tag :rsync
  @tag rfc: ["8182#3.4.3", "8182#3.4.5"]
  test "a rejected snapshot falls back to rsync in the same run", %{tmp_dir: dir} do
    result = fallback(dir, %{"/rrdp/snapshot.xml" => {200, [], "<snapshot/>"}})
    assert_fell_back(result, :snapshot_hash_mismatch)
  end

  @tag :rsync
  @tag rfc: ["9674#3.2", "8182#3.4.5"]
  test "a cross-origin redirect falls back to rsync in the same run", %{tmp_dir: dir} do
    log =
      capture_log(fn ->
        result =
          fallback(dir, %{
            "/rrdp/snapshot.xml" =>
              {302, [{"location", "https://127.0.0.1:8443/rrdp/snapshot.xml"}], ""}
          })

        assert_fell_back(result, :cross_origin)
      end)

    assert log =~ "RFC 9674"
  end

  @tag :rsync
  @tag rfc: "8182#3.4.5",
       doc: """
       The store from a first run's RRDP sync is kept when the next run's
       RRDP fails; that run reads from rsync.
       """
  test "a failed sync keeps the last good store", %{tmp_dir: dir} do
    fixture = Fixture.load!("m3-walk-nested")
    server = RRDPServer.start!(RRDPServer.routes(fixture))
    cache = Path.join(dir, "cache")
    first = Walk.run(ta!(fixture), cache, opts(server, closed()))
    before = Enum.map(first.points, &files/1)

    RRDPServer.serve(server, %{})
    second = Walk.run(ta!(fixture), cache, opts(server, daemon!(dir, fixture)))
    assert Enum.all?(second.points, &(source(&1) == :rsync))
    assert Enum.map(first.points, &files/1) == before
  end

  @tag doc: """
       m3-walk-siblings: eight CAs under the TA, each in its own rsync
       module, all naming one notification URI. It is synced once, and its
       notification and snapshot are each requested once.
       """
  test "a repository many CAs name is synced once", %{tmp_dir: dir} do
    fixture = Fixture.load!("m3-walk-siblings")
    server = RRDPServer.start!(RRDPServer.routes(fixture))

    result = Walk.run(ta!(fixture), Path.join(dir, "cache"), opts(server, closed()))

    assert length(result.points) == 9
    assert [%{outcome: :snapshot}] = result.rrdp
    assert RRDPServer.requested(server) == ["/rrdp/notification.xml", "/rrdp/snapshot.xml"]
  end

  @tag doc: """
       Two TALs for the same TA in one `Lumina.Sync.run/3`: the second
       walk is passed the first's `:fetched` (#102), so the repository is
       synced once per sync.
       """
  test "two TALs sharing a repository sync it once per sync", %{tmp_dir: dir} do
    fixture = Fixture.load!("m3-walk-siblings")
    server = RRDPServer.start!(RRDPServer.routes(fixture))
    {:ok, tal} = TAL.decode_file(fixture.tal_path)
    tals = [{"first.tal", tal}, {"second.tal", tal}]
    https = [cacerts: server.opts[:cacerts], remap: server.opts[:remap]]

    assert {:ok, [first, second]} =
             Lumina.Sync.run(tals, Path.join(dir, "cache"), opts(server, closed(), https: https))

    assert [%{outcome: :snapshot}] = first.walk.rrdp
    assert second.walk.rrdp == []
    assert length(second.walk.points) == 9
    assert Enum.all?(second.walk.points, &(source(&1) == :rrdp))

    assert Enum.count(RRDPServer.requested(server), &(&1 == "/rrdp/notification.xml")) == 1

    summary = Lumina.Sync.summary([first, second])
    assert summary =~ "  rrdp repositories: 1 (1 snapshot)\n"
    assert summary =~ "2 TAL(s), 0 rsync fetch(es), 1 RRDP repository, 0 TAL(s) with failures"
  end

  @tag :rsync
  test "with RRDP off nothing is fetched over HTTPS", %{tmp_dir: dir} do
    fixture = Fixture.load!("m3-walk-nested")
    server = RRDPServer.start!(RRDPServer.routes(fixture))

    result =
      Walk.run(
        ta!(fixture),
        Path.join(dir, "cache"),
        Keyword.put(opts(server, daemon!(dir, fixture)), :rrdp, false)
      )

    assert RRDPServer.requested(server) == []
    assert result.rrdp == []
    assert [%{uri: @module, outcome: :ok}] = result.fetches
    assert Enum.all?(result.points, &(source(&1) == :rsync))
  end

  @tag rfc: "8182#3.4.1",
       doc: """
       D-039: the first notification response is cut short (:truncated),
       the sync is tried once more and succeeds; the walk reports the
       retry and reads from RRDP.
       """
  test "an RRDP sync whose connection dropped is retried once", %{tmp_dir: dir} do
    fixture = Fixture.load!("m3-walk-nested")
    {:ok, counter} = Agent.start_link(fn -> 0 end)
    good = {:file, Path.join(fixture.rrdp_root, "notification.xml")}

    flaky = fn _request ->
      case Agent.get_and_update(counter, &{&1, &1 + 1}) do
        0 -> {:raw, "HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n<notif"}
        _ -> good
      end
    end

    server =
      RRDPServer.start!(Map.put(RRDPServer.routes(fixture), "/rrdp/notification.xml", flaky))

    result = Walk.run(ta!(fixture), Path.join(dir, "cache"), opts(server, closed()))

    assert [%{outcome: :snapshot}] = result.rrdp

    assert [%{kind: :retried, uri: @notify, detail: %{reason: :truncated}}] =
             Enum.filter(result.issues, &(&1.kind == :retried))

    assert Enum.all?(result.points, &(source(&1) == :rrdp))
  end

  @tag :rsync
  @tag rfc: ["8182#3.4.3", "6481#5"],
       doc: """
       Every positive fixture walked twice, over RRDP only and over rsync
       only: the same points (URI, depth, status), the same issues, and
       each point's files byte for byte. m3-walk-delegation,
       m3-walk-silent-branch and m3-walk-unreachable are left out: they
       name rsync hosts other than localhost:8873, which this test doesn't
       serve, while their RRDP repository holds every object.
       """
  test "for every positive fixture, an RRDP walk equals an rsync walk", %{tmp_dir: dir} do
    {fixtures, _} = Fixtures.load_all()
    others = ["m3-walk-delegation", "m3-walk-silent-branch", "m3-walk-unreachable"]

    for %{id: id, expected: :valid} <- fixtures, id not in others do
      fixture = Fixture.load!(id)
      server = RRDPServer.start!(RRDPServer.routes(fixture))
      base = Path.join(dir, id)

      rrdp = Walk.run(ta!(fixture), Path.join(base, "rrdp"), opts(server, closed()))

      rsync =
        Walk.run(
          ta!(fixture),
          Path.join(base, "rsync"),
          Keyword.put(opts(server, daemon!(base, fixture)), :rrdp, false)
        )

      shape = fn result -> Enum.map(result.points, &{&1.uri, &1.depth, &1.status, &1.stale}) end

      issues = fn result ->
        for i <- result.issues, i.kind not in @rrdp_kinds, do: {i.kind, i.uri}
      end

      assert shape.(rrdp) == shape.(rsync), id
      assert issues.(rrdp) == issues.(rsync), id
      assert Enum.map(rrdp.points, &files/1) == Enum.map(rsync.points, &files/1), id
      assert Enum.all?(rrdp.points, &(source(&1) == :rrdp)), id
      assert rrdp.fetches == [], id
    end
  end
end
