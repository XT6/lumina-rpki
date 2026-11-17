defmodule Lumina.ValidateSourceTest do
  @moduledoc """
  Offline validation reads each publication point from where the last
  sync read it (#207): the RRDP store or the rsync tree (`Lumina.Source`,
  recorded by the walk, #206). A sync can switch a CA between the two
  (D-040), so validating from the rsync tree alone would miss everything
  synced over RRDP, and reading an old RRDP store after a fallback would
  validate a copy the sync didn't see. A cache synced before RRDP has no
  records and validates from rsync, as before.

  Each test syncs a fixture with `Lumina.Sync.run/3` (the TA over HTTPS
  from `Lumina.Test.RRDPServer`, the repository over RRDP or from a
  `Lumina.Test.RsyncDaemon`), then runs `Lumina.Validate.run/3`.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Source, TAL, Validate, Walk}
  alias Lumina.Test.{Fixture, RRDPServer, RsyncDaemon}

  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]

  defp closed, do: "127.0.0.1:#{RsyncDaemon.closed_port()}"

  defp daemon!(dir, fixture) do
    daemon = RsyncDaemon.start!(Path.join(dir, "rsyncd"), fixture.modules)
    "127.0.0.1:#{daemon.port}"
  end

  # Syncs `fixture` into `cache`: the TA over HTTPS from `server`, the
  # repository over RRDP (`rrdp: true`) or rsync from `rsync`.
  defp sync!(fixture, cache, server, rsync, rrdp) do
    {:ok, tal} = TAL.decode_file(fixture.tal_path)

    opts = [
      now: @now,
      rrdp: rrdp,
      remap: Map.put(server.opts[:remap], "localhost:8873", rsync),
      rrdp_opts: Keyword.take(server.opts, [:cacerts, :min_interval]),
      https: [cacerts: server.opts[:cacerts], remap: server.opts[:remap]]
    ]

    {:ok, [report]} = Lumina.Sync.run([{"case.tal", tal}], cache, opts)
    {tal, report}
  end

  defp validate!(tal, cache) do
    {:ok, result} = Validate.run(tal, cache, now: @now, name: "case")
    result
  end

  # What validation concluded, without where it read from.
  defp verdicts(result),
    do: {Enum.map(result.objects, &{&1.uri, &1[:type], &1[:valid]}), result.vrps}

  defp transports(result), do: result.points |> Enum.map(&elem(&1.source, 0)) |> Enum.uniq()

  @tag :rsync
  @tag doc: """
       m3-walk-siblings synced over RRDP only (rsync unreachable) and,
       into another cache, over rsync only. Validation gives the same
       objects, verdicts and VRPs, and reads every point from the RRDP
       store in the first cache, which has no rsync tree at all.
       """
  test "a repository synced over RRDP validates as when synced over rsync", %{tmp_dir: dir} do
    fixture = Fixture.load!("m3-walk-siblings")
    server = RRDPServer.start!(RRDPServer.routes(fixture))
    rrdp_cache = Path.join(dir, "rrdp")
    rsync_cache = Path.join(dir, "rsync")

    {tal, _} = sync!(fixture, rrdp_cache, server, closed(), true)
    sync!(fixture, rsync_cache, server, daemon!(dir, fixture), false)

    over_rrdp = validate!(tal, rrdp_cache)
    over_rsync = validate!(tal, rsync_cache)

    assert verdicts(over_rrdp) == verdicts(over_rsync)
    assert over_rrdp.vrps != []
    assert length(over_rrdp.points) == 9
    assert transports(over_rrdp) == [:rrdp]
    assert transports(over_rsync) == [:rsync]
    refute File.exists?(Path.join(rrdp_cache, "rsync"))

    summary = Validate.summary([{"case.tal", {:ok, over_rrdp}}], @now)
    assert summary =~ "  publication points: 9: 9 from RRDP, 0 from rsync\n"
  end

  @tag :rsync
  @tag rfc: "8182#3.4.5",
       doc: """
       A first sync over RRDP leaves a store. The next one finds the
       notification gone and falls back to rsync (D-040). Validation then
       reads rsync: the old store's files are removed to show they aren't
       read, and the results stand.
       """
  test "after a sync that fell back to rsync, validation reads rsync", %{tmp_dir: dir} do
    fixture = Fixture.load!("m0-minimal-valid")
    server = RRDPServer.start!(RRDPServer.routes(fixture))
    cache = Path.join(dir, "cache")

    {tal, _} = sync!(fixture, cache, server, closed(), true)
    first = validate!(tal, cache)
    assert transports(first) == [:rrdp]

    RRDPServer.serve(server, Map.delete(RRDPServer.routes(fixture), "/rrdp/notification.xml"))
    {_, report} = sync!(fixture, cache, server, daemon!(dir, fixture), true)
    assert Enum.any?(report.walk.issues, &(&1.kind == :rrdp_fallback))

    {:ok, notify} = Walk.notify_uri(fixture |> ta())
    store = Lumina.RRDP.Store.path(cache, notify)
    assert File.dir?(store)

    for path <- Path.wildcard(Path.join(store, "**/*")), File.regular?(path), do: File.rm!(path)

    second = validate!(tal, cache)
    assert transports(second) == [:rsync]
    assert verdicts(second) == verdicts(first)
  end

  @tag :rsync
  @tag doc: """
       A cache synced before RRDP: rsync only, and no source records
       (removed here). Every point is read from rsync and the results are
       those of a cache with the records.
       """
  test "a cache synced before RRDP validates from rsync, as before", %{tmp_dir: dir} do
    fixture = Fixture.load!("m0-minimal-valid")
    server = RRDPServer.start!(RRDPServer.routes(fixture))
    cache = Path.join(dir, "cache")

    {tal, _} = sync!(fixture, cache, server, daemon!(dir, fixture), false)
    with_records = validate!(tal, cache)

    File.rm_rf!(Path.join([cache, ".state", "sources"]))
    without = validate!(tal, cache)

    assert transports(without) == [:rsync]
    assert verdicts(without) == verdicts(with_records)
    assert without.vrps != []
  end

  @tag doc: """
       The record says RRDP, but the store is gone (or the CA no longer
       names that notification URI): the point is looked for in the rsync
       tree, never in a store the certificate doesn't lead to.
       """
  test "a point recorded as RRDP whose store is gone resolves to the rsync tree",
       %{tmp_dir: dir} do
    fixture = Fixture.load!("m0-minimal-valid")
    ta = ta(fixture)
    {:ok, pp} = Walk.repository(ta)
    {:ok, notify} = Walk.notify_uri(ta)
    {:ok, other} = Lumina.URI.parse("https://other.example/notification.xml")
    key = Walk.point_key(ta, pp)
    {:ok, module} = Lumina.URI.module(pp)

    :ok = Source.save(dir, key, {:rrdp, notify}, @now)
    assert Source.resolve(dir, ta, pp) == {Lumina.Cache.path(dir, pp), {:rsync, module}}

    File.mkdir_p!(Lumina.RRDP.Store.path(dir, notify))
    assert Source.resolve(dir, ta, pp) == {Source.path(dir, {:rrdp, notify}, pp), {:rrdp, notify}}

    :ok = Source.save(dir, key, {:rrdp, other}, @now)
    File.mkdir_p!(Lumina.RRDP.Store.path(dir, other))
    assert Source.resolve(dir, ta, pp) == {Lumina.Cache.path(dir, pp), {:rsync, module}}
  end

  defp ta(fixture) do
    {:ok, %Lumina.Object{value: cert}} =
      Lumina.Object.decode_file(Path.join(fixture.rsync_root, "ta.cer"))

    cert
  end
end
