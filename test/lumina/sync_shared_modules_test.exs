defmodule Lumina.SyncSharedModulesTest do
  @moduledoc """
  Tests that one sync fetches a module once, however many TALs' trees
  reach it (#102, D-012).

  `Lumina.Sync.run/3` walks each TAL's tree in turn and passes the
  modules each walk fetched (or failed to fetch) to the next, so a module
  shared by several trees, such as a hosted repository serving CAs under
  several RIRs, costs one rsync run per sync, and a module that failed
  isn't retried. Each tree is still walked whole. The same holds for a
  retry after a transient failure (D-039, #193): at most one per module
  per sync.

  The two "trees" here are one Barry fixture, m0-minimal-valid, served by
  a local rsync daemon, under two TAL names: everything below the TA is
  in the shared module `rsync://localhost:8873/rpki`.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Sync, TAL}
  alias Lumina.Test.{Fixture, RsyncDaemon}

  @moduletag :rsync
  @moduletag :tmp_dir
  @now ~U[2030-01-01 00:00:00Z]
  @module "rsync://localhost:8873/rpki"

  # m0-minimal-valid's TAL, at a local daemon, under each name in `names`.
  defp tals!(tmp, names) do
    fixture = Fixture.load!("m0-minimal-valid")
    daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), fixture.modules)
    authority = "127.0.0.1:#{daemon.port}"

    {:ok, tal} =
      fixture.tal_path
      |> File.read!()
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(&1, "https://"))
      |> Enum.map_join("\n", &String.replace(&1, "localhost:8873", authority))
      |> TAL.parse()

    {for(name <- names, do: {name <> ".tal", tal}), %{"localhost:8873" => authority}}
  end

  test "a module two TALs' trees share is fetched once, and both trees are walked", %{
    tmp_dir: tmp
  } do
    {tals, remap} = tals!(tmp, ["first", "second"])

    assert {:ok, [first, second]} =
             Sync.run(tals, Path.join(tmp, "cache"), now: @now, remap: remap)

    assert [%{uri: @module, outcome: :ok}] = first.walk.fetches
    assert second.walk.fetches == []

    assert [_ | _] = first.walk.points
    assert length(second.walk.points) == length(first.walk.points)

    for point <- second.walk.points do
      assert %{covered_by: @module, stale: false, status: :accepted} = point
    end

    refute first.failed? or second.failed?
  end

  @tag doc: """
       After a first sync, the shared module's host is remapped to a closed
       port: the first walk's fetch fails and its copy goes stale; the
       second walk doesn't try again and reads the same stale copy.
       """
  test "a shared module that failed isn't fetched again for the next TAL", %{tmp_dir: tmp} do
    {tals, remap} = tals!(tmp, ["first", "second"])
    cache = Path.join(tmp, "cache")
    {:ok, _} = Sync.run(tals, cache, now: @now, remap: remap)

    closed = %{"localhost:8873" => "127.0.0.1:#{RsyncDaemon.closed_port()}"}
    rsync = [contimeout: 5, timeout: 5]

    assert {:ok, [first, second]} =
             Sync.run(tals, cache, now: @now, remap: closed, rsync: rsync)

    assert [%{uri: @module, outcome: :error}] = first.walk.fetches
    assert Enum.any?(first.walk.issues, &(&1.kind == :fetch_failed))
    assert second.walk.fetches == []
    assert [_ | _] = second.walk.points
    assert Enum.all?(second.walk.points, & &1.stale)
  end

  # The remap of `tals!/2`, sent through a proxy that resets the
  # connections numbered in `drop`, or `:all`.
  defp dropping(%{"localhost:8873" => "127.0.0.1:" <> port}, drop) do
    proxy = RsyncDaemon.dropping_proxy!(String.to_integer(port), drop)
    %{"localhost:8873" => "127.0.0.1:#{proxy}"}
  end

  @tag doc: """
       Every connection to the shared module is reset: the first walk
       fetches it, retries once, and fails; the second walk neither
       fetches nor retries it.
       """
  test "a shared module is retried once per sync, not again for the next TAL", %{tmp_dir: tmp} do
    {tals, remap} = tals!(tmp, ["first", "second"])

    assert {:ok, [first, second]} =
             Sync.run(tals, Path.join(tmp, "cache"),
               now: @now,
               remap: dropping(remap, :all),
               retry_delay: 0
             )

    assert [%{uri: @module, outcome: :retried}, %{uri: @module, outcome: :error}] =
             first.walk.fetches

    assert Enum.count(first.walk.issues, &(&1.kind == :retried)) == 1
    assert second.walk.fetches == []
    refute Enum.any?(second.walk.issues, &(&1.kind == :retried))
  end

  test "the summary counts retried fetches and names the retry with its reason", %{tmp_dir: tmp} do
    {tals, remap} = tals!(tmp, ["first"])

    {:ok, [report]} =
      Sync.run(tals, Path.join(tmp, "cache"),
        now: @now,
        remap: dropping(remap, [1]),
        retry_delay: 0
      )

    summary = Sync.summary([report])

    assert summary =~ "  rsync fetches: 2, 0 failed, 1 retried\n"

    # rsync's exit 12, or 10 if the reset comes while it is still connecting.
    assert summary =~ ~r"    retried: #{@module} \((protocol_error: |socket_error\))"

    assert summary =~ "1 TAL(s), 2 rsync fetch(es), 0 TAL(s) with failures\n"
  end

  test "the summary says which modules an earlier TAL's walk fetched", %{tmp_dir: tmp} do
    {tals, remap} = tals!(tmp, ["first", "second"])
    {:ok, reports} = Sync.run(tals, Path.join(tmp, "cache"), now: @now, remap: remap)

    [first, second] = String.split(Sync.summary(reports), "second.tal")

    assert first =~ "  rsync fetches: 1, 0 failed\n"
    assert second =~ "  rsync fetches: 0, 0 failed; 1 modules fetched for an earlier TAL\n"
  end
end
