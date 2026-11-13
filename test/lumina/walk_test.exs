defmodule Lumina.WalkTest do
  @moduledoc """
  Tests the repository walk (`Lumina.Walk`, #75) against real rsync
  daemons serving Barry fixtures: from the TA, every publication point
  reached through CA certificates is mirrored into the cache (RFC 6481 §5),
  each fetched at most once per run, with publication points nested in a
  fetched directory read from that copy (D-009).

  The `m3-walk-*` fixtures each exercise one part of the walk: a
  delegation to a second rsync host, a nested publication point, an SIA
  loop, a deep chain and an unreachable host. The fixtures name
  `localhost:8873` (and `other.example:8873`), so each test remaps those
  to its own daemons with `:remap`; cache paths and reports keep the names
  from the certificates.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Cache, Certificate, Object, URI, Walk}
  alias Lumina.Test.{Fixture, RsyncDaemon}
  alias Mix.Lumina.Fixtures

  @moduletag :rsync
  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]
  @base "rsync://localhost:8873/rpki"

  defp ta!(id) do
    {:ok, %Object{value: %Certificate{} = cert}} =
      Object.decode_file(Path.join(Fixture.load!(id).rsync_root, "ta.cer"))

    cert
  end

  defp serve(tmp, name, dir) do
    daemon = RsyncDaemon.start!(Path.join(tmp, name), %{name => dir})
    "127.0.0.1:#{daemon.port}"
  end

  # Serves the fixture's rsync tree as localhost:8873/rpki, and walks it.
  defp walk!(tmp, id, opts \\ []) do
    remap = Map.put(opts[:remap] || %{}, "localhost:8873", serve(tmp, "rpki", rsync_root(id)))
    Walk.run(ta!(id), cache(tmp), [now: @now, remap: remap] ++ Keyword.delete(opts, :remap))
  end

  defp rsync_root(id), do: Fixture.load!(id).rsync_root
  defp cache(tmp), do: Path.join(tmp, "cache")

  defp tree(dir) do
    for path <- Path.wildcard(Path.join(dir, "**/*"), match_dot: true),
        File.regular?(path),
        into: %{},
        do: {Path.relative_to(path, dir), File.read!(path)}
  end

  defp kinds(result), do: Enum.map(result.issues, &{&1.kind, &1.uri})

  describe "mirroring" do
    @tag rfc: ["6481#5", "6481#2"],
         doc: """
         Every file of the fixture except the TA certificate (fetched by TA
         retrieval, #74) lies in a publication point, so all of them must
         arrive. Fixtures that need a second host, or that are built to be
         unreachable, have their own tests; so do the m2-ta-* fixtures,
         whose TA is never accepted.
         """
    test "every Barry fixture mirrors completely from the local daemon", %{tmp_dir: tmp} do
      for dir <- Fixtures.case_dirs(),
          id = Path.basename(dir),
          not String.starts_with?(id, "m2-ta-"),
          id not in ["m3-walk-delegation", "m3-walk-unreachable"] do
        tmp = Path.join(tmp, id)
        result = walk!(tmp, id)

        assert Enum.filter(result.issues, &(&1.kind == :fetch_failed)) == [], id

        assert tree(Path.join(cache(tmp), "rsync/localhost:8873/rpki")) ==
                 Map.delete(tree(rsync_root(id)), "ta.cer"),
               id
      end
    end

    @tag rfc: ["6481#5", "6487#4.8.8.1"],
         doc:
           "D-009: like LACNIC's delegations to registro.br and Amazon, fetched where the certificate says."
    test "a CA whose publication point is on a second rsync host is fetched there", %{
      tmp_dir: tmp
    } do
      other = serve(tmp, "repo", Path.join(rsync_root("m3-walk-delegation"), "other"))
      result = walk!(tmp, "m3-walk-delegation", remap: %{"other.example:8873" => other})

      assert Enum.map(result.fetches, & &1.uri) == [
               @base <> "/ta",
               @base <> "/ca1",
               "rsync://other.example:8873/repo/ca2"
             ]

      assert result.issues == []

      assert tree(Path.join(cache(tmp), "rsync/other.example:8873/repo/ca2")) ==
               tree(Path.join(rsync_root("m3-walk-delegation"), "other/ca2"))
    end

    @tag rfc: "6481#5",
         doc:
           "D-009: the TA's recursive fetch already brought ca1's directory; one rsync run in all."
    test "a publication point nested in one already fetched causes no extra rsync run", %{
      tmp_dir: tmp
    } do
      result = walk!(tmp, "m3-walk-nested")

      assert [%{uri: @base <> "/ta", outcome: :ok}] = result.fetches

      assert [
               %{uri: @base <> "/ta", depth: 0},
               %{uri: @base <> "/ta/ca1", depth: 1, covered_by: @base <> "/ta", stale: false}
             ] = result.points

      assert File.read!(Path.join(cache(tmp), "rsync/localhost:8873/rpki/ta/ca1/roa1.roa")) ==
               File.read!(Path.join(rsync_root("m3-walk-nested"), "ta/ca1/roa1.roa"))
    end

    test "each fetch's outcome is recorded in the cache status", %{tmp_dir: tmp} do
      walk!(tmp, "m0-minimal-valid")
      {:ok, ca1} = URI.parse(@base <> "/ca1")

      assert %{outcome: :ok, last_success: @now} = Cache.status(cache(tmp), ca1)
    end
  end

  describe "limits (D-008)" do
    @tag rfc: "6481#5"
    test "an SIA loop terminates, with the loop reported", %{tmp_dir: tmp} do
      result = walk!(tmp, "m3-walk-loop")

      assert kinds(result) == [{:loop, @base <> "/ca1"}]
      assert [%{certificate: @base <> "/ca1/ca2.cer"}] = Enum.map(result.issues, & &1.detail)
      assert Enum.map(result.points, & &1.uri) == [@base <> "/ta", @base <> "/ca1"]
    end

    @tag rfc: "6481#5",
         doc:
           "RFC 6481 §5's locally configured maximum chain length, set to 2 here: ca3 is depth 3."
    test "a chain deeper than the limit stops there, reported", %{tmp_dir: tmp} do
      result = walk!(tmp, "m3-walk-deep", max_depth: 2)

      assert Enum.map(result.points, &{&1.uri, &1.depth}) == [
               {@base <> "/ta", 0},
               {@base <> "/ca1", 1},
               {@base <> "/ca2", 2}
             ]

      assert kinds(result) == [{:depth_exceeded, @base <> "/ca3"}]
      refute File.exists?(Path.join(cache(tmp), "rsync/localhost:8873/rpki/ca3"))
    end

    test "the default depth limit lets a five-level chain through", %{tmp_dir: tmp} do
      result = walk!(tmp, "m3-walk-deep")

      assert result.issues == []
      assert length(result.points) == 5
    end
  end

  describe "failures" do
    @tag rfc: "6481#5"
    test "a child CA on an unreachable host is reported, and the rest is mirrored", %{
      tmp_dir: tmp
    } do
      result = walk!(tmp, "m3-walk-unreachable")
      unreachable = "rsync://unreachable.invalid/repo/ca1"

      assert [{:fetch_failed, ^unreachable}, {:missing, ^unreachable}] = kinds(result)
      assert [%{detail: %{reason: :unknown_host}} | _] = result.issues

      assert tree(Path.join(cache(tmp), "rsync/localhost:8873/rpki/ca2")) ==
               tree(Path.join(rsync_root("m3-walk-unreachable"), "ca2"))
    end

    @tag rfc: ["6481#5", "8897#7"],
         doc: """
         First run: the host is reachable (remapped to a daemon). Second run:
         it isn't. The last good copy stays byte-identical, and the walk
         continues from it, marked stale.
         """
    test "an unreachable publication point keeps its last good copy, walked as stale", %{
      tmp_dir: tmp
    } do
      id = "m3-walk-unreachable"
      repo = serve(tmp, "repo", Path.join(rsync_root(id), "unreachable"))
      walk!(Path.join(tmp, "first"), id, remap: %{"unreachable.invalid" => repo})
      File.rename!(Path.join(tmp, "first/cache"), cache(tmp))
      copy = Path.join(cache(tmp), "rsync/unreachable.invalid/repo/ca1")
      before = tree(copy)
      assert before == tree(Path.join(rsync_root(id), "unreachable/ca1"))

      result = walk!(tmp, id)

      assert kinds(result) == [{:fetch_failed, "rsync://unreachable.invalid/repo/ca1"}]
      assert %{stale: true, path: ^copy} = Enum.find(result.points, &(&1.uri =~ "unreachable"))
      assert tree(copy) == before
    end
  end

  describe "concurrent fetches (D-011)" do
    # Serves m3-walk-siblings from a daemon that accepts at most
    # `max_connections` at once per module, refusing the rest, and walks
    # it with at most `per_host` rsync runs at once.
    defp siblings!(tmp, max_connections, per_host) do
      id = "m3-walk-siblings"

      daemon =
        RsyncDaemon.start!(tmp, %{"rpki" => rsync_root(id)}, max_connections: max_connections)

      Walk.run(ta!(id), cache(tmp),
        now: @now,
        per_host: per_host,
        remap: %{"localhost:8873" => "127.0.0.1:#{daemon.port}"}
      )
    end

    @tag rfc: "6481#5",
         doc: """
         Eight sibling publication points, as registro.br publishes thousands
         (#85). The daemon refuses a third connection, so a single refusal
         would show the cap was exceeded.
         """
    test "sibling publication points on one host are fetched at most :per_host at a time", %{
      tmp_dir: tmp
    } do
      result = siblings!(tmp, 2, 2)

      assert result.issues == []
      assert length(result.fetches) == 9
      assert Enum.all?(result.fetches, &(&1.outcome == :ok))

      assert tree(Path.join(cache(tmp), "rsync/localhost:8873/rpki")) ==
               Map.delete(tree(rsync_root("m3-walk-siblings")), "ta.cer")
    end

    @tag doc: """
         The converse of the test above: with :per_host above what the daemon
         accepts, it refuses some of the eight sibling fetches, which shows
         they really run at the same time.
         """
    test "sibling publication points on one host are fetched concurrently", %{tmp_dir: tmp} do
      result = siblings!(tmp, 1, 8)

      assert Enum.any?(result.fetches, &(&1.outcome == :error))
      assert [%{uri: @base <> "/ta", outcome: :ok} | _] = result.fetches
    end

    @tag rfc: "6481#5",
         doc: "The order a sequential walk gives: TA first, then ca1 to ca8 as listed."
    test "points and fetches are reported in walk order, whatever order the fetches finish in",
         %{tmp_dir: tmp} do
      result = siblings!(tmp, 8, 8)
      expected = [@base <> "/ta" | for(i <- 1..8, do: @base <> "/ca#{i}")]

      assert Enum.map(result.fetches, & &1.uri) == expected
      assert Enum.map(result.points, & &1.uri) == expected
    end
  end

  describe "selecting CAs (D-005)" do
    @tag rfc: "6487#4.8.1"
    test "a certificate that isn't a CA isn't followed" do
      assert Walk.repository(ta!("m2-ta-not-ca")) == :not_ca
    end

    @tag rfc: "6487#4.8.8.1"
    test "a CA is followed to its rsync caRepository" do
      {:ok, uri} = Walk.repository(ta!("m0-minimal-valid"))
      assert to_string(uri) == @base <> "/ta"
    end
  end
end
