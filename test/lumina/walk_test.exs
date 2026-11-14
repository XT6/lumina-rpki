defmodule Lumina.WalkTest do
  @moduledoc """
  Tests the repository walk (`Lumina.Walk`, #75) against real rsync
  daemons serving Barry fixtures: from the TA, every publication point
  reached through CA certificates is mirrored into the cache (RFC 6481 §5).
  The unit of fetching is the rsync module of a publication point, fetched
  at most once per run; publication points in a module already fetched
  are read from that copy (D-012).

  The `m3-walk-*` fixtures each exercise one part of the walk: a
  delegation to a second rsync host, a nested publication point, an SIA
  loop, a deep chain, an unreachable host and CAs in separate modules of
  one host. The walk follows only CAs that validate (D-014, #113): the
  `m4-chain-*` fixtures show what isn't followed. The fixtures name `localhost:8873` (and `other.example:8873`),
  so each test remaps those to its own daemons with `:remap`; cache paths
  and reports keep the names from the certificates.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Cache, Certificate, Object, URI, Walk}
  alias Lumina.Test.{Fixture, RsyncDaemon}
  alias Mix.Lumina.Fixtures

  @moduletag :rsync
  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]
  @module "rsync://localhost:8873/rpki"

  defp ta!(id) do
    {:ok, %Object{value: %Certificate{} = cert}} =
      Object.decode_file(Path.join(Fixture.load!(id).rsync_root, "ta.cer"))

    cert
  end

  defp serve(tmp, name, dir) do
    daemon = RsyncDaemon.start!(Path.join(tmp, name), %{name => dir})
    "127.0.0.1:#{daemon.port}"
  end

  # Serves the fixture's modules as localhost:8873, and walks it.
  defp walk!(tmp, id, opts \\ []) do
    daemon = RsyncDaemon.start!(Path.join(tmp, "localhost"), Fixture.load!(id).modules)
    remap = Map.put(opts[:remap] || %{}, "localhost:8873", "127.0.0.1:#{daemon.port}")
    Walk.run(ta!(id), cache(tmp), [now: @now, remap: remap] ++ Keyword.delete(opts, :remap))
  end

  # Walks a copy of fixture `id`'s single module after `change` (given the
  # copy's root) has altered it.
  defp walk_changed!(tmp, id, change) do
    copy = Path.join(tmp, "copy")
    File.cp_r!(rsync_root(id), copy)
    change.(copy)
    daemon = RsyncDaemon.start!(Path.join(tmp, "localhost"), %{"rpki" => copy})

    Walk.run(ta!(id), cache(tmp),
      now: @now,
      remap: %{"localhost:8873" => "127.0.0.1:#{daemon.port}"}
    )
  end

  defp rsync_root(id), do: Fixture.load!(id).rsync_root
  defp cache(tmp), do: Path.join(tmp, "cache")
  defp mirror(tmp, path), do: tree(Path.join([cache(tmp), "rsync", path]))

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
         Each module a fixture serves on localhost:8873 must arrive byte for
         byte. Fixtures that need a second host, or that are built to be
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

        for {name, path} <- Fixture.load!(id).modules,
            do: assert(mirror(tmp, "localhost:8873/" <> name) == tree(path), "#{id} #{name}")
      end
    end

    @tag rfc: ["6481#5", "5781#2"],
         doc: """
         D-012: the TA's and ca1's publication points are sibling
         directories of module rpki. Under D-009 they took two runs; the
         module takes one.
         """
    test "publication points in sibling directories of one module take one rsync run", %{
      tmp_dir: tmp
    } do
      result = walk!(tmp, "m0-minimal-valid")

      assert [%{uri: @module, outcome: :ok}] = result.fetches

      assert [
               %{uri: @module <> "/ta", depth: 0, covered_by: @module},
               %{uri: @module <> "/ca1", depth: 1, covered_by: @module, stale: false}
             ] = result.points
    end

    @tag rfc: ["6481#5", "6487#4.8.8.1"],
         doc:
           "Like LACNIC's delegations to registro.br and Amazon, fetched where the certificate says."
    test "a CA whose publication point is on a second rsync host is fetched there", %{
      tmp_dir: tmp
    } do
      other = serve(tmp, "repo", Path.join(rsync_root("m3-walk-delegation"), "other"))
      result = walk!(tmp, "m3-walk-delegation", remap: %{"other.example:8873" => other})

      assert Enum.map(result.fetches, & &1.uri) == [@module, "rsync://other.example:8873/repo"]
      assert result.issues == []

      assert mirror(tmp, "other.example:8873/repo") ==
               tree(Path.join(rsync_root("m3-walk-delegation"), "other"))
    end

    @tag rfc: "6481#5",
         doc:
           "The fetch of the TA's module already brought ca1's directory; one rsync run in all."
    test "a publication point nested in one already fetched causes no extra rsync run", %{
      tmp_dir: tmp
    } do
      result = walk!(tmp, "m3-walk-nested")

      assert [%{uri: @module, outcome: :ok}] = result.fetches

      assert [
               %{uri: @module <> "/ta", depth: 0},
               %{uri: @module <> "/ta/ca1", depth: 1, covered_by: @module, stale: false}
             ] = result.points

      assert File.read!(Path.join(cache(tmp), "rsync/localhost:8873/rpki/ta/ca1/roa1.roa")) ==
               File.read!(Path.join(rsync_root("m3-walk-nested"), "ta/ca1/roa1.roa"))
    end

    test "each fetch's outcome is recorded in the cache status", %{tmp_dir: tmp} do
      walk!(tmp, "m0-minimal-valid")
      {:ok, module} = URI.parse(@module)

      assert %{outcome: :ok, last_success: @now} = Cache.status(cache(tmp), module)
    end
  end

  describe "limits (D-008)" do
    @tag rfc: "6481#5"
    test "an SIA loop terminates, with the loop reported", %{tmp_dir: tmp} do
      result = walk!(tmp, "m3-walk-loop")

      assert kinds(result) == [{:loop, @module <> "/ca1"}]
      assert [%{certificate: @module <> "/ca1/ca2.cer"}] = Enum.map(result.issues, & &1.detail)
      assert Enum.map(result.points, & &1.uri) == [@module <> "/ta", @module <> "/ca1"]
    end

    @tag rfc: "6481#5",
         doc: """
         RFC 6481 §5's locally configured maximum chain length, set to 2
         here: ca3 is depth 3. Its files arrive with the module, but it isn't
         walked.
         """
    test "a chain deeper than the limit stops there, reported", %{tmp_dir: tmp} do
      result = walk!(tmp, "m3-walk-deep", max_depth: 2)

      assert Enum.map(result.points, &{&1.uri, &1.depth}) == [
               {@module <> "/ta", 0},
               {@module <> "/ca1", 1},
               {@module <> "/ca2", 2}
             ]

      assert kinds(result) == [{:depth_exceeded, @module <> "/ca3"}]
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

      assert kinds(result) == [
               {:fetch_failed, "rsync://unreachable.invalid/repo"},
               {:missing, "rsync://unreachable.invalid/repo/ca1"}
             ]

      assert [%{detail: %{reason: :unknown_host}} | _] = result.issues

      assert mirror(tmp, "localhost:8873/rpki/ca2") ==
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

      assert kinds(result) == [{:fetch_failed, "rsync://unreachable.invalid/repo"}]
      assert %{stale: true, path: ^copy} = Enum.find(result.points, &(&1.uri =~ "unreachable"))
      assert tree(copy) == before
    end
  end

  describe "concurrent fetches (D-011)" do
    # Serves m3-walk-siblings (eight CAs, each in a module of its own) from
    # a daemon that accepts at most `max_connections` at once over all its
    # modules, refusing the rest, and walks it with at most `per_host`
    # rsync runs at once.
    defp siblings!(tmp, max_connections, per_host) do
      id = "m3-walk-siblings"

      daemon =
        RsyncDaemon.start!(tmp, Fixture.load!(id).modules, max_connections: max_connections)

      Walk.run(ta!(id), cache(tmp),
        now: @now,
        per_host: per_host,
        remap: %{"localhost:8873" => "127.0.0.1:#{daemon.port}"}
      )
    end

    @tag rfc: "6481#5",
         doc: """
         Eight modules on one host, fetched in one level. The daemon refuses
         a third connection, so a single refusal would show the cap was
         exceeded.
         """
    test "modules on one host are fetched at most :per_host at a time", %{tmp_dir: tmp} do
      result = siblings!(tmp, 2, 2)

      assert result.issues == []
      assert length(result.fetches) == 9
      assert Enum.all?(result.fetches, &(&1.outcome == :ok))

      for i <- 1..8,
          do:
            assert(
              mirror(tmp, "localhost:8873/s#{i}") ==
                tree(Path.join(rsync_root("m3-walk-siblings"), "s#{i}"))
            )
    end

    @tag doc: """
         The converse of the test above: with :per_host above what the daemon
         accepts, it refuses some of the eight module fetches, which shows
         they really run at the same time.
         """
    test "modules on one host are fetched concurrently", %{tmp_dir: tmp} do
      result = siblings!(tmp, 1, 8)

      assert Enum.any?(result.fetches, &(&1.outcome == :error))
      assert [%{uri: @module, outcome: :ok} | _] = result.fetches
    end

    @tag rfc: "6481#5",
         doc: "The order a sequential walk gives: the TA's module first, then s1 to s8 as listed."
    test "points and fetches are reported in walk order, whatever order the fetches finish in",
         %{tmp_dir: tmp} do
      result = siblings!(tmp, 8, 8)
      base = "rsync://localhost:8873"

      assert Enum.map(result.fetches, & &1.uri) == [@module | for(i <- 1..8, do: "#{base}/s#{i}")]

      assert Enum.map(result.points, & &1.uri) ==
               [@module <> "/ta" | for(i <- 1..8, do: "#{base}/s#{i}/ca#{i}")]
    end
  end

  describe "validation (D-014)" do
    @tag rfc: ["6481#5", "6487#7.2"],
         doc: """
         Same points as M3 gave: no CA of a positive fixture is reported
         invalid. Warnings are allowed (m4-cert-unknown-extension, D-013).
         """
    test "every positive Barry fixture walks without an invalid CA", %{tmp_dir: tmp} do
      for dir <- Fixtures.case_dirs(),
          id = Path.basename(dir),
          Fixture.load!(id).expected == :valid,
          id not in ["m3-walk-delegation", "m3-walk-unreachable"] do
        result = walk!(Path.join(tmp, id), id)

        assert Enum.filter(result.issues, &(&1.kind == :invalid)) == [], id
      end
    end

    @tag rfc: ["6481#5", "6487#7.2"],
         doc: "ca1's directory arrives with the module (D-012), but it isn't walked."
    test "a CA that doesn't validate is reported with its reasons, and nothing below it is walked",
         %{tmp_dir: tmp} do
      result = walk!(tmp, "m4-chain-ca-bad-signature")

      assert kinds(result) == [{:invalid, @module <> "/ta/ca1.cer"}]
      assert [%{detail: [%{rule: :bad_signature}]}] = result.issues
      assert Enum.map(result.points, & &1.uri) == [@module <> "/ta"]
    end

    @tag rfc: ["6487#7.2", "9829#3.2"]
    test "a revoked CA isn't walked, and its sibling is", %{tmp_dir: tmp} do
      result = walk!(tmp, "m4-chain-revoked-ca")

      assert kinds(result) == [{:invalid, @module <> "/ta/ca1.cer"}]
      assert [%{detail: [%{rule: :revoked}]}] = result.issues
      assert Enum.map(result.points, & &1.uri) == [@module <> "/ta", @module <> "/ca2"]
    end

    @tag rfc: ["6487#7.2", "9829#3.2"]
    test "a CA whose CRL is missing isn't walked", %{tmp_dir: tmp} do
      result = walk!(tmp, "m4-chain-crl-missing")

      assert [%{kind: :invalid, detail: [%{rule: :crl_missing}]}] = result.issues
      assert length(result.points) == 1
    end

    @tag rfc: "6481#5",
         doc: """
         #103: LACNIC publishes its TA certificate in the TA's own
         publication point. A certificate with the CA's own key is the CA
         itself, not a child: no loop, no invalid CA.
         """
    test "a TA certificate published in its own publication point is skipped silently", %{
      tmp_dir: tmp
    } do
      result =
        walk_changed!(tmp, "m0-minimal-valid", fn copy ->
          File.cp!(Path.join(copy, "ta.cer"), Path.join(copy, "ta/ta.cer"))
        end)

      assert result.issues == []
      assert Enum.map(result.points, & &1.uri) == [@module <> "/ta", @module <> "/ca1"]
    end

    @tag rfc: ["6481#5", "6487#4.8.3"],
         doc: """
         Until manifests say what a CA published (M5), a certificate whose
         issuer name and AKI both name another CA belongs to a CA sharing
         the directory: here a CA certificate from another fixture.
         """
    test "a certificate issued by another CA is skipped, not reported invalid", %{tmp_dir: tmp} do
      result =
        walk_changed!(tmp, "m0-minimal-valid", fn copy ->
          File.cp!(
            Path.join(rsync_root("m3-walk-deep"), "ca1/ca2.cer"),
            Path.join(copy, "ta/x.cer")
          )
        end)

      assert result.issues == []
      assert Enum.map(result.points, & &1.uri) == [@module <> "/ta", @module <> "/ca1"]
    end

    @tag rfc: ["6487#4.8.3", "6487#7.2"],
         doc: "Only one of the two names another CA: a fault, reported."
    test "a certificate naming the CA as issuer but with another AKI is reported invalid", %{
      tmp_dir: tmp
    } do
      result = walk!(tmp, "m4-chain-aki-mismatch")

      assert [%{kind: :invalid, detail: [%{rule: :aki_mismatch}]}] = result.issues
    end

    @tag rfc: ["6487#4.8.1", "6487#4.8.4"],
         doc: """
         Its Key Usage has keyCertSign, so it is checked as a CA and the
         missing Basic Constraints reported (#115); it isn't walked.
         """
    test "a CA certificate without Basic Constraints is reported invalid, not skipped", %{
      tmp_dir: tmp
    } do
      result = walk!(tmp, "m4-cert-ca-no-basic-constraints")

      assert [%{kind: :invalid, detail: [%{rule: :missing_extension, field: :basic_constraints}]}] =
               result.issues

      assert Enum.map(result.points, & &1.uri) == [@module <> "/ta"]
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
      assert to_string(uri) == @module <> "/ta"
    end
  end
end
