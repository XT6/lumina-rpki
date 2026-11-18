defmodule Lumina.CLIVRPsTest do
  @moduledoc """
  Tests `lumina vrps` (#165, D-031): it validates the cache offline, as
  `lumina validate` does, and writes the VRPs of the valid ROAs as CSV in
  Routinator's columns (D-032), one row per distinct AS, prefix,
  maxLength and trust anchor (D-033), to stdout or atomically to
  `--output FILE`, as CSV or as JSON (`--format json`, #167, RFC 8259,
  `doc/output.md`). Above `--max-invalid` the VRPs are still written, with
  a warning, and the exit code is 1 (D-034).

  Each test syncs Barry fixtures from a local rsync daemon with `lumina
  sync`, then runs `lumina vrps` at 2030-01-01 (`--now`), through
  `Lumina.CLI.run/4`.
  """
  use ExUnit.Case, async: true

  alias Lumina.{CLI, TAL}

  doctest Lumina.VRP
  alias Lumina.Test.{Fixture, RsyncDaemon}

  @header "ASN,IP Prefix,Max Length,Trust Anchor\n"

  defp run(args, internal \\ []) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(Lumina.Test.Quiet.args(args), out, err, internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  # Serves fixture `id`, writes its TAL (rsync only) under each name in
  # `names`, and syncs them all into one cache. Returns the TAL paths, the
  # cache and the internal options.
  defp synced!(tmp, id, names \\ ["case"]) do
    fixture = Fixture.load!(id)
    daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), fixture.modules)
    authority = "127.0.0.1:#{daemon.port}"

    text =
      fixture.tal_path
      |> File.read!()
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(&1, "https://"))
      |> Enum.map_join("\n", &String.replace(&1, "localhost:8873", authority))

    tals =
      for name <- names do
        path = Path.join(tmp, name <> ".tal")
        File.write!(path, text)
        path
      end

    cache = Path.join(tmp, "cache")
    internal = [remap: %{"localhost:8873" => authority}]
    tal_flags = Enum.flat_map(tals, &["--tal", &1])
    {0, _, ""} = run(["sync", "--cache", cache | tal_flags], internal)
    {tal_flags, cache, internal}
  end

  defp vrps_args(tal_flags, cache, extra \\ []),
    do: ["vrps", "--cache", cache, "--now", "2030-01-01" | tal_flags] ++ extra

  describe "CSV output" do
    @describetag :rsync
    @describetag :tmp_dir

    @tag rfc: ["9582#4.3.2.2", "9582#5"],
         doc: "m1-roa-prefixes: AS64496 with 1.1.0.0/17-24, 1.1.128.0/24 and 0101::/16-48."
    test "a fixture's VRPs are written as CSV, header first, in order", %{tmp_dir: tmp} do
      {tals, cache, internal} = synced!(tmp, "m1-roa-prefixes")

      assert {0, out, err} = run(vrps_args(tals, cache), internal)

      assert out ==
               @header <>
                 "AS64496,1.1.0.0/17,24,case\n" <>
                 "AS64496,1.1.128.0/24,24,case\n" <>
                 "AS64496,101::/16,48,case\n"

      assert err == "case: 3 VRPs\n"
    end

    @tag doc: """
         m0-minimal-valid's TAL under two names: each VRP once per trust
         anchor, named after its TAL file (D-032), in the VRP order.
         """
    test "with two TALs, each VRP carries its own trust anchor's name", %{tmp_dir: tmp} do
      {tals, cache, internal} = synced!(tmp, "m0-minimal-valid", ["lacnic", "ripe-ncc"])

      assert {0, out, _err} = run(vrps_args(tals, cache), internal)

      assert out ==
               @header <>
                 "AS1234,1.1.0.0/16,16,lacnic\n" <>
                 "AS1234,1.1.0.0/16,16,ripe-ncc\n" <>
                 "AS1234,101::/16,16,lacnic\n" <>
                 "AS1234,101::/16,16,ripe-ncc\n"
    end

    @tag doc: "m7-vrp-duplicate: roa1.roa and roa2.roa both state AS64496, 1.1.0.0/16 (D-033)."
    test "a VRP stated by two ROAs is written once", %{tmp_dir: tmp} do
      {tals, cache, internal} = synced!(tmp, "m7-vrp-duplicate")

      assert {0, out, "case: 1 VRPs\n"} = run(vrps_args(tals, cache), internal)
      assert out == @header <> "AS64496,1.1.0.0/16,16,case\n"
    end
  end

  describe "shared publication points (#195)" do
    @describetag :rsync
    @describetag :tmp_dir

    @tag rfc: ["9286#1", "6481#2.2", "9582#5"],
         doc: """
         m7-shared-point: ca1's roa1.roa (1.1.0.0/16, 101::/16) and ca2's
         roa2.roa (2.1.0.0/16, 201::/16) are in one directory, each listed
         on its own CA's manifest.
         """
    test "CAs sharing a publication point directory each give their ROAs' VRPs", %{
      tmp_dir: tmp
    } do
      {tals, cache, internal} = synced!(tmp, "m7-shared-point")

      assert {0, out, "case: 4 VRPs\n"} = run(vrps_args(tals, cache), internal)

      assert out ==
               @header <>
                 "AS1234,1.1.0.0/16,16,case\n" <>
                 "AS1234,2.1.0.0/16,16,case\n" <>
                 "AS1234,101::/16,16,case\n" <>
                 "AS1234,201::/16,16,case\n"
    end
  end

  describe "--wide (#166)" do
    @describetag :rsync
    @describetag :tmp_dir

    @tag doc: """
         m7-vrp-duplicate: roa1.roa and roa2.roa both state AS64496,
         1.1.0.0/16. --wide lists it once for each, with its ROA's URI
         (D-033); without it, once.
         """
    test "adds the ROA's URI and lists a VRP once per ROA that states it", %{tmp_dir: tmp} do
      {tals, cache, internal} = synced!(tmp, "m7-vrp-duplicate")

      assert {0, out, _err} = run(vrps_args(tals, cache, ["--wide"]), internal)

      assert out ==
               "ASN,IP Prefix,Max Length,Trust Anchor,URI\n" <>
                 "AS64496,1.1.0.0/16,16,case,rsync://localhost:8873/rpki/ca1/roa1.roa\n" <>
                 "AS64496,1.1.0.0/16,16,case,rsync://localhost:8873/rpki/ca1/roa2.roa\n"

      assert {0, @header <> "AS64496,1.1.0.0/16,16,case\n", _} =
               run(vrps_args(tals, cache), internal)
    end

    @tag doc: "m1-roa-prefixes: one ROA, so each row's URI is roa1.roa."
    test "every row's URI is the ROA the VRP comes from, in the default order", %{tmp_dir: tmp} do
      {tals, cache, internal} = synced!(tmp, "m1-roa-prefixes")
      uri = "rsync://localhost:8873/rpki/ca1/roa1.roa"

      assert {0, out, _err} = run(vrps_args(tals, cache, ["--wide"]), internal)

      assert out ==
               "ASN,IP Prefix,Max Length,Trust Anchor,URI\n" <>
                 "AS64496,1.1.0.0/17,24,case,#{uri}\n" <>
                 "AS64496,1.1.128.0/24,24,case,#{uri}\n" <>
                 "AS64496,101::/16,48,case,#{uri}\n"
    end
  end

  describe "--format json (#167)" do
    @describetag :rsync
    @describetag :tmp_dir

    # Microseconds, which the output drops.
    @generated ~U[2026-11-15 12:00:00.123456Z]

    defp json!(tal_flags, cache, internal, extra \\ []) do
      args = vrps_args(tal_flags, cache, ["--format", "json" | extra])
      {code, out, _err} = run(args, [generated: @generated] ++ internal)
      {code, out, :json.decode(out)}
    end

    @tag rfc: ["8259#4", "8259#5", "9582#4.3.2.2"],
         doc: """
         m1-roa-prefixes: the whole document, metadata and the three VRPs,
         as `:json.decode/1` gives it.
         """
    test "a fixture's JSON decodes to exactly the expected document", %{tmp_dir: tmp} do
      {tals, cache, internal} = synced!(tmp, "m1-roa-prefixes")
      ["--tal", tal] = tals

      assert {0, _out, document} = json!(tals, cache, internal)

      assert document == %{
               "metadata" => %{
                 "generated" => "2026-11-15T12:00:00Z",
                 "validationTime" => "2030-01-01T00:00:00Z",
                 "lumina" => Mix.Project.config()[:version],
                 "trustAnchors" => [
                   %{"name" => "case", "tal" => tal, "status" => "ok", "vrps" => 3}
                 ],
                 "vrps" => 3
               },
               "roas" => [
                 %{
                   "asn" => "AS64496",
                   "prefix" => "1.1.0.0/17",
                   "maxLength" => 24,
                   "ta" => "case"
                 },
                 %{
                   "asn" => "AS64496",
                   "prefix" => "1.1.128.0/24",
                   "maxLength" => 24,
                   "ta" => "case"
                 },
                 %{"asn" => "AS64496", "prefix" => "101::/16", "maxLength" => 48, "ta" => "case"}
               ]
             }
    end

    @tag doc: """
         m0-minimal-valid's TAL under two names: the JSON rows, written as
         CSV rows, are the CSV's rows, in its order, and each trust anchor
         counts its own.
         """
    test "the JSON has the same VRPs as the CSV, in the same order", %{tmp_dir: tmp} do
      {tals, cache, internal} = synced!(tmp, "m0-minimal-valid", ["lacnic", "ripe-ncc"])

      assert {0, csv, _} = run(vrps_args(tals, cache), internal)
      assert {0, _out, document} = json!(tals, cache, internal)

      rows =
        for r <- document["roas"],
            do: "#{r["asn"]},#{r["prefix"]},#{r["maxLength"]},#{r["ta"]}\n"

      assert Enum.join([@header | rows]) == csv
      assert length(rows) == 4

      assert for(t <- document["metadata"]["trustAnchors"], do: {t["name"], t["vrps"]}) ==
               [{"lacnic", 2}, {"ripe-ncc", 2}]
    end

    @tag doc: """
         m7-vrp-duplicate: with --wide, each row has "uri" and the VRP that
         roa1.roa and roa2.roa both state is there twice (D-033).
         """
    test "with --wide, each VRP has its ROA's URI and duplicates are kept", %{tmp_dir: tmp} do
      {tals, cache, internal} = synced!(tmp, "m7-vrp-duplicate")

      assert {0, _out, document} = json!(tals, cache, internal, ["--wide"])

      assert document["roas"] == [
               %{
                 "asn" => "AS64496",
                 "prefix" => "1.1.0.0/16",
                 "maxLength" => 16,
                 "ta" => "case",
                 "uri" => "rsync://localhost:8873/rpki/ca1/roa1.roa"
               },
               %{
                 "asn" => "AS64496",
                 "prefix" => "1.1.0.0/16",
                 "maxLength" => 16,
                 "ta" => "case",
                 "uri" => "rsync://localhost:8873/rpki/ca1/roa2.roa"
               }
             ]

      assert document["metadata"]["vrps"] == 2
      assert {0, _, %{"roas" => [_]}} = json!(tals, cache, internal)
    end

    @tag rfc: "8259#7",
         doc: """
         A TAL file named with a double quote, a backslash and a control
         character (U+0001): JSON escapes them in the trust anchor's name,
         and decoding gives the name back. The solidus in a prefix stays
         unescaped, as §7's prose allows (F-036).
         """
    test "quotes, backslashes and control characters in a name are escaped", %{tmp_dir: tmp} do
      name = "q\"b\\s\x01t"
      {tals, cache, internal} = synced!(tmp, "m0-minimal-valid", [name])

      assert {0, out, document} = json!(tals, cache, internal)

      assert out =~ ~S("ta":"q\"b\\s\u0001t")
      refute out =~ "\x01"
      # The solidus may stand unescaped (§7's prose; F-036).
      assert out =~ ~s("prefix":"1.1.0.0/16")
      assert [%{"ta" => ^name} | _] = document["roas"]
      assert [%{"name" => ^name}] = document["metadata"]["trustAnchors"]
    end

    @tag doc: """
         m7-roa-prefix-outside-ee (over --max-invalid, D-034) and a TAL with
         no trust anchor in the cache: each one's status, and the VRPs
         still written for the first.
         """
    test "each trust anchor's status says why the run failed", %{tmp_dir: tmp} do
      {tals, cache, internal} = synced!(tmp, "m7-roa-prefix-outside-ee")
      missing = Path.join(tmp, "lacnic.tal")
      File.cp!("tals/lacnic.tal", missing)

      assert {1, _out, document} = json!(tals ++ ["--tal", missing], cache, internal)

      assert for(
               t <- document["metadata"]["trustAnchors"],
               do: {t["name"], t["status"], t["vrps"]}
             ) ==
               [{"case", "too_many_invalid", 2}, {"lacnic", "no_trust_anchor", 0}]

      assert length(document["roas"]) == 2
    end

    test "with no VRPs, roas is an empty array", %{tmp_dir: tmp} do
      tal = Path.join(tmp, "lacnic.tal")
      File.cp!("tals/lacnic.tal", tal)

      assert {1, out, %{"roas" => [], "metadata" => %{"vrps" => 0}}} =
               json!(["--tal", tal], Path.join(tmp, "empty"), [])

      assert out =~ ~s("roas": []\n)
    end
  end

  describe "--sync (#185)" do
    @describetag :rsync
    @describetag :tmp_dir

    # The clock (`internal` :now) for the syncs and the age checks; the
    # VRPs are validated at --now 2030-01-01 throughout.
    @clock ~U[2030-01-01 12:00:00Z]

    # A fixture (m1-roa-prefixes by default) at a local daemon, with a TAL
    # named case.tal, not synced yet.
    defp served!(tmp, id \\ "m1-roa-prefixes") do
      fixture = Fixture.load!(id)
      daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), fixture.modules)
      authority = "127.0.0.1:#{daemon.port}"
      tal = Path.join(tmp, "case.tal")

      File.write!(
        tal,
        fixture.tal_path
        |> File.read!()
        |> String.split("\n")
        |> Enum.reject(&String.starts_with?(&1, "https://"))
        |> Enum.map_join("\n", &String.replace(&1, "localhost:8873", authority))
      )

      {["--tal", tal], Path.join(tmp, "cache"), [remap: %{"localhost:8873" => authority}]}
    end

    defp at(internal, minutes), do: [now: DateTime.add(@clock, minutes * 60)] ++ internal

    defp sync_at!(tals, cache, internal, minutes),
      do: {0, _, _} = run(["sync", "--cache", cache | tals], at(internal, minutes))

    @csv @header <>
           "AS64496,1.1.0.0/17,24,case\nAS64496,1.1.128.0/24,24,case\nAS64496,101::/16,48,case\n"

    test "with an empty cache, the TAL is synced and its VRPs written", %{tmp_dir: tmp} do
      {tals, cache, internal} = served!(tmp)

      assert {1, @header, _} = run(vrps_args(tals, cache), at(internal, 0))

      assert {0, @csv, err} = run(vrps_args(tals, cache, ["--sync"]), at(internal, 0))
      assert err =~ "lumina vrps: syncing #{List.last(tals)}: no trust anchor in the cache\n"
      assert err =~ "  rsync fetches: 1, 0 failed\n"
    end

    @tag rfc: "8182#3.4.5",
         doc: """
         m1-roa-prefixes served over RRDP (Lumina.Test.RRDPServer, the TA
         certificate too) and rsync, with RRDP on as outside tests. With
         --no-rrdp the sync asks the HTTPS server only for the TA
         certificate; without it, for the notification, and the summary on
         stderr has the repository's line (#233). The VRPs are the same.
         """
    test "--sync --no-rrdp syncs the repository with rsync only", %{tmp_dir: tmp} do
      fixture = Fixture.load!("m1-roa-prefixes")
      server = Lumina.Test.RRDPServer.start!(Lumina.Test.RRDPServer.routes(fixture))
      daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), fixture.modules)

      internal = [
        rrdp: true,
        rrdp_opts: [cacerts: server.opts[:cacerts], min_interval: 0],
        remap: Map.put(server.opts[:remap], "localhost:8873", "127.0.0.1:#{daemon.port}"),
        https: [cacerts: server.opts[:cacerts], remap: server.opts[:remap]]
      ]

      tals = ["--tal", fixture.tal_path]

      assert {0, @csv, err} =
               run(vrps_args(tals, Path.join(tmp, "a"), ["--sync", "--no-rrdp"]), internal)

      assert Lumina.Test.RRDPServer.requested(server) == ["/rrdp/ta.cer"]
      refute err =~ "rrdp:"

      Lumina.Test.RRDPServer.serve(server, Lumina.Test.RRDPServer.routes(fixture))
      assert {0, @csv, err} = run(vrps_args(tals, Path.join(tmp, "b"), ["--sync"]), internal)
      assert "/rrdp/notification.xml" in Lumina.Test.RRDPServer.requested(server)
      assert err =~ "  rrdp: 1 repository: 1 snapshot\n"

      assert err =~
               "    #{fixture.notification_uri}: session #{fixture.session_id}, serial 1, snapshot (first sync), "
    end

    @tag doc: """
         Synced 10 minutes before, within the default --max-age of 1h: no
         sync, shown by the repository host now pointing at a closed port,
         which would fail one.
         """
    test "a TAL synced within --max-age isn't synced again", %{tmp_dir: tmp} do
      {tals, cache, internal} = served!(tmp)
      sync_at!(tals, cache, internal, -10)
      closed = [remap: %{"localhost:8873" => "127.0.0.1:#{RsyncDaemon.closed_port()}"}]

      assert {0, @csv, err} = run(vrps_args(tals, cache, ["--sync"]), at(closed, 0))
      refute err =~ "syncing"
    end

    test "a TAL last synced longer ago than --max-age is synced", %{tmp_dir: tmp} do
      {tals, cache, internal} = served!(tmp)
      sync_at!(tals, cache, internal, -120)

      assert {0, @csv, err} = run(vrps_args(tals, cache, ["--sync"]), at(internal, 0))

      assert err =~
               "lumina vrps: syncing #{List.last(tals)}: last synced 2030-01-01T10:00:00Z, " <>
                 "more than 1h ago\n"

      assert Lumina.Sync.last_synced(cache, elem(TAL.decode_file(List.last(tals)), 1)) == @clock

      assert {0, @csv, err} =
               run(vrps_args(tals, cache, ["--sync", "--max-age", "3h"]), at(internal, 100))

      refute err =~ "syncing"
    end

    @tag doc: """
         Two TALs: case.tal, synced a minute ago, and dead.tal, with
         m0-minimal-valid's key (so its own trust anchor) and only a URI
         at a closed port. Only dead.tal is synced; that sync fails, and
         case.tal's VRPs are still written, with exit 1.
         """
    test "only the TALs that need it are synced, and a failed sync still writes the VRPs",
         %{tmp_dir: tmp} do
      {tals, cache, internal} = served!(tmp)
      sync_at!(tals, cache, internal, -1)
      dead = Path.join(tmp, "dead.tal")

      File.write!(
        dead,
        Fixture.load!("m0-minimal-valid").tal_path
        |> File.read!()
        |> String.split("\n")
        |> Enum.reject(&String.starts_with?(&1, ["https://", "rsync://"]))
        |> then(&["rsync://127.0.0.1:#{RsyncDaemon.closed_port()}/rpki/ta.cer" | &1])
        |> Enum.join("\n")
      )

      args = vrps_args(tals ++ ["--tal", dead], cache, ["--sync", "--timeout", "5"])
      assert {1, @csv, err} = run(args, at(internal, 0))

      assert err =~ "lumina vrps: syncing #{dead}: no trust anchor in the cache\n"
      refute err =~ "syncing #{List.last(tals)}"

      assert err =~
               "lumina vrps: warning: the sync had failures (above); the VRPs are written from what the cache holds\n"
    end

    @tag doc: """
         m3-walk-unreachable: the TA's publication point is fetched, the
         delegated CA's host (unreachable.invalid) isn't. The sync's
         failure is reported, but the trust anchor synced, so the exit
         code is 0 (D-037).
         """
    test "a fetch failing below the trust anchor's own publication point only warns", %{
      tmp_dir: tmp
    } do
      {tals, cache, internal} = served!(tmp, "m3-walk-unreachable")

      assert {0, out, err} = run(vrps_args(tals, cache, ["--sync"]), at(internal, 0))
      assert out == @header <> "AS1234,2.1.0.0/16,16,case\nAS1234,201::/16,16,case\n"
      assert err =~ "rsync fetches: 2, 1 failed\n"
      assert err =~ "fetch_failed: rsync://unreachable.invalid/repo"

      assert err =~
               "lumina vrps: warning: the sync had failures (above); the VRPs are written from what the cache holds\n"
    end

    @tag doc: "Reports as Lumina.Sync.run/3 gives them, reduced to what matters."
    test "a TAL counts as synced only if its TA and the TA's own publication point were fetched" do
      point = fn depth, stale -> %{depth: depth, stale: stale} end

      assert Lumina.Sync.ta_synced?(%{
               ta: {:ok, %{}},
               walk: %{points: [point.(0, false), point.(1, true)]}
             })

      # The TA's module failed: its point is a stale copy.
      refute Lumina.Sync.ta_synced?(%{ta: {:ok, %{}}, walk: %{points: [point.(0, true)]}})
      # The TA's point was never fetched and has no copy.
      refute Lumina.Sync.ta_synced?(%{ta: {:ok, %{}}, walk: %{points: []}})
      # The TA wasn't retrieved: walked from a stale TA, or not at all.
      refute Lumina.Sync.ta_synced?(%{ta: {:error, %{}}, walk: %{points: [point.(0, false)]}})
      refute Lumina.Sync.ta_synced?(%{ta: {:error, %{}}, walk: nil})
    end

    @tag :tmp_dir
    test "sync flags without --sync, and a bad --max-age or RRDP limit, are usage errors", %{
      tmp_dir: tmp
    } do
      base = vrps_args(["--tal", "tals/lacnic.tal"], Path.join(tmp, "cache"))

      assert {2, "", err} = run(base ++ ["--max-age", "2h"])
      assert err =~ "lumina vrps: --max-age needs --sync\n"
      assert {2, "", err} = run(base ++ ["--per-host", "2"])
      assert err =~ "lumina vrps: --per-host needs --sync\n"
      assert {2, "", err} = run(base ++ ["--no-rrdp"])
      assert err =~ "lumina vrps: --no-rrdp needs --sync\n"
      assert {2, "", err} = run(base ++ ["--rrdp-max-size", "1G"])
      assert err =~ "lumina vrps: --rrdp-max-size needs --sync\n"
      assert {2, "", err} = run(base ++ ["--rrdp-idle-timeout", "60"])
      assert err =~ "lumina vrps: --rrdp-idle-timeout needs --sync\n"
      assert {2, "", err} = run(base ++ ["--sync", "--rrdp-max-size", "big"])
      assert err =~ "--rrdp-max-size must be a size such as 500M, 2G or a number of bytes"

      for bad <- ["0", "2w", "-1h", "h", "1.5h"] do
        assert {2, "", err} = run(base ++ ["--sync", "--max-age", bad])
        assert err =~ "--max-age must be a duration such as 90s, 30m, 2h or 1d"
      end
    end
  end

  describe "--output" do
    @describetag :rsync
    @describetag :tmp_dir

    test "writes the same bytes as standard output, and nothing to standard output", %{
      tmp_dir: tmp
    } do
      {tals, cache, internal} = synced!(tmp, "m1-roa-prefixes")
      {0, expected, _} = run(vrps_args(tals, cache), internal)
      file = Path.join(tmp, "vrps.csv")
      File.write!(file, "old contents")

      assert {0, "", _err} = run(vrps_args(tals, cache, ["--output", file]), internal)
      assert File.read!(file) == expected
      assert File.ls!(tmp) |> Enum.filter(&String.ends_with?(&1, ".tmp")) == []
    end

    test "a file that can't be written fails with exit 1 and leaves nothing behind", %{
      tmp_dir: tmp
    } do
      {tals, cache, internal} = synced!(tmp, "m1-roa-prefixes")
      file = Path.join([tmp, "missing", "vrps.csv"])

      assert {1, "", err} = run(vrps_args(tals, cache, ["--output", file]), internal)
      assert err =~ "lumina vrps: can't write #{file}: no such file or directory\n"
      refute File.exists?(Path.dirname(file))
    end
  end

  describe "failures" do
    @describetag :rsync
    @describetag :tmp_dir

    @tag rfc: "9582#5",
         doc: """
         m7-roa-prefix-outside-ee: one invalid ROA of five objects, 20%,
         above the default 10% (D-022). roa2.roa's VRPs are written anyway
         (D-034).
         """
    test "above --max-invalid the VRPs are still written, with a warning, and exit 1", %{
      tmp_dir: tmp
    } do
      {tals, cache, internal} = synced!(tmp, "m7-roa-prefix-outside-ee")

      assert {1, out, err} = run(vrps_args(tals, cache), internal)
      assert out == @header <> "AS1234,1.2.0.0/16,16,case\nAS1234,102::/16,16,case\n"
      assert err =~ "lumina vrps: warning: "
      assert err =~ "more than 10% of the CA certificates and signed objects are invalid"

      assert {0, ^out, _} = run(vrps_args(tals, cache, ["--max-invalid", "50"]), internal)
    end

    @tag :tmp_dir
    test "a TAL with no trust anchor in the cache gives no rows, and exit 1", %{tmp_dir: tmp} do
      tal = Path.join(tmp, "lacnic.tal")
      File.cp!("tals/lacnic.tal", tal)
      cache = Path.join(tmp, "empty")

      assert {1, @header, err} = run(vrps_args(["--tal", tal], cache))
      assert err =~ "lacnic: no VRPs\n"
      assert err =~ "no trust anchor in the cache; run lumina sync first\n"
    end
  end

  describe "Lumina.VRP.csv/2" do
    @tag doc: "Lumina.URI accepts a comma in a path; the field is quoted so the columns hold."
    test "a field holding a comma or a quote is quoted, its quotes doubled" do
      vrp = %{
        asn: 1,
        afi: :ipv4,
        address: 0x0A000000,
        length: 8,
        max_length: 8,
        ta: ~s(my "ta"),
        uri: "rsync://h/m/a,b.roa"
      }

      assert IO.iodata_to_binary(Lumina.VRP.csv([vrp], wide: true)) ==
               "ASN,IP Prefix,Max Length,Trust Anchor,URI\n" <>
                 ~s(AS1,10.0.0.0/8,8,"my ""ta""","rsync://h/m/a,b.roa"\n)
    end
  end

  describe "usage" do
    test "an unknown format is a usage error" do
      assert {2, "", err} = run(["vrps", "--format", "xml", "--tal", "tals/lacnic.tal"])
      assert err =~ ~s(--format must be csv or json, not "xml")
    end

    test "lumina help vrps describes the command and its flags" do
      assert {0, out, ""} = run(["help", "vrps"])
      assert out =~ "Usage: lumina vrps"
      assert out =~ "--output FILE"
      assert out =~ "ASN,IP Prefix,Max Length,Trust Anchor"
      assert out =~ "--wide"
      assert out =~ "--format csv|json"
    end
  end
end
