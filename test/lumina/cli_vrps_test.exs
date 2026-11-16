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

  alias Lumina.CLI

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
