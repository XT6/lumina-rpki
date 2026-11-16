defmodule Lumina.M7DoneTest do
  @moduledoc """
  The end-to-end check that closes M7, ROAs and VRP output (#170): "a full
  run from TALs to VRPs works against live RIR repositories". It runs
  `lumina sync` and then `lumina vrps` (`Lumina.CLI.run/4`) the way a user
  would.

    * Every Barry fixture is synced from a local rsync daemon and its VRPs
      written at 2030-01-01, as CSV and as JSON. Each fixture gives exactly
      the VRPs its metadata states (`vrps:` in `case.exs`, required for a
      fixture with ROAs), none from an invalid ROA.
    * RFC 9582 §4 and §5 are covered by tests other than this one.
    * Tagged `:network`, run by hand only (`mix test --only network`): the
      five RIR TALs in `tals/` are synced and their VRPs compared with
      Routinator's live CSV (#168, D-035). Per trust anchor, the VRPs only
      one side has are at most 1% of that side's; if not, the CSV is
      downloaded again once and compared again, to rule out drift between
      the two snapshots.

  ROA decoding, validation and VRP output are tested in detail elsewhere
  (`ROATest`, `ROAValidationTest`, `VRPCollectionTest`, `CLIVRPsTest`,
  `VRPCompareTest`). This module checks that they hold together, over all
  the data at once, and against the live repositories.
  """
  use ExUnit.Case, async: true

  alias Lumina.{CLI, VRPCompare}
  alias Lumina.Test.{Fixture, RsyncDaemon}
  alias Mix.Lumina.{Fixtures, RFC, TestScanner}

  @moduletag :tmp_dir
  @now "2030-01-01T00:00:00Z"

  # Fixture directories published on a second host (as in M3DoneTest),
  # served here so that every fixture's VRPs are reachable: the directory
  # under rsync/ and the authority the certificates name, module "repo".
  @elsewhere %{
    "m3-walk-delegation" => {"other", "other.example:8873"},
    "m3-walk-unreachable" => {"unreachable", "unreachable.invalid"},
    "m3-walk-silent-branch" => {"silent", "silent.example:8873"}
  }

  # The trust anchors of tals/, as the reference names them.
  @rirs ["afrinic", "apnic", "arin", "lacnic", "ripe"]

  defp run(args, internal) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(Lumina.Test.Quiet.args(args), out, err, internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  # Serves `fixture` over rsync (a second daemon for a fixture in
  # @elsewhere), writes its TAL pointing at the daemon (rsync only) as
  # case.tal, so its trust anchor is "case", and syncs it with lumina sync.
  # Returns the arguments for lumina vrps and the internal options.
  defp synced!(tmp, fixture) do
    work = Path.join(tmp, fixture.id)
    daemon = RsyncDaemon.start!(Path.join(work, "daemon"), fixture.modules)
    authority = "127.0.0.1:#{daemon.port}"

    remap =
      case @elsewhere[fixture.id] do
        {dir, other} ->
          served = %{"repo" => Path.join(fixture.rsync_root, dir)}
          %{other => "127.0.0.1:#{RsyncDaemon.start!(Path.join(work, dir), served).port}"}

        nil ->
          %{}
      end

    tal = Path.join(work, "case.tal")

    File.write!(
      tal,
      fixture.tal_path
      |> File.read!()
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(&1, "https://"))
      |> Enum.map_join(
        "\n",
        &String.replace(&1, "rsync://localhost:8873/", "rsync://#{authority}/")
      )
    )

    cache = Path.join(work, "cache")
    {:ok, now, 0} = DateTime.from_iso8601(@now)
    internal = [now: now, remap: Map.put(remap, "localhost:8873", authority)]
    _ = run(["sync", "--cache", cache, "--tal", tal], internal)
    {["vrps", "--cache", cache, "--tal", tal, "--now", @now], internal}
  end

  # The rows of a lumina vrps CSV, without the header.
  defp rows(csv), do: csv |> String.split("\n", trim: true) |> tl()

  # The path under rsync/ of an object's URI.
  defp object(fixture, "rsync://localhost:8873/" <> rest) do
    case String.split(rest, "/", parts: 2) do
      ["rpki", path] -> path
      [module, path] -> Path.join(Map.fetch!(fixture.rsync_modules, module), path)
    end
  end

  defp object(fixture, uri) do
    {dir, authority} = Map.fetch!(@elsewhere, fixture.id)
    "rsync://" <> rest = uri
    [^authority, "repo", path] = String.split(rest, "/", parts: 3)
    Path.join(dir, path)
  end

  defp rejected(%{expected: {:invalid, rejects}}), do: Enum.map(rejects, & &1.object)
  defp rejected(_fixture), do: []

  @tag :rsync
  @tag rfc: ["9582#4", "9582#5", "9582#4.3.2.2"],
       doc: """
       Driven by the fixture metadata, at 2030-01-01: for every fixture,
       lumina vrps writes as CSV exactly the VRPs its `vrps:` states (none
       for a fixture without one), each once, all under the trust anchor
       "case"; the JSON output has the same rows; --wide names only ROAs
       that no reject in the metadata names, so no VRP comes from an
       invalid ROA. The expected VRPs were checked, when written, against
       the payloads of the ROAs that no reject names and that lie below no
       rejected certificate, manifest or CRL.
       """
  # Syncs every fixture; the done tests run at the same time (async).
  @tag timeout: :timer.minutes(5)
  test "every fixture gives exactly the VRPs its metadata states, as CSV and as JSON", %{
    tmp_dir: tmp
  } do
    {fixtures, []} = Fixtures.load_all()

    with_vrps =
      for meta <- fixtures, fixture = Map.merge(meta, Fixture.load!(meta.id)) do
        {args, internal} = synced!(tmp, fixture)
        stated = Map.get(fixture, :vrps, [])

        {_code, csv, _err} = run(args, internal)
        found = for row <- rows(csv), do: String.replace_suffix(row, ",case", "")
        assert Enum.all?(rows(csv), &String.ends_with?(&1, ",case")), "#{fixture.id}:\n#{csv}"
        assert Enum.sort(found) == Enum.sort(stated), "#{fixture.id}:\n#{csv}"
        assert found == Enum.uniq(found), fixture.id

        {_code, json, _err} = run(args ++ ["--format", "json"], internal)

        from_json =
          for %{"asn" => asn, "prefix" => prefix, "maxLength" => max, "ta" => "case"} <-
                JSON.decode!(json)["roas"],
              do: "#{asn},#{prefix},#{max}"

        assert from_json == found, fixture.id

        {_code, wide, _err} = run(args ++ ["--wide"], internal)

        for row <- rows(wide) do
          uri = row |> String.split(",") |> List.last()
          refute object(fixture, uri) in rejected(fixture), "#{fixture.id}: #{row}"
        end

        stated != []
      end

    assert Enum.count(with_vrps, & &1) >= 15
    assert length(with_vrps) >= 90
  end

  @tag doc: """
       The coverage `mix lumina.rfc_coverage` reports, computed the same way,
       ignoring this module's own tags. A section counts as covered by a
       test of it or of one of its subsections.
       """
  test "RFC 9582 §4 and §5 are covered by other tests" do
    {modules, []} = TestScanner.scan_dir("test")

    covered =
      for test <- TestScanner.tests(modules),
          test.module != inspect(__MODULE__),
          string <- test.refs,
          {:ok, %{rfc: rfc, section: section}} <- [RFC.parse(string)],
          do: {rfc, section}

    for section <- ["4", "4.1", "4.2", "4.3", "4.3.1", "4.3.2", "4.3.3", "5"] do
      assert Enum.any?(covered, fn {r, s} ->
               r == 9582 and (s == section or String.starts_with?(s, section <> "."))
             end),
             "RFC 9582 §#{section} isn't covered"
    end
  end

  describe "the five RIRs" do
    @describetag :network
    @describetag timeout: :timer.minutes(90)

    @tag rfc: ["9582#5", "6481#5"],
         doc: """
         Run by hand: mix test --only network. Needs the Internet; takes
         many minutes. Syncs every TAL in tals/ into an empty cache, writes
         the VRPs as CSV, and compares them with Routinator's live CSV per
         trust anchor, printing the run time, the counts and the
         differences. Both commands exit 0: each trust anchor and its own
         publication point synced (D-037), and no trust anchor above
         --max-invalid (D-022). Each of the five has VRPs on both sides.
         """
    test "the five RIRs' VRPs agree with Routinator's live CSV within 1% per trust anchor", %{
      tmp_dir: tmp
    } do
      cache = Path.join(tmp, "cache")
      csv = Path.join(tmp, "vrps.csv")
      started = System.monotonic_time(:second)

      {code, sync_out, _err} = run(["sync", "--cache", cache], [])
      synced = System.monotonic_time(:second)
      # The whole summary stays in the test's tmp dir; the per-TAL lines are printed.
      File.write!(Path.join(tmp, "sync.txt"), sync_out)
      assert code == 0, sync_out

      {code, _out, vrps_err} = run(["vrps", "--cache", cache, "--output", csv], [])
      finished = System.monotonic_time(:second)
      assert code == 0, vrps_err

      {:ok, ours} = VRPCompare.parse(File.read!(csv))
      assert ours.malformed == []

      first = compare(ours)

      results =
        if Enum.all?(first, &within?/1) do
          first
        else
          IO.puts("Outside the 1% bound; downloading the reference again:\n" <> report(first))
          compare(ours)
        end

      IO.puts("""

      sync: #{synced - started} s, vrps: #{finished - synced} s
      #{sync_out |> String.split("\n") |> Enum.reject(&String.starts_with?(&1, "    ")) |> Enum.join("\n")}
      #{vrps_err}
      #{report(results)}\
      """)

      assert Enum.map(results, & &1.ta) == @rirs

      for r <- results do
        assert r.lumina > 0 and r.reference > 0, r.ta
        assert within?(r), report([r])
      end
    end
  end

  # The comparison with a fresh download of the reference, for the five
  # RIRs.
  defp compare(ours) do
    {:ok, text} = VRPCompare.fetch()
    {:ok, reference} = VRPCompare.parse(text)
    ours |> VRPCompare.compare(reference) |> Enum.filter(&(&1.ta in @rirs))
  end

  # At most 1% of each side's VRPs only on that side (D-035).
  defp within?(%{lumina: ours, reference: theirs} = r)
       when is_integer(ours) and is_integer(theirs),
       do: length(r.only_lumina) * 100 <= ours and length(r.only_reference) * 100 <= theirs

  defp within?(_result), do: false

  defp report(results), do: VRPCompare.report(results, 20)
end
