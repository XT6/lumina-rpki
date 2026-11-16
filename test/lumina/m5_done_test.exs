defmodule Lumina.M5DoneTest do
  @moduledoc """
  The end-to-end check that closes M5, signed objects and manifests
  (#138). It runs `lumina sync` and then `lumina validate`
  (`Lumina.CLI.run/4`) the way a user would, over the whole M5 pipeline:
  the CMS envelope of every signed object (RFC 6488, RFC 9589), manifest
  content (RFC 9286 §4), publication point processing (§6, RFC 9981), the
  last valid copy (D-023) and replay protection (D-024).

    * Every Barry fixture is synced from a local rsync daemon and
      validated at 2030-01-01. Each publication point must be accepted or
      failed as the fixture's `expected` metadata states: it fails exactly
      when a reject with a `rule` names its manifest or its CRL. Nothing
      is validated below a failed point, every signed object of an
      accepted point is validated, and the signed objects found invalid
      are exactly those a ruled reject names. (`M4DoneTest` covers the certificates and the
      rejected TAs.)
    * Over one copy of a repository changed between syncs, a point that
      fails, live or as a replay, is served from its last valid copy by
      both commands.
    * RFC 6488 §3, RFC 9589 §4, RFC 9286 §4.2-4.4 and §6, and RFC 9981
      §2-4 are covered by tests other than this one.
    * Tagged `:network`, run by hand only (`mix test --only network`):
      the live LACNIC repository is synced and validated, and its
      publication points accepted, failed (with reasons) and served from
      the last valid copy are printed.

  The individual behaviours are tested in detail elsewhere (`CMSTest`,
  `ManifestCheckTest`, `PublicationPointTest`, `LastValidTest`,
  `ManifestStateTest`, `WalkTest`, ...). This module checks that they hold
  together, over all the data at once.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, CLI, ManifestState, TAL, Validate}
  alias Lumina.Test.{Fixture, RsyncDaemon}
  alias Mix.Lumina.{Fixtures, RFC, TestScanner}

  @moduletag :tmp_dir
  @now ~U[2030-01-01 00:00:00Z]
  @ca1_manifest "rsync://localhost:8873/rpki/ca1/ca1.mft"

  defp run(args, internal) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(Lumina.Test.Quiet.args(args), out, err, internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  # Serves `modules` over rsync and writes `fixture`'s TAL pointing at the
  # daemon (rsync only). Returns the TAL and the CLI's internal options.
  defp serve!(work, fixture, modules) do
    daemon = RsyncDaemon.start!(Path.join(work, "daemon"), modules)
    authority = "127.0.0.1:#{daemon.port}"
    tal = Path.join(work, fixture.id <> ".tal")

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

    {tal, [now: @now, remap: %{"localhost:8873" => authority}]}
  end

  defp uri(object), do: "rsync://localhost:8873/rpki/" <> object

  defp ruled(%{expected: {:invalid, rejects}}),
    do: Enum.filter(rejects, &Map.has_key?(&1, :rule))

  defp ruled(_fixture), do: []

  defp manifest?(%{kind: :object, type: :manifest}), do: true
  defp manifest?(_entry), do: false

  defp signed?(%{kind: :object, type: type}), do: type != :manifest
  defp signed?(_entry), do: false

  defp dir(uri), do: Path.dirname(uri) <> "/"

  defp cache_dir(cache, manifest) do
    {:ok, uri} = Lumina.URI.parse(Path.dirname(manifest))
    Lumina.Cache.path(cache, uri)
  end

  # The file names a manifest in the cache lists.
  defp listed(cache, manifest) do
    path = Path.join(cache_dir(cache, manifest), Path.basename(manifest))
    {:ok, decoded} = Lumina.Manifest.decode(File.read!(path))
    Lumina.Manifest.names(decoded)
  end

  @tag :rsync
  @tag rfc: ["6488#3", "9286#4.4", "9286#6", "9286#6.6"],
       doc: """
       Driven by the fixture metadata; fixtures whose TA is rejected are
       M4DoneTest's. A point fails exactly when a ruled reject names its
       manifest (its CMS envelope, its content, or the point's files) or
       its CRL (which invalidates the manifest's EE certificate). A
       failed point has only its manifest entry, nothing validated below
       it; an accepted point has an entry for every signed object its
       manifest lists (several CAs' manifests may share a directory, #195),
       and those found invalid are exactly the ones a ruled reject names.
       The summary's manifest and ROA counts agree.
       """
  # Syncs every fixture; the done tests run at the same time (async).
  @tag timeout: :timer.minutes(5)
  test "every Barry fixture's publication points and signed objects get the verdicts its metadata states",
       %{tmp_dir: tmp} do
    {fixtures, []} = Fixtures.load_all()

    outcomes =
      for meta <- fixtures,
          fixture = Map.merge(meta, Fixture.load!(meta.id)),
          rejects = ruled(fixture),
          not Enum.any?(rejects, &(&1.object == "ta.cer")) do
        work = Path.join(tmp, fixture.id)
        {tal, internal} = serve!(work, fixture, fixture.modules)
        cache = Path.join(work, "cache")
        {_code, _out, ""} = run(["sync", "--cache", cache, "--tal", tal], internal)
        {_code, out, ""} = run(["validate", "--cache", cache, "--tal", tal], internal)

        {:ok, tal} = TAL.decode_file(tal)
        {:ok, result} = Validate.run(tal, cache, now: @now)
        named = MapSet.new(rejects, &uri(&1.object))

        # A point fails when its manifest is named, or its CRL: an invalid
        # CRL makes the manifest's EE certificate invalid (D-015).
        crl_dirs = for r <- rejects, Path.extname(r.object) == ".crl", do: dir(uri(r.object))
        fails? = &(&1 in named or dir(&1) in crl_dirs)

        manifests = Enum.filter(result.objects, &manifest?/1)
        failed = for %{valid: false} = m <- manifests, do: m.uri

        assert Enum.sort(failed) ==
                 manifests |> Enum.map(& &1.uri) |> Enum.filter(fails?) |> Enum.sort(),
               "#{fixture.id}:\n#{out}"

        signed = Enum.filter(result.objects, &signed?/1)

        for point <- failed,
            do:
              refute(
                Enum.any?(signed, &(dir(&1.uri) == dir(point))),
                "#{fixture.id}: objects validated below failed #{point}"
              )

        # Several CAs may share a directory, each with its own manifest
        # (RFC 9286 §1, #195): per directory, the signed objects the
        # accepted manifests there list.
        for {directory, accepted} <-
              Enum.group_by(for(%{valid: true, uri: m} <- manifests, do: m), &dir/1) do
          listed =
            for manifest <- accepted,
                name <- listed(cache, manifest),
                Path.extname(name) in [".roa", ".gbr", ".sig", ".tak"],
                uniq: true,
                do: directory <> name

          assert Enum.sort(listed) ==
                   signed
                   |> Enum.map(& &1.uri)
                   |> Enum.filter(&(dir(&1) == directory))
                   |> Enum.sort(),
                 "#{fixture.id} #{directory}"
        end

        invalid = for %{valid: false} = o <- signed, do: o

        for o <- invalid,
            do: assert(o.uri in named, "#{fixture.id}: #{o.uri} invalid:\n#{out}")

        for reject <- rejects, Path.extname(reject.object) in ~w(.roa .gbr .sig .tak) do
          assert %{problems: problems} = Enum.find(invalid, &(&1.uri == uri(reject.object))),
                 "#{fixture.id}: #{reject.object} not invalid"

          assert Enum.any?(problems, &(&1.severity == :error and &1.rule == reject.rule))
        end

        assert out =~
                 "  manifests: #{length(manifests) - length(failed)} valid, #{length(failed)} invalid\n",
               fixture.id

        roas = Enum.filter(signed, &(&1.type == :roa))

        if roas != [],
          do:
            assert(
              out =~
                "  ROAs: #{Enum.count(roas, & &1.valid)} valid, #{Enum.count(roas, &(not &1.valid))} invalid\n",
              fixture.id
            )

        cond do
          failed != [] -> :point_failed
          invalid != [] -> :object_invalid
          true -> :accepted
        end
      end

    assert Enum.count(outcomes, &(&1 == :point_failed)) >= 20
    assert Enum.count(outcomes, &(&1 == :object_invalid)) >= 5
    assert Enum.count(outcomes, &(&1 == :accepted)) >= 30
  end

  @tag :rsync
  @tag rfc: ["9286#6.6", "9286#4.2.1", "6481#5"],
       doc: """
       One copy of m0-minimal-valid, served by a daemon and changed between
       syncs. A ROA that no longer matches its hash, and then (restored) a
       manifest older than the one recorded, each make ca1's point fail;
       sync and validate both serve it from the copy the first sync saved,
       with its ROA still valid, and exit 0.
       """
  test "a point that fails live or as a replay is served from its last valid copy by sync and validate",
       %{tmp_dir: tmp} do
    fixture = Fixture.load!("m0-minimal-valid")
    copy = Path.join(tmp, "copy")
    File.cp_r!(fixture.rsync_root, copy)
    {tal, internal} = serve!(tmp, fixture, %{"rpki" => copy})
    cache = Path.join(tmp, "cache")
    sync = ["sync", "--cache", cache, "--tal", tal]
    validate = ["validate", "--cache", cache, "--tal", tal]

    assert {0, out, ""} = run(sync, internal)
    assert out =~ "  publication points: 2\n"

    roa = Path.join(copy, "ca1/roa1.roa")
    original = File.read!(roa)
    File.write!(roa, "changed", [:append])

    assert {0, out, ""} = run(sync, internal)
    assert out =~ "  publication points: 2 (1 from the last valid copy)\n"
    assert out =~ "    point_fallback: #{@ca1_manifest} (hash_mismatch)\n"

    assert {0, out, ""} = run(validate, internal)
    assert out =~ "  publication points from the last valid copy: 1 "
    assert out =~ "  ROAs: 1 valid, 0 invalid\n"

    # The manifest validated last had number 1; record a later one, as if
    # the repository had moved on and now replays number 1.
    File.write!(roa, original)
    {:ok, ca1} = Certificate.decode(File.read!(Path.join(copy, "ta/ca1.cer")))

    :ok =
      ManifestState.record(cache, ca1, %{
        status: :accepted,
        manifest: @ca1_manifest,
        number: 2,
        this_update: ~U[2025-06-01 00:00:00Z]
      })

    assert {0, out, ""} = run(sync, internal)
    assert out =~ "    point_fallback: #{@ca1_manifest} (manifest_number_replay)\n"

    assert {0, out, ""} = run(validate, internal)
    assert out =~ "  publication points from the last valid copy: 1 "
    assert out =~ "  ROAs: 1 valid, 0 invalid\n"
  end

  @tag doc: """
       The coverage `mix lumina.rfc_coverage` reports, computed the same way,
       ignoring this module's own tags. A section counts as covered by a
       test of it or of one of its subsections.
       """
  test "RFC 6488 §3, RFC 9589 §4, RFC 9286 §4.2-4.4 and §6, and RFC 9981 §2-4 are covered by other tests" do
    {modules, []} = TestScanner.scan_dir("test")

    covered =
      for test <- TestScanner.tests(modules),
          test.module != inspect(__MODULE__),
          string <- test.refs,
          {:ok, %{rfc: rfc, section: section}} <- [RFC.parse(string)],
          do: {rfc, section}

    for {rfc, section} <- [
          {6488, "3"},
          {9589, "4"},
          {9286, "4.2"},
          {9286, "4.2.1"},
          {9286, "4.2.2"},
          {9286, "4.3"},
          {9286, "4.4"},
          {9286, "6"},
          {9286, "6.3"},
          {9286, "6.4"},
          {9286, "6.5"},
          {9286, "6.6"},
          {9981, "2"},
          {9981, "3"},
          {9981, "4"}
        ] do
      assert Enum.any?(covered, fn {r, s} ->
               r == rfc and (s == section or String.starts_with?(s, section <> "."))
             end),
             "RFC #{rfc} §#{section} isn't covered"
    end
  end

  describe "the live LACNIC repository" do
    @describetag :network
    @describetag timeout: :timer.minutes(30)

    @tag rfc: ["9286#6", "6481#5"],
         doc: """
         Run by hand: mix test --only network. Needs the Internet; takes
         minutes. Syncs LACNIC twice into one cache (the second sync can
         serve points from the copies the first saved) and validates it,
         printing the publication points accepted, failed with their
         reasons, and served from the last valid copy. Failures are
         expected to be very few: at most 1% of the points, none in
         LACNIC's own repository.
         """
    test "the live LACNIC repository's publication points are processed", %{tmp_dir: tmp} do
      cache = Path.join(tmp, "cache")
      sync = ["sync", "--cache", cache, "--tal", "tals/lacnic.tal"]
      {code, _out, ""} = run(sync, [])
      assert code in [0, 1]
      {code, sync_out, ""} = run(sync, [])
      assert code in [0, 1]

      {code, out, ""} = run(["validate", "--cache", cache, "--tal", "tals/lacnic.tal"], [])
      assert code == 0, out

      {:ok, tal} = TAL.decode_file("tals/lacnic.tal")
      assert {:ok, result} = Validate.run(tal, cache)
      assert result.ta.valid

      manifests = Enum.filter(result.objects, &manifest?/1)
      failed = Enum.reject(manifests, & &1.valid)

      IO.puts("""
      second sync: #{sync_out |> String.split("\n") |> Enum.find("", &(&1 =~ "publication points"))}
      validate: #{length(manifests)} publication points, #{length(manifests) - length(failed)} accepted (#{result.fallback} from the last valid copy), #{length(failed)} failed
      #{Enum.map_join(failed, "\n", &"  failed: #{&1.uri} (#{&1.problems |> Enum.filter(fn p -> p.severity == :error end) |> Enum.map_join(", ", fn p -> p.rule end)})")}
      """)

      assert length(manifests) >= 1_000
      assert length(failed) * 100 <= length(manifests), out
      refute Enum.any?(failed, &(&1.uri =~ ~r"\Arsync://repository\.lacnic\.net/")), out
    end
  end
end
