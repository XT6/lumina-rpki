defmodule Lumina.M3DoneTest do
  @moduledoc """
  The end-to-end check that closes M3, rsync retrieval (#77). It runs
  `lumina sync` (`Lumina.CLI.run/4`) the way a user would, over the whole
  M3 pipeline: TAL, TA retrieval (HTTPS first), repository walk, rsync,
  cache.

    * Every Barry fixture is synced from a local HTTPS server and rsync
      daemon. The mirror must be byte-identical to the fixture's `rsync/`
      tree, the accepted TA identical to its `ta.cer`, and every mirrored
      object must decode (M1). Fixtures whose TA fails the TAL check
      must mirror nothing.
    * RFC 5781 §2, RFC 6481 §3 and §5, and RFC 8630 §3 and §4 are
      covered by tests other than this one.
    * Tagged `:network`, run by hand only (`mix test --only network`):
      the live LACNIC repository is mirrored from `tals/lacnic.tal`.

  The individual behaviours are tested in detail elsewhere (`HTTPSTest`,
  `RsyncTest`, `TATest`, `WalkTest`, `CLISyncTest`). This module checks
  that they hold together, over all the data at once.

  Fixture TALs name `https://localhost:8443` and `rsync://localhost:8873`.
  Each fixture gets its own servers, a copy of its TAL pointing at them,
  and `:remap` for the repository URIs inside its certificates.
  """
  use ExUnit.Case, async: true

  alias Lumina.{CLI, Object, TA, TAL}
  alias Lumina.Test.{Fixture, HTTPSServer, RsyncDaemon}
  alias Mix.Lumina.{Fixtures, RFC, TestScanner}

  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]

  # Fixture directories published somewhere other than localhost:8873/rpki:
  # the second host's authority and module, and whether it is reachable.
  @elsewhere %{
    "m3-walk-delegation" => {"other", "other.example:8873", "repo", :served},
    "m3-walk-unreachable" => {"unreachable", "unreachable.invalid", "repo", :unreachable},
    # silent.example doesn't resolve here; WalkTest points it at a silent server.
    "m3-walk-silent-branch" => {"silent", "silent.example:8873", "repo", :unreachable}
  }

  defp run(args, internal) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(Lumina.Test.Quiet.args(args), out, err, internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  defp tree(dir) do
    for path <- Path.wildcard(Path.join(dir, "**/*"), match_dot: true),
        File.regular?(path),
        into: %{},
        do: {Path.relative_to(path, dir), File.read!(path)}
  end

  # A TA that retrieval rejects: by the TAL check (the M2 fixtures) or by
  # validation, signature or dates (M4, #113).
  defp ta_invalid?(%{expected: {:invalid, problems}}),
    do: Enum.any?(problems, &(&1.object == "ta.cer"))

  defp ta_invalid?(_fixture), do: false

  # Serves `fixture` over HTTPS and rsync, writes its TAL pointing at them,
  # and runs `lumina sync` on it into a fresh cache.
  defp sync!(tmp, fixture) do
    work = Path.join(tmp, fixture.id)
    ta = File.read!(Path.join(fixture.rsync_root, "ta.cer"))
    pki = HTTPSServer.pki()
    https = "localhost:#{HTTPSServer.start!(pki, %{"/rrdp/ta.cer" => {200, [], ta}})}"
    daemon = RsyncDaemon.start!(Path.join(work, "rpki"), fixture.modules)
    rsync = "127.0.0.1:#{daemon.port}"

    remap =
      case @elsewhere[fixture.id] do
        {dir, authority, module, :served} ->
          other =
            RsyncDaemon.start!(Path.join(work, dir), %{
              module => Path.join(fixture.rsync_root, dir)
            })

          %{authority => "127.0.0.1:#{other.port}"}

        _ ->
          %{}
      end

    tal = Path.join(work, fixture.id <> ".tal")

    File.write!(
      tal,
      fixture.tal_path
      |> File.read!()
      |> String.replace("https://localhost:8443/", "https://#{https}/")
      |> String.replace("rsync://localhost:8873/", "rsync://#{rsync}/")
    )

    cache = Path.join(work, "cache")

    result =
      run(["sync", "--cache", cache, "--tal", tal],
        now: @now,
        https: [cacerts: pki.cacerts],
        remap: Map.put(remap, "localhost:8873", rsync)
      )

    {result, cache}
  end

  @tag :rsync
  @tag rfc: ["8630#3", "8630#4", "6481#5", "6481#3", "5781#2"],
       doc: """
       Driven by the fixture metadata. A fixture whose TA is invalid exits 1
       with nothing mirrored. Every other fixture's TA arrives over HTTPS
       (D-003) and its whole repository over rsync. The delegated fixture's
       second host is served too; the unreachable fixtures exit 0 (only a
       delegated host fails, D-037, #187), with the rest mirrored.
       """
  test "every Barry fixture syncs through lumina sync into a byte-identical mirror", %{
    tmp_dir: tmp
  } do
    {fixtures, []} = Fixtures.load_all()

    outcomes =
      for meta <- fixtures do
        fixture = Map.merge(meta, Fixture.load!(meta.id))
        {{code, out, err}, cache} = sync!(tmp, fixture)
        assert err == "", fixture.id
        source = tree(fixture.rsync_root)

        if ta_invalid?(fixture) do
          assert code == 1, fixture.id
          assert out =~ "check_failed", fixture.id
          refute File.exists?(Path.join(cache, "rsync")), fixture.id
          :ta_rejected
        else
          assert out =~ ~r"  ta: https://localhost:\d+/rrdp/ta.cer\n", fixture.id
          assert [ta] = Path.wildcard(Path.join(cache, ".ta/*.cer")), fixture.id
          assert File.read!(ta) == source["ta.cer"], fixture.id

          # Whole modules are mirrored (D-012): rpki is all of rsync/.
          for {name, path} <- fixture.modules do
            assert tree(Path.join(cache, "rsync/localhost:8873/" <> name)) == tree(path),
                   "#{fixture.id} #{name}"
          end

          case @elsewhere[fixture.id] do
            {dir, authority, module, reachable} ->
              mirror = tree(Path.join([cache, "rsync", authority, module]))

              if reachable == :served,
                do: assert(mirror == tree(Path.join(fixture.rsync_root, dir)), fixture.id),
                else: assert(mirror == %{}, fixture.id)

            nil ->
              :ok
          end

          for path <- Path.wildcard(Path.join(cache, "rsync/**/*")), File.regular?(path) do
            assert {:ok, %Object{}} = Object.decode_file(path), path
          end

          assert code == 0, "#{fixture.id}:\n#{out}"

          if match?({_, _, _, :unreachable}, @elsewhere[fixture.id]),
            do: assert(out =~ "warning: some fetches below the trust anchors failed", fixture.id)

          :mirrored
        end
      end

    assert Enum.count(outcomes, &(&1 == :ta_rejected)) >= 3
    assert Enum.count(outcomes, &(&1 == :mirrored)) >= 12
  end

  @tag doc: """
       The coverage `mix lumina.rfc_coverage` reports, computed the same way,
       ignoring this module's own tags.
       """
  test "RFC 5781 §2, RFC 6481 §3 and §5, and RFC 8630 §3 and §4 are covered by other tests" do
    {modules, []} = TestScanner.scan_dir("test")

    covered =
      for test <- TestScanner.tests(modules),
          test.module != inspect(__MODULE__),
          string <- test.refs,
          {:ok, %{rfc: rfc, section: section}} <- [RFC.parse(string)],
          into: MapSet.new(),
          do: {rfc, section}

    for {rfc, section} <- [{5781, "2"}, {6481, "3"}, {6481, "5"}, {8630, "3"}, {8630, "4"}],
        do: assert({rfc, section} in covered, "RFC #{rfc} §#{section} isn't covered")
  end

  describe "the live LACNIC repository" do
    @describetag :network
    @describetag timeout: :timer.minutes(30)

    @tag rfc: ["8630#3", "8630#4", "6481#5"],
         doc: """
         Run by hand: mix test --only network. Needs the Internet; takes
         minutes. Delegated repositories on other hosts may be down, so their
         failures are printed but don't fail the test; LACNIC's own
         repository and TA must arrive. In the local LACNIC copy of
         2026-11 the repository held about 28,000 files.
         ASPA objects (.asa) aren't decoded: ASPA isn't an RFC yet.
         """
    test "the live LACNIC repository mirrors from tals/lacnic.tal and every object decodes", %{
      tmp_dir: tmp
    } do
      cache = Path.join(tmp, "cache")
      {code, out, err} = run(["sync", "--cache", cache, "--tal", "tals/lacnic.tal"], [])
      IO.puts(out)
      assert err == ""
      assert code in [0, 1]

      {:ok, tal} = TAL.decode_file("tals/lacnic.tal")
      assert %{certificate: _} = TA.cached(cache, tal, @now)

      assert out =~ "  ta: https://rrdp.lacnic.net/" or
               out =~ "  ta: rsync://repository.lacnic.net/"

      refute out =~ ~r"fetch_failed: rsync://repository\.lacnic\.net/"
      refute out =~ ~r"missing: rsync://repository\.lacnic\.net/"

      files =
        for path <- Path.wildcard(Path.join(cache, "rsync/**/*")),
            File.regular?(path),
            do: path

      {known, unknown} = Enum.split_with(files, &Object.type/1)

      assert unknown |> Enum.map(&Path.extname/1) |> Enum.uniq() |> Enum.reject(&(&1 == ".asa")) ==
               []

      failures =
        for path <- known,
            result = Object.decode_file(path),
            not match?({:ok, _}, result),
            do: {path, result}

      assert failures == []
      assert length(known) in 15_000..100_000

      for ext <- [".cer", ".crl", ".mft", ".roa"],
          do: assert(Enum.count(known, &(Path.extname(&1) == ext)) >= 1_000, ext)
    end
  end
end
