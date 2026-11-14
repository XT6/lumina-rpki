defmodule Lumina.M4DoneTest do
  @moduledoc """
  The end-to-end check that closes M4, certificates and CRLs (#115). It
  runs `lumina sync` and then `lumina validate` (`Lumina.CLI.run/4`) the
  way a user would, over the whole M4 pipeline: TA validation, the walk
  through valid CAs, and offline validation of every CA and EE
  certificate in the cache.

    * Every Barry fixture is synced from a local rsync daemon and
      validated at 2030-01-01, the time the chain and profile tests use.
      The certificates found invalid must be exactly those the fixture's
      `expected` metadata names with a `rule`, each rejected for that
      rule (since #131 that includes the CMS envelope of signed objects,
      the `m5-cms-*` fixtures); a fixture with nothing invalid must
      validate completely.
    * RFC 6487 §4, §5 and §7.2, RFC 7935 §2 and §3, and RFC 9829 §3 are
      covered by tests other than this one.
    * Tagged `:network`, run by hand only (`mix test --only network`):
      the live LACNIC repository is synced from `tals/lacnic.tal` and
      validated; the counts and every invalid certificate are printed.

  The individual behaviours are tested in detail elsewhere (`ChainTest`,
  `ProfileTest`, `WalkTest`, `CLIValidateTest`, ...). This module checks
  that they hold together, over all the data at once.
  """
  use ExUnit.Case, async: true

  alias Lumina.{CLI, TAL, Validate}
  alias Lumina.Test.{Fixture, RsyncDaemon}
  alias Mix.Lumina.{Fixtures, RFC, TestScanner}

  @moduletag :tmp_dir
  @now ~U[2030-01-01 00:00:00Z]

  defp run(args, internal) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(args, out, err, internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  # Serves `fixture` over rsync, writes its TAL pointing at the daemon
  # (rsync only), syncs it with lumina sync and validates the cache with
  # lumina validate. Returns both CLI results, the TAL and the cache.
  defp sync_and_validate!(tmp, fixture) do
    work = Path.join(tmp, fixture.id)
    daemon = RsyncDaemon.start!(Path.join(work, "daemon"), fixture.modules)
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

    cache = Path.join(work, "cache")
    internal = [now: @now, remap: %{"localhost:8873" => authority}]
    sync = run(["sync", "--cache", cache, "--tal", tal], internal)
    validate = run(["validate", "--cache", cache, "--tal", tal], internal)
    {sync, validate, tal, cache}
  end

  defp uri(object), do: "rsync://localhost:8873/rpki/" <> object

  # The rejects the fixture states as verdicts lumina validate gives: on
  # certificates, on signed objects' CMS envelopes (#131) and, through
  # each point's manifest entry, on publication points (#134).
  defp ruled(%{expected: {:invalid, rejects}}),
    do: Enum.filter(rejects, &Map.has_key?(&1, :rule))

  defp ruled(_fixture), do: []

  defp errors(problems), do: for(%{severity: :error} = p <- problems, do: p)

  # The certificates a ruled reject makes invalid, as {uri, check}: the
  # certificate itself, or for a CRL every certificate validated in its
  # directory, invalid because of that CRL.
  defp expected_invalid(reject, certificates) do
    if Path.extname(reject.object) == ".crl" do
      dir = uri(Path.dirname(reject.object)) <> "/"

      for %{uri: uri} <- certificates, String.starts_with?(uri, dir) do
        {uri,
         fn problems ->
           Enum.any?(
             errors(problems),
             &(&1.rule == :crl_invalid and &1.message =~ Atom.to_string(reject.rule))
           )
         end}
      end
    else
      [
        {uri(reject.object),
         fn problems -> Enum.any?(errors(problems), &(&1.rule == reject.rule)) end}
      ]
    end
  end

  @tag :rsync
  @tag rfc: ["6487#4", "6487#5", "6487#7.2", "7935#2", "7935#3", "9829#3.1", "9829#3.2"],
       doc: """
       Driven by the fixture metadata. A fixture whose rejected TA has a
       rule: sync exits 1 naming the rule, and validate finds no TA. Every
       other fixture: sync and validate agree, the certificates validate
       finds invalid are exactly those the ruled rejects name (rejects
       without a rule are later milestones' checks or lie below an invalid
       CA), each for its rule, nothing fails to decode, and validate
       exits 1 exactly when something is invalid (each fixture's invalid
       share is above D-022's 10%).
       """
  test "every Barry fixture syncs and validates to the verdicts its metadata states", %{
    tmp_dir: tmp
  } do
    {fixtures, []} = Fixtures.load_all()

    outcomes =
      for meta <- fixtures do
        fixture = Map.merge(meta, Fixture.load!(meta.id))

        {{sync_code, sync_out, ""}, {code, out, ""}, tal, cache} =
          sync_and_validate!(tmp, fixture)

        rejects = ruled(fixture)

        case Enum.find(rejects, &(&1.object == "ta.cer")) do
          %{rule: rule} ->
            assert sync_code == 1, fixture.id
            assert sync_out =~ "check_failed (#{rule})", "#{fixture.id}:\n#{sync_out}"
            assert code == 1, fixture.id
            assert out =~ "  ta: none in the cache; run lumina sync first\n", fixture.id
            :ta_rejected

          nil ->
            {:ok, tal} = TAL.decode_file(tal)
            assert {:ok, result} = Validate.run(tal, cache, now: @now), fixture.id
            assert result.ta.valid, fixture.id

            refute Enum.any?(result.objects, &(&1.kind == :decode_failed)), fixture.id

            expected = Enum.flat_map(rejects, &expected_invalid(&1, result.objects))
            invalid = for %{valid: false} = c <- result.objects, into: %{}, do: {c.uri, c}

            assert Enum.sort(Map.keys(invalid)) ==
                     expected |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> Enum.sort(),
                   "#{fixture.id}:\n#{out}"

            for {uri, check} <- expected,
                do: assert(check.(invalid[uri].problems), "#{fixture.id} #{uri}:\n#{out}")

            if expected == [] do
              assert code == 0, "#{fixture.id}:\n#{out}"
              :valid
            else
              assert code == 1, "#{fixture.id}:\n#{out}"
              :invalid
            end
        end
      end

    assert Enum.count(outcomes, &(&1 == :ta_rejected)) >= 5
    assert Enum.count(outcomes, &(&1 == :invalid)) >= 25
    assert Enum.count(outcomes, &(&1 == :valid)) >= 12
  end

  @tag doc: """
       The coverage `mix lumina.rfc_coverage` reports, computed the same way,
       ignoring this module's own tags. A section counts as covered by a
       test of it or of one of its subsections.
       """
  test "RFC 6487 §4, §5 and §7.2, RFC 7935 §2 and §3, and RFC 9829 §3 are covered by other tests" do
    {modules, []} = TestScanner.scan_dir("test")

    covered =
      for test <- TestScanner.tests(modules),
          test.module != inspect(__MODULE__),
          string <- test.refs,
          {:ok, %{rfc: rfc, section: section}} <- [RFC.parse(string)],
          do: {rfc, section}

    for {rfc, section} <- [
          {6487, "4"},
          {6487, "5"},
          {6487, "7.2"},
          {7935, "2"},
          {7935, "3"},
          {9829, "3"}
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

    @tag rfc: ["6487#7.2", "6481#5"],
         doc: """
         Run by hand: mix test --only network. Needs the Internet; takes
         minutes. Syncs LACNIC and validates the cache, printing the
         summary. Every CA certificate under LACNIC's own repository must
         validate; delegated repositories may hold faults (in 2026-11, 21
         expired manifests at one of them), printed but not failing the
         test as long as the share stays within D-022's 10%.
         """
    test "the live LACNIC repository syncs and validates from tals/lacnic.tal", %{tmp_dir: tmp} do
      cache = Path.join(tmp, "cache")
      {sync_code, _out, ""} = run(["sync", "--cache", cache, "--tal", "tals/lacnic.tal"], [])
      assert sync_code in [0, 1]

      {code, out, ""} = run(["validate", "--cache", cache, "--tal", "tals/lacnic.tal"], [])
      IO.puts(out)
      assert code == 0

      {:ok, tal} = TAL.decode_file("tals/lacnic.tal")
      assert {:ok, result} = Validate.run(tal, cache)
      assert result.ta.valid

      cas = Enum.filter(result.objects, &(&1.kind == :ca))
      assert Enum.count(cas, & &1.valid) >= 1_000

      refute Enum.any?(
               cas,
               &(not &1.valid and &1.uri =~ ~r"\Arsync://repository\.lacnic\.net/")
             ),
             out
    end
  end
end
