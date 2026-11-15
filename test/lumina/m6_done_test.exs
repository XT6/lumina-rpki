defmodule Lumina.M6DoneTest do
  @moduledoc """
  The end-to-end check that closes M6, resource inclusion (#156). It runs
  `lumina sync` and then `lumina validate` (`Lumina.CLI.run/4`) the way a
  user would, over the whole M6 pipeline: effective resources with
  `inherit` resolved (#153, D-026), resource inclusion (RFC 6487 §7.2
  point 6, #154, D-028), its reporting (#155) and the manifest EE
  `inherit` warning (#157, D-029).

    * Every Barry fixture is synced from a local rsync daemon and
      validated at 2030-01-01. The M6 fixtures (`m6-overclaim-*`,
      `m6-inherit-*`, `m6-encompass-*`, `m6-mft-ee-*`) give the verdicts
      their metadata states: each overclaim is listed by both commands
      (sync for CA certificates only) with the resources outside its
      issuer's, counted on the `overclaims:` line, and nothing below an
      overclaiming CA is validated. No other fixture gets a
      `resources_not_encompassed` problem, and every valid CA's
      effective resources are within its issuer's.
    * RFC 6487 §7.1 and §7.2, RFC 3779 §2.2.3.5, §2.3, §3.2.3.3 and §3.3
      are covered by tests other than this one.
    * Tagged `:network`, run by hand only (`mix test --only network`):
      the live LACNIC repository is synced and validated, and every
      overclaiming certificate is printed with the resources outside its
      issuer's.

  The individual behaviours are tested in detail elsewhere
  (`EffectiveResourcesTest`, `ResourceSetTest`, `ResourceInclusionTest`,
  `ManifestEEInheritTest`, `CLIValidateTest`, `CLISyncTest`, ...). This
  module checks that they hold together, over all the data at once.
  (`M4DoneTest` and `M5DoneTest` check every fixture's other verdicts.)
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, Chain, CLI, Resources, TAL, Validate}
  alias Lumina.Test.{Fixture, RsyncDaemon}
  alias Mix.Lumina.{Fixtures, RFC, TestScanner}

  @moduletag :tmp_dir
  @now ~U[2030-01-01 00:00:00Z]
  @rule :resources_not_encompassed
  @overclaims "overclaims: "
  @not_held " not held by the issuer"

  defp run(args, internal) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(Lumina.Test.Quiet.args(args), out, err, internal)
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

  defp overclaims(%{expected: {:invalid, rejects}}),
    do: Enum.filter(rejects, &(&1[:rule] == @rule))

  defp overclaims(_fixture), do: []

  defp ta_rejected?(%{expected: {:invalid, rejects}}),
    do: Enum.any?(rejects, &(&1.object == "ta.cer" and Map.has_key?(&1, :rule)))

  defp ta_rejected?(_fixture), do: false

  defp overclaimed?(entry), do: Chain.overclaim?(Map.get(entry, :problems, []))

  # Barry names a CA's certificate after the CA and publishes the CA's
  # objects in a directory of that name: rpki/ca1/ca2.cer is ca2, issued
  # by ca1, publishing under rpki/ca2/.
  defp ca_name(uri), do: Path.basename(uri, ".cer")
  defp issuer_name(uri), do: uri |> Path.dirname() |> Path.basename()

  @tag :rsync
  @tag rfc: ["6487#7.2", "6487#7.1", "3779#2.2.3.5", "3779#2.3", "3779#3.2.3.3", "3779#3.3"],
       doc: """
       Driven by the fixture metadata; fixtures whose TA is rejected are
       M4DoneTest's. For an M6 fixture: validate exits 1 exactly when it
       states a reject; each overclaiming certificate is listed by
       validate, and by sync when it is a CA certificate, as
       `resources_not_encompassed: <the reason without " not held by the
       issuer">`; both print `overclaims: N` with N the overclaims stated
       (sync: the CA certificates among them), or no such line; nothing
       under an overclaiming CA's directory is validated. For every
       fixture: the certificates validate finds overclaiming are exactly
       those an overclaim reject names, and every valid CA's effective
       resources are encompassed by its issuer's (the TA's own for ca1).
       """
  # Syncs every fixture; the done tests run at the same time (async).
  @tag timeout: :timer.minutes(5)
  test "the overclaim and inheritance fixtures get their verdicts, and resource checks reject nothing else",
       %{tmp_dir: tmp} do
    {fixtures, []} = Fixtures.load_all()

    outcomes =
      for meta <- fixtures,
          fixture = Map.merge(meta, Fixture.load!(meta.id)),
          not ta_rejected?(fixture) do
        {{_sync_code, sync_out, ""}, {code, out, ""}, tal, cache} =
          sync_and_validate!(tmp, fixture)

        stated = overclaims(fixture)
        {:ok, decoded} = TAL.decode_file(tal)
        {:ok, result} = Validate.run(decoded, cache, now: @now)

        found = for e <- result.objects, overclaimed?(e), do: e.uri
        assert Enum.sort(found) == Enum.sort(Enum.map(stated, &uri(&1.object))), fixture.id

        {:ok, ta} = Certificate.decode(File.read!(result.ta.path))

        held =
          Map.new(
            [{"ta", Resources.effective(ta, nil)}] ++
              for(
                %{kind: :ca, valid: true} = e <- result.objects,
                do: {ca_name(e.uri), e.resources}
              )
          )

        for %{kind: :ca, valid: true, uri: uri} <- result.objects do
          assert Resources.encompasses?(held[issuer_name(uri)], held[ca_name(uri)]),
                 "#{fixture.id}: #{uri}"
        end

        if fixture.milestone == "M6" do
          ca_claims = Enum.filter(stated, &(Path.extname(&1.object) == ".cer"))

          for reject <- stated do
            line =
              "    invalid: #{uri(reject.object)} " <>
                "(#{@rule}: #{String.replace_suffix(reject.reason, @not_held, "")})\n"

            assert out =~ line, "#{fixture.id}:\n#{out}"
            if reject in ca_claims, do: assert(sync_out =~ line, "#{fixture.id}:\n#{sync_out}")
          end

          for {output, n} <- [{out, length(stated)}, {sync_out, length(ca_claims)}] do
            if n == 0,
              do: refute(output =~ "  " <> @overclaims, fixture.id),
              else: assert(output =~ "  #{@overclaims}#{n} (", "#{fixture.id}:\n#{output}")
          end

          for %{object: object} <- ca_claims do
            below = uri(ca_name(object)) <> "/"
            refute Enum.any?(result.objects, &String.starts_with?(&1.uri, below)), fixture.id
          end

          # Other ruled rejects (m6-inherit-ee's ROA, RFC 9582 §5, #171)
          # fail validate too.
          invalid? = match?({:invalid, [_ | _]}, fixture.expected)
          assert code == if(invalid?, do: 1, else: 0), "#{fixture.id}:\n#{out}"

          cond do
            stated != [] -> :m6_overclaim
            invalid? -> :m6_other_invalid
            true -> :m6_valid
          end
        else
          :other
        end
      end

    assert Enum.count(outcomes, &(&1 == :m6_overclaim)) >= 8
    assert Enum.count(outcomes, &(&1 == :m6_valid)) >= 5
    assert Enum.count(outcomes, &(&1 == :other)) >= 60
  end

  @tag :rsync
  @tag rfc: ["3779#2.2.3.5", "3779#3.2.3.3", "9286#5.1"],
       doc: """
       The effective resources the inheritance fixtures state, as validate
       carries them down: m6-inherit-from-empty's ca2 inherits both
       address families and holds ca1's IPv4 and no IPv6 (D-026); m6-inherit-two-levels' ca3
       holds ca1's resources through ca2.
       """
  test "inherited resources are resolved from the issuer, recursively, end to end", %{
    tmp_dir: tmp
  } do
    resources = fn id ->
      fixture = Fixture.load!(id)
      {_sync, {0, _out, ""}, tal, cache} = sync_and_validate!(tmp, fixture)
      {:ok, tal} = TAL.decode_file(tal)
      {:ok, result} = Validate.run(tal, cache, now: @now)
      for %{kind: :ca} = e <- result.objects, into: %{}, do: {ca_name(e.uri), e.resources}
    end

    empty = resources.("m6-inherit-from-empty")
    assert empty["ca2"].ipv4 == empty["ca1"].ipv4
    assert empty["ca2"].ipv4 != []
    assert empty["ca1"].ipv6 == []
    assert empty["ca2"].ipv6 == []

    two = resources.("m6-inherit-two-levels")
    assert two["ca3"] == two["ca1"]
    assert two["ca2"] == two["ca1"]
  end

  @tag doc: """
       The coverage `mix lumina.rfc_coverage` reports, computed the same way,
       ignoring this module's own tags. A section counts as covered by a
       test of it or of one of its subsections.
       """
  test "RFC 6487 §7.1 and §7.2, RFC 3779 §2.2.3.5, §2.3, §3.2.3.3 and §3.3 are covered by other tests" do
    {modules, []} = TestScanner.scan_dir("test")

    covered =
      for test <- TestScanner.tests(modules),
          test.module != inspect(__MODULE__),
          string <- test.refs,
          {:ok, %{rfc: rfc, section: section}} <- [RFC.parse(string)],
          do: {rfc, section}

    for {rfc, section} <- [
          {6487, "7.1"},
          {6487, "7.2"},
          {3779, "2.2.3.5"},
          {3779, "2.3"},
          {3779, "3.2.3.3"},
          {3779, "3.3"}
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

    @tag rfc: ["6487#7.2", "3779#2.3", "3779#3.3"],
         doc: """
         Run by hand: mix test --only network. Needs the Internet; takes
         minutes. Syncs LACNIC and validates it, printing every
         overclaiming certificate with the resources outside its issuer's.
         Overclaims are expected to be none or very few: at most 0.1% of
         the certificates and signed objects, each one explained when the
         test is run. The summary's overclaims line agrees.
         """
    test "the live LACNIC repository's overclaiming certificates are reported", %{tmp_dir: tmp} do
      cache = Path.join(tmp, "cache")
      {code, _out, ""} = run(["sync", "--cache", cache, "--tal", "tals/lacnic.tal"], [])
      assert code in [0, 1]

      {code, out, ""} = run(["validate", "--cache", cache, "--tal", "tals/lacnic.tal"], [])
      assert code == 0, out

      {:ok, tal} = TAL.decode_file("tals/lacnic.tal")
      assert {:ok, result} = Validate.run(tal, cache)
      assert result.ta.valid

      certificates = Enum.filter(result.objects, &(&1.kind in [:ca, :object]))
      claims = Enum.filter(certificates, &overclaimed?/1)

      IO.puts("""
      validate: #{length(certificates)} certificates and signed objects, #{length(claims)} overclaiming
      #{Enum.map_join(claims, "\n", fn c -> "  overclaim: #{c.uri} (#{c.problems |> Enum.filter(&(&1.rule == @rule)) |> Enum.map_join(", ", &Chain.rule_text/1)})" end)}
      """)

      assert length(certificates) >= 1_000

      if claims == [],
        do: refute(out =~ "  " <> @overclaims),
        else: assert(out =~ "  #{@overclaims}#{length(claims)} (", out)

      assert length(claims) * 1_000 <= length(certificates), out
    end
  end
end
