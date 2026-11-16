defmodule Lumina.CLIValidateTest do
  @moduledoc """
  Tests offline validation of the cache (#114, D-014): `Lumina.Validate.run/3`
  and `lumina validate` through `Lumina.CLI.run/4`.

  Each test first fills a cache with a sync of a Barry fixture from a
  local rsync daemon (as `Lumina.CLISyncTest` does), then validates that
  cache without fetching. Validation must give the same verdicts on CA
  certificates as the walk gave during the sync, and adds the EE
  signed objects (CMS envelope and EE certificate, #131).

  Syncs run at 2026-11-13, inside the fixtures' default validity.
  """
  use ExUnit.Case, async: true

  alias Lumina.{CLI, Sync, TAL, Validate}
  alias Lumina.Test.{Fixture, RsyncDaemon}
  alias Mix.Lumina.Fixtures

  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]

  defp run(args, internal \\ []) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(Lumina.Test.Quiet.args(args), out, err, [now: @now] ++ internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  # Serves fixture `id`, writes a TAL for it whose only URI is rsync at the
  # daemon, and syncs it into `<tmp>/cache`. Returns the TAL path, the
  # cache and the sync report.
  defp synced!(tmp, id) do
    fixture = Fixture.load!(id)
    daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), fixture.modules)
    authority = "127.0.0.1:#{daemon.port}"

    text =
      fixture.tal_path
      |> File.read!()
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(&1, "https://"))
      |> Enum.map_join(
        "\n",
        &String.replace(&1, "rsync://localhost:8873", "rsync://" <> authority)
      )

    path = Path.join(tmp, id <> ".tal")
    File.write!(path, text)
    {:ok, tal} = TAL.decode_file(path)
    cache = Path.join(tmp, "cache")

    {:ok, [report]} =
      Sync.run([{path, tal}], cache, now: @now, remap: %{"localhost:8873" => authority})

    {path, cache, report}
  end

  defp tal!(path) do
    {:ok, tal} = TAL.decode_file(path)
    tal
  end

  defp invalid(objects, kind),
    do: for(%{kind: ^kind, valid: false, uri: uri} <- objects, do: uri)

  describe "verdicts" do
    @tag :rsync
    @tag rfc: ["6487#7.2", "6481#5"],
         doc: """
         Every fixture whose TA a sync accepts. The CA certificates found
         invalid offline are exactly those the walk reported invalid, and a
         positive fixture has nothing invalid at all, signed objects
         included.
         """
    # Syncs every fixture, while the done tests do the same (async): the
    # default 60 s isn't enough under the full suite's load.
    @tag timeout: :timer.minutes(5)
    test "validating a synced cache gives the walk's verdicts on every Barry fixture", %{
      tmp_dir: tmp
    } do
      for dir <- Fixtures.case_dirs(), id = Path.basename(dir) do
        tmp = Path.join(tmp, id)
        {path, cache, report} = synced!(tmp, id)

        with {:ok, _ta} <- report.ta do
          assert {:ok, result} = Validate.run(tal!(path), cache, now: @now), id
          assert result.ta.valid, id
          walk_invalid = for %{kind: :invalid, uri: uri} <- report.walk.issues, do: uri

          assert invalid(result.objects, :ca) == walk_invalid, id

          if Fixture.load!(id).expected == :valid do
            assert invalid(result.objects, :object) == [], id
            refute Enum.any?(result.objects, &(&1.kind == :decode_failed)), id
          end
        end
      end
    end

    @tag :rsync
    @tag rfc: ["6487#7.2", "9829#3.2"],
         doc: "One of four certificates invalid is more than the default 10% (D-022)."
    test "an invalid CA is listed with its reasons, nothing below it is validated, exit 1", %{
      tmp_dir: tmp
    } do
      {tal, cache, _report} = synced!(tmp, "m4-chain-revoked-ca")

      assert {1, out, ""} = run(["validate", "--cache", cache, "--tal", tal])

      assert out =~ ~r"  ta: rsync://127\.0\.0\.1:\d+/rpki/ta\.cer: valid\n"
      assert out =~ "  CA certificates: 1 valid, 1 invalid\n"
      assert out =~ "    invalid: rsync://localhost:8873/rpki/ta/ca1.cer (revoked)\n"
      # ta.mft and ca2.mft; ca1.mft is below the revoked CA.
      assert out =~ "  manifests: 2 valid, 0 invalid\n"
    end

    @tag :rsync
    @tag doc: """
         m4-chain-revoked-ca has one invalid certificate of four (25%):
         --max-invalid 0 and 24 fail, 25 and 100 pass (D-022).
         """
    test "--max-invalid sets the share of invalid certificates a run may have and still exit 0",
         %{tmp_dir: tmp} do
      {tal, cache, _report} = synced!(tmp, "m4-chain-revoked-ca")
      args = ["validate", "--cache", cache, "--tal", tal, "--max-invalid"]

      assert {1, _out, ""} = run(args ++ ["0"])
      assert {1, _out, ""} = run(args ++ ["24"])
      assert {0, out, ""} = run(args ++ ["25"])
      assert out =~ "    invalid: rsync://localhost:8873/rpki/ta/ca1.cer (revoked)\n"
      assert {0, _out, ""} = run(args ++ ["100"])
    end

    @tag :rsync
    @tag rfc: ["6487#7.2", "6487#4"],
         doc: "m0-minimal-valid: ca1, two manifests and a ROA."
    test "a valid tree exits 0 and counts CA certificates and signed objects by type", %{
      tmp_dir: tmp
    } do
      {tal, cache, _report} = synced!(tmp, "m0-minimal-valid")

      assert {0, out, ""} = run(["validate", "--cache", cache, "--tal", tal])

      assert out =~
               "  CA certificates: 1 valid, 0 invalid\n  manifests: 2 valid, 0 invalid\n" <>
                 "  ROAs: 1 valid, 0 invalid\n"

      assert out =~ "1 TAL(s), 4 object(s) valid, 0 invalid, at 2026-11-13T12:00:00Z\n"
    end
  end

  describe "signed objects (#131, #132)" do
    @tag :rsync
    @tag rfc: ["6488#3", "9589#4", "9286#4.4"],
         doc: """
         Driven by the metadata of every m5-cms-* and m5-mft-* fixture: the
         object it names is listed invalid with its (first) rule, and nothing
         else is.
         """
    test "a signed object whose CMS envelope or manifest content is invalid is listed with its rule",
         %{tmp_dir: tmp} do
      ids =
        for dir <- Fixtures.case_dirs(),
            id = Path.basename(dir),
            String.starts_with?(id, "m5-cms-") or String.starts_with?(id, "m5-mft-"),
            do: id

      assert length(ids) >= 15

      for id <- ids do
        {tal, cache, _report} = synced!(Path.join(tmp, id), id)
        {:invalid, [%{object: object, rule: rule} | _]} = Fixture.load!(id).expected

        assert {1, out, ""} = run(["validate", "--cache", cache, "--tal", tal])
        assert [line] = Regex.scan(~r"    invalid: .*\n", out), "#{id}:\n#{out}"
        assert hd(line) =~ "rsync://localhost:8873/rpki/#{object} (", id
        assert hd(line) =~ Atom.to_string(rule), id

        if String.ends_with?(object, ".mft"),
          do: assert(out =~ "  manifests: 1 valid, 1 invalid\n", id),
          else: assert(out =~ "  ROAs: 0 valid, 1 invalid\n", id)
      end
    end
  end

  describe "--now" do
    @tag :rsync
    @tag rfc: "6487#7.2",
         doc: "After the fixtures' notAfter (2036-01-01), the TA itself has expired."
    test "--now after the fixture's expiry finds the TA expired, and nothing below valid", %{
      tmp_dir: tmp
    } do
      {tal, cache, _report} = synced!(tmp, "m0-minimal-valid")

      assert {1, out, ""} =
               run(["validate", "--cache", cache, "--tal", tal, "--now", "2036-06-01"])

      assert out =~ ": INVALID (expired); nothing below it validated\n"
      assert out =~ "0 object(s) valid, 0 invalid, at 2036-06-01T00:00:00Z\n"
    end

    @tag :rsync
    @tag rfc: "6487#7.2",
         doc: "m4-cert-expired's ca1 expires before 2030; the sync, in 2026, followed it."
    test "--now sets the validation time for every certificate", %{tmp_dir: tmp} do
      {tal, cache, report} = synced!(tmp, "m4-cert-expired")
      refute Enum.any?(report.walk.issues, &(&1.kind == :invalid))

      assert {1, out, ""} =
               run(["validate", "--cache", cache, "--tal", tal, "--now", "2030-01-01T00:00:00Z"])

      assert out =~ "    invalid: rsync://localhost:8873/rpki/ta/ca1.cer (expired)\n"
      assert {0, _out, ""} = run(["validate", "--cache", cache, "--tal", tal])
    end
  end

  describe "publication points (#134)" do
    @tag :rsync
    @tag rfc: ["9286#6.3", "9286#6.6"],
         doc: """
         m5-pp-manifest-stale's ca1.mft goes stale on 2027-01-01. The sync
         (2026-11-13) accepted the point; validating at 2030 fails it, and
         its ROA isn't validated.
         """
    test "a point that fails is its manifest's invalid entry, and nothing in it is validated", %{
      tmp_dir: tmp
    } do
      {tal, cache, report} = synced!(tmp, "m5-pp-manifest-stale")
      assert Enum.all?(report.walk.points, &(&1.status == :accepted))

      assert {0, out, ""} = run(["validate", "--cache", cache, "--tal", tal])
      assert out =~ "  manifests: 2 valid, 0 invalid\n  ROAs: 1 valid, 0 invalid\n"

      assert {1, out, ""} =
               run(["validate", "--cache", cache, "--tal", tal, "--now", "2030-01-01"])

      assert out =~ "  manifests: 1 valid, 1 invalid\n"
      refute out =~ "ROAs:"
      assert out =~ "    invalid: rsync://localhost:8873/rpki/ca1/ca1.mft (manifest_stale)\n"
    end

    @tag :rsync
    @tag rfc: "9286#6",
         doc: "Files not on the manifest \"MUST NOT be used\": counted, never validated."
    test "files not on a manifest are counted and not validated", %{tmp_dir: tmp} do
      {tal, cache, _report} = synced!(tmp, "m0-minimal-valid")
      dir = Path.join(cache, "rsync/localhost:8873/rpki/ca1")
      File.write!(Path.join(dir, "junk.roa"), "not DER")

      assert {0, out, ""} = run(["validate", "--cache", cache, "--tal", tal])
      assert out =~ "  files not on a manifest: 1 (not used, RFC 9286 section 6)\n"
      refute out =~ "junk.roa"
    end
  end

  describe "last valid copy (D-023, #135)" do
    @tag :rsync
    @tag rfc: "9286#6.6",
         doc: """
         The sync kept each accepted point. A listed file then changes in
         the mirror: validate falls back to the kept copy, says so, and the
         ROA is still validated.
         """
    test "a point that fails offline is validated from its last valid copy", %{tmp_dir: tmp} do
      {tal, cache, _report} = synced!(tmp, "m0-minimal-valid")
      roa = Path.join(cache, "rsync/localhost:8873/rpki/ca1/roa1.roa")
      File.write!(roa, "changed", [:append])

      assert {0, out, ""} = run(["validate", "--cache", cache, "--tal", tal])
      assert out =~ "  manifests: 2 valid, 0 invalid\n  ROAs: 1 valid, 0 invalid\n"
      assert out =~ "  publication points from the last valid copy: 1 "
      assert out =~ ~r"    warning: rsync://localhost:8873/rpki/ca1/ca1.mft \(last_valid_copy"
    end
  end

  describe "overclaims (#155)" do
    @tag :rsync
    @tag rfc: ["6487#7.2", "3779#2.3"],
         doc: """
         m6-overclaim-ipv4: ca2 claims 2.0.0.0/16, outside ca1's
         1.0.0.0/8. The line names the prefix after the rule, and the TAL
         summary counts one overclaim.
         """
    test "an overclaiming CA certificate is listed with the resources outside its issuer's, and counted",
         %{tmp_dir: tmp} do
      {tal, cache, _report} = synced!(tmp, "m6-overclaim-ipv4")

      assert {1, out, ""} = run(["validate", "--cache", cache, "--tal", tal])

      assert out =~
               "    invalid: rsync://localhost:8873/rpki/ca1/ca2.cer " <>
                 "(resources_not_encompassed: 2.0.0.0/16)\n"

      assert out =~ "  overclaims: 1 (resources outside the issuer's, RFC 6487 section 7.2)\n"
    end

    @tag :rsync
    @tag rfc: ["6487#7.2", "6488#3"],
         doc: "m6-overclaim-roa-ee: the EE certificate of roa1.roa claims 2.0.0.0/16."
    test "a signed object whose EE certificate overclaims is listed with the resources, and counted",
         %{tmp_dir: tmp} do
      {tal, cache, _report} = synced!(tmp, "m6-overclaim-roa-ee")

      assert {1, out, ""} = run(["validate", "--cache", cache, "--tal", tal])

      assert out =~
               "    invalid: rsync://localhost:8873/rpki/ca1/roa1.roa " <>
                 "(resources_not_encompassed: 2.0.0.0/16)\n"

      assert out =~ "  ROAs: 0 valid, 1 invalid\n"
      assert out =~ "  overclaims: 1 (resources outside the issuer's, RFC 6487 section 7.2)\n"
    end

    @tag :rsync
    @tag rfc: ["6487#7.2", "3779#3.3"],
         doc: "m6-overclaim-as-range: only the half of ca2's AS range above ca1's is named."
    test "an AS range partly outside the issuer's is listed as the part outside", %{tmp_dir: tmp} do
      {tal, cache, _report} = synced!(tmp, "m6-overclaim-as-range")

      assert {1, out, ""} = run(["validate", "--cache", cache, "--tal", tal])

      assert out =~
               "    invalid: rsync://localhost:8873/rpki/ca1/ca2.cer " <>
                 "(resources_not_encompassed: AS33554432-AS33554687)\n"
    end

    @tag :rsync
    @tag rfc: "6487#7.2",
         doc: """
         m6-overclaim-grandchild: one invalid object (ca3) of nine, 11%:
         above the default 10%, within --max-invalid 12 (D-022).
         """
    test "an overclaim counts as invalid toward --max-invalid", %{tmp_dir: tmp} do
      {tal, cache, _report} = synced!(tmp, "m6-overclaim-grandchild")
      args = ["validate", "--cache", cache, "--tal", tal]

      assert {1, out, ""} = run(args)
      assert out =~ "1 TAL(s), 8 object(s) valid, 1 invalid, at "
      assert out =~ "  overclaims: 1 (resources outside the issuer's, RFC 6487 section 7.2)\n"
      assert {0, _out, ""} = run(args ++ ["--max-invalid", "12"])
    end

    @tag :rsync
    test "a tree without overclaims prints no overclaims line", %{tmp_dir: tmp} do
      {tal, cache, _report} = synced!(tmp, "m0-minimal-valid")

      assert {0, out, ""} = run(["validate", "--cache", cache, "--tal", tal])
      refute out =~ "  overclaims:"
    end
  end

  describe "failures and usage" do
    test "a cache without the TAL's TA exits 1 and says to sync first", %{tmp_dir: tmp} do
      tal = Fixture.load!("m0-minimal-valid").tal_path

      assert {1, out, ""} = run(["validate", "--cache", Path.join(tmp, "empty"), "--tal", tal])
      assert out =~ "  ta: none in the cache; run lumina sync first\n"
    end

    @tag :rsync
    @tag rfc: "6481#5",
         doc: "Missing publication points are a fetch problem, reported by sync (D-022)."
    test "a valid CA whose publication point isn't in the cache is reported missing, exit 0", %{
      tmp_dir: tmp
    } do
      {tal, cache, _report} = synced!(tmp, "m0-minimal-valid")
      File.rm_rf!(Path.join(cache, "rsync/localhost:8873/rpki/ca1"))

      assert {0, out, ""} = run(["validate", "--cache", cache, "--tal", tal])
      assert out =~ "    missing: rsync://localhost:8873/rpki/ca1\n"
    end

    test "a bad --now or --max-invalid, an unknown flag or a stray argument is a usage error", %{
      tmp_dir: tmp
    } do
      tal = Fixture.load!("m0-minimal-valid").tal_path

      assert {2, "", err} = run(["validate", "--tal", tal, "--now", "tomorrow"])
      assert err =~ "--now must be an ISO 8601 time"

      assert {2, "", err} = run(["validate", "--tal", tal, "--max-invalid", "101"])
      assert err =~ "--max-invalid must be a percentage, 0 to 100"

      assert {2, "", err} = run(["validate", "--tal", tal, "--max-invalid", "ten"])
      assert err =~ "unknown or invalid flag --max-invalid"

      assert {2, "", err} = run(["validate", "--fetch"])
      assert err =~ "unknown or invalid flag --fetch"

      assert {2, "", err} = run(["validate", "--cache", tmp, "extra"])
      assert err =~ "unexpected argument extra"
    end

    test "lumina help validate describes the flags and exit codes" do
      assert {0, out, ""} = run(["help", "validate"])
      assert out =~ "Usage: lumina validate [--cache DIR] [--tal FILE]... [--now TIME]"
      assert out =~ "--max-invalid PERCENT"
      assert out =~ "Exit codes: 0 valid (at most PERCENT invalid objects per TAL;"

      assert {0, out, ""} = run(["help"])
      assert out =~ "validate  validate the certificates and signed objects in the local cache"
    end
  end
end
