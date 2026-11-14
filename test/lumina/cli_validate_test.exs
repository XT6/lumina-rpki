defmodule Lumina.CLIValidateTest do
  @moduledoc """
  Tests offline validation of the cache (#114, D-014): `Lumina.Validate.run/3`
  and `lumina validate` through `Lumina.CLI.run/4`.

  Each test first fills a cache with a sync of a Barry fixture from a
  local rsync daemon (as `Lumina.CLISyncTest` does), then validates that
  cache without fetching. Validation must give the same verdicts on CA
  certificates as the walk gave during the sync, and adds the EE
  certificates of signed objects.

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
    code = CLI.run(args, out, err, [now: @now] ++ internal)
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

  defp invalid(certificates, kind),
    do: for(%{kind: ^kind, valid: false, uri: uri} <- certificates, do: uri)

  describe "verdicts" do
    @tag :rsync
    @tag rfc: ["6487#7.2", "6481#5"],
         doc: """
         Every fixture whose TA a sync accepts. The CA certificates found
         invalid offline are exactly those the walk reported invalid, and a
         positive fixture has no invalid certificate at all, EE certificates
         included.
         """
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

          assert invalid(result.certificates, :ca) == walk_invalid, id

          if Fixture.load!(id).expected == :valid do
            assert invalid(result.certificates, :ee) == [], id
            refute Enum.any?(result.certificates, &(&1.kind == :decode_failed)), id
          end
        end
      end
    end

    @tag :rsync
    @tag rfc: ["6487#7.2", "9829#3.2"]
    test "an invalid CA is listed with its reasons, nothing below it is validated, exit 1", %{
      tmp_dir: tmp
    } do
      {tal, cache, _report} = synced!(tmp, "m4-chain-revoked-ca")

      assert {1, out, ""} = run(["validate", "--cache", cache, "--tal", tal])

      assert out =~ ~r"  ta: rsync://127\.0\.0\.1:\d+/rpki/ta\.cer: valid\n"
      assert out =~ "  CA certificates: 1 valid, 1 invalid\n"
      assert out =~ "    invalid: rsync://localhost:8873/rpki/ta/ca1.cer (revoked)\n"
      # ta.mft and ca2.mft; ca1.mft is below the revoked CA.
      assert out =~ "  EE certificates: 2 valid, 0 invalid\n"
    end

    @tag :rsync
    @tag rfc: ["6487#7.2", "6487#4"],
         doc: "m0-minimal-valid: ca1, and the EE certificates of two manifests and a ROA."
    test "a valid tree exits 0 and counts CA and EE certificates", %{tmp_dir: tmp} do
      {tal, cache, _report} = synced!(tmp, "m0-minimal-valid")

      assert {0, out, ""} = run(["validate", "--cache", cache, "--tal", tal])

      assert out =~
               "  CA certificates: 1 valid, 0 invalid\n  EE certificates: 3 valid, 0 invalid\n"

      assert out =~ "1 TAL(s), 4 certificate(s) valid, 0 invalid, at 2026-11-13T12:00:00Z\n"
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
      assert out =~ "0 certificate(s) valid, 0 invalid, at 2036-06-01T00:00:00Z\n"
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

  describe "failures and usage" do
    test "a cache without the TAL's TA exits 1 and says to sync first", %{tmp_dir: tmp} do
      tal = Fixture.load!("m0-minimal-valid").tal_path

      assert {1, out, ""} = run(["validate", "--cache", Path.join(tmp, "empty"), "--tal", tal])
      assert out =~ "  ta: none in the cache; run lumina sync first\n"
    end

    @tag :rsync
    @tag rfc: "6481#5"
    test "a valid CA whose publication point isn't in the cache is reported missing, exit 1", %{
      tmp_dir: tmp
    } do
      {tal, cache, _report} = synced!(tmp, "m0-minimal-valid")
      File.rm_rf!(Path.join(cache, "rsync/localhost:8873/rpki/ca1"))

      assert {1, out, ""} = run(["validate", "--cache", cache, "--tal", tal])
      assert out =~ "    missing: rsync://localhost:8873/rpki/ca1\n"
    end

    test "a bad --now, an unknown flag or a stray argument is a usage error", %{tmp_dir: tmp} do
      tal = Fixture.load!("m0-minimal-valid").tal_path

      assert {2, "", err} = run(["validate", "--tal", tal, "--now", "tomorrow"])
      assert err =~ "--now must be an ISO 8601 time"

      assert {2, "", err} = run(["validate", "--fetch"])
      assert err =~ "unknown or invalid flag --fetch"

      assert {2, "", err} = run(["validate", "--cache", tmp, "extra"])
      assert err =~ "unexpected argument extra"
    end

    test "lumina help validate describes the flags and exit codes" do
      assert {0, out, ""} = run(["help", "validate"])
      assert out =~ "Usage: lumina validate [--cache DIR] [--tal FILE]... [--now TIME]"
      assert out =~ "Exit codes: 0 everything valid, 1 something invalid or missing"

      assert {0, out, ""} = run(["help"])
      assert out =~ "validate  validate the certificates in the local cache, offline"
    end
  end
end
