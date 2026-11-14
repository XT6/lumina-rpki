defmodule Lumina.TATest do
  @moduledoc """
  Tests TA retrieval (`Lumina.TA`, #74): the TAL's URIs tried in D-003
  order over the real fetchers, each certificate checked against the TAL
  (RFC 8630 §3), the next URI tried on any failure, the accepted
  certificate kept in the cache, and the previous one offered as stale
  when every URI fails.

  HTTPS URIs are served by `Lumina.Test.HTTPSServer` with a CA made in the
  test, rsync URIs by `Lumina.Test.RsyncDaemon`, both serving Barry
  fixture TAs. The fixture TALs name fixed ports, so each test points the
  TAL at its own servers by replacing its URIs; the key stays the
  fixture's.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Cache, TA, TAL, URI}
  alias Lumina.Test.{Fixture, HTTPSServer, RsyncDaemon}
  alias Mix.Lumina.Fixtures

  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]

  defp tal!(id, uris) do
    {:ok, tal} = TAL.decode_file(Fixture.load!(id).tal_path)
    %{tal | uris: uris}
  end

  defp ta_bytes(id), do: File.read!(Path.join(Fixture.load!(id).rsync_root, "ta.cer"))

  # An HTTPS server for `routes`; returns the base URI and the options
  # that make Lumina.HTTPS trust it.
  defp https(routes) do
    pki = HTTPSServer.pki()
    port = HTTPSServer.start!(pki, routes)
    {"https://localhost:#{port}", [https: [cacerts: pki.cacerts]]}
  end

  defp rsync(tmp, id) do
    daemon = RsyncDaemon.start!(Path.join(tmp, id), %{"rpki" => Fixture.load!(id).rsync_root})
    "rsync://127.0.0.1:#{daemon.port}/rpki"
  end

  defp ta_invalid?(%{expected: {:invalid, problems}}),
    do: Enum.any?(problems, &(&1.object == "ta.cer"))

  defp ta_invalid?(_fixture), do: false

  defp closed, do: "https://localhost:#{RsyncDaemon.closed_port()}/ta.cer"

  describe "retrieval" do
    @tag :rsync
    @tag rfc: ["8630#3", "8630#2.3"],
         doc: """
         Fixtures whose TA is expected invalid (m2-ta-*, m4-chain-ta-*) are
         covered by the next tests.
         """
    test "every Barry fixture's TA is retrieved over rsync and stored byte-identical", %{
      tmp_dir: tmp
    } do
      for dir <- Fixtures.case_dirs(),
          id = Path.basename(dir),
          not ta_invalid?(Fixture.load!(id)) do
        root = Path.join(tmp, "cache-" <> id)
        tal = tal!(id, [rsync(tmp, id) <> "/ta.cer"])

        assert {:ok, %{certificate: cert, path: path}} = TA.retrieve(tal, root, now: @now), id
        assert cert.der == ta_bytes(id), id
        assert File.read!(path) == ta_bytes(id), id
      end
    end

    @tag :rsync
    @tag rfc: "8630#3"
    test "a fixture TA that fails the TAL check is fetched but not accepted", %{tmp_dir: tmp} do
      tal = tal!("m2-ta-not-ca", [rsync(tmp, "m2-ta-not-ca") <> "/ta.cer"])

      assert {:error, %{attempts: [attempt], stale: nil}} = TA.retrieve(tal, tmp, now: @now)
      assert %{outcome: :check_failed, detail: [%{rule: :not_ca}]} = attempt
    end

    @tag :rsync
    @tag rfc: ["8630#3", "6487#7.2"],
         doc: "D-014: TAL checks alone (M2) would accept both; validation rejects them."
    test "a TA whose self-signature fails, or that has expired, is fetched but not accepted", %{
      tmp_dir: tmp
    } do
      for {id, rule} <- [
            {"m4-chain-ta-bad-signature", :bad_signature},
            {"m4-chain-ta-expired", :expired}
          ] do
        tal = tal!(id, [rsync(tmp, id) <> "/ta.cer"])

        assert {:error, %{attempts: [attempt], stale: nil}} =
                 TA.retrieve(tal, Path.join(tmp, "cache-" <> id), now: @now),
               id

        assert %{outcome: :check_failed, detail: [%{rule: ^rule}]} = attempt, id
      end
    end

    @tag :rsync
    @tag rfc: "8630#3"
    test "when the first URI is unreachable, the next one is used", %{tmp_dir: tmp} do
      rsync_uri = rsync(tmp, "m0-minimal-valid") <> "/ta.cer"
      tal = tal!("m0-minimal-valid", [closed(), rsync_uri])

      assert {:ok, %{uri: ^rsync_uri, attempts: [first, second]}} =
               TA.retrieve(tal, tmp, now: @now)

      assert %{outcome: :fetch_failed, detail: %{reason: :connection_refused}} = first
      assert %{uri: ^rsync_uri, outcome: :accepted} = second
    end

    @tag rfc: ["8630#3", "8630#2.3"]
    test "a certificate whose key doesn't match is reported, and the next URI is used", %{
      tmp_dir: tmp
    } do
      {base, opts} =
        https(%{
          "/wrong.cer" => {200, [], ta_bytes("m1-roa-prefixes")},
          "/ta.cer" => {200, [], ta_bytes("m0-minimal-valid")}
        })

      tal = tal!("m0-minimal-valid", [base <> "/wrong.cer", base <> "/ta.cer"])

      assert {:ok, %{uri: uri, attempts: [first, _]}} = TA.retrieve(tal, tmp, [now: @now] ++ opts)
      assert uri == base <> "/ta.cer"
      assert %{outcome: :check_failed, detail: problems} = first
      assert :key_mismatch in Enum.map(problems, & &1.rule)
    end

    test "content that isn't a certificate is reported, and the next URI is used", %{
      tmp_dir: tmp
    } do
      {base, opts} =
        https(%{
          "/junk.cer" => {200, [], "not DER"},
          "/ta.cer" => {200, [], ta_bytes("m0-minimal-valid")}
        })

      tal = tal!("m0-minimal-valid", [base <> "/junk.cer", base <> "/ta.cer"])

      assert {:ok, %{attempts: [%{outcome: :decode_failed}, %{outcome: :accepted}]}} =
               TA.retrieve(tal, tmp, [now: @now] ++ opts)
    end

    @tag rfc: "8630#3",
         doc: "D-003: HTTPS first, whatever the TAL order. The rsync URI is never tried."
    test "an HTTPS URI is tried before an rsync URI listed ahead of it", %{tmp_dir: tmp} do
      {base, opts} = https(%{"/ta.cer" => {200, [], ta_bytes("m0-minimal-valid")}})
      tal = tal!("m0-minimal-valid", ["rsync://127.0.0.1:1/rpki/ta.cer", base <> "/ta.cer"])

      assert {:ok, %{attempts: [%{outcome: :accepted}]}} =
               TA.retrieve(tal, tmp, [now: @now] ++ opts)
    end
  end

  describe "the cache" do
    @tag rfc: ["8630#3", "8897#7"],
         doc: "The last accepted TA is kept, byte for byte, and offered as stale with its source."
    test "when every URI fails, the error lists each attempt and the previous TA is kept", %{
      tmp_dir: tmp
    } do
      {base, opts} = https(%{"/ta.cer" => {200, [], ta_bytes("m0-minimal-valid")}})
      good = tal!("m0-minimal-valid", [base <> "/ta.cer"])
      {:ok, %{path: path}} = TA.retrieve(good, tmp, [now: @now] ++ opts)

      dead = %{
        good
        | uris: [closed(), "rsync://127.0.0.1:#{RsyncDaemon.closed_port()}/rpki/ta.cer"]
      }

      assert {:error, %{attempts: [first, second], stale: stale}} =
               TA.retrieve(dead, tmp, now: ~U[2026-11-14 12:00:00Z])

      assert first.outcome == :fetch_failed and second.outcome == :fetch_failed
      assert %{uri: uri, fetched_at: @now, path: ^path} = stale
      assert uri == base <> "/ta.cer"
      assert stale.certificate.der == ta_bytes("m0-minimal-valid")
      assert File.read!(path) == ta_bytes("m0-minimal-valid")
    end

    @tag :rsync
    @tag rfc: ["8630#3", "6487#7.2"]
    test "a previously accepted TA that has since expired is not offered as stale", %{
      tmp_dir: tmp
    } do
      id = "m0-minimal-valid"

      {:ok, %{certificate: cert}} =
        TA.retrieve(tal!(id, [rsync(tmp, id) <> "/ta.cer"]), tmp, now: @now)

      tal = tal!(id, [closed()])

      assert {:error, %{stale: %{certificate: ^cert}}} = TA.retrieve(tal, tmp, now: @now)

      assert {:error, %{stale: nil}} =
               TA.retrieve(tal, tmp, now: DateTime.add(cert.not_after.at, 1))
    end

    test "when every URI fails and nothing was cached, there is no stale TA", %{tmp_dir: tmp} do
      tal = tal!("m0-minimal-valid", [closed()])

      assert {:error, %{attempts: [%{outcome: :fetch_failed}], stale: nil}} =
               TA.retrieve(tal, tmp, now: @now)
    end

    @tag doc: "A TA rejected later must not replace the one accepted before."
    test "a rejected certificate never replaces the accepted one", %{tmp_dir: tmp} do
      {base, opts} =
        https(%{
          "/ta.cer" => {200, [], ta_bytes("m0-minimal-valid")},
          "/wrong.cer" => {200, [], ta_bytes("m1-roa-prefixes")}
        })

      tal = tal!("m0-minimal-valid", [base <> "/ta.cer"])
      {:ok, %{path: path}} = TA.retrieve(tal, tmp, [now: @now] ++ opts)

      assert {:error, %{stale: %{path: ^path}}} =
               TA.retrieve(%{tal | uris: [base <> "/wrong.cer"]}, tmp, [now: @now] ++ opts)

      assert File.read!(path) == ta_bytes("m0-minimal-valid")
    end

    test "each URI's outcome is recorded in the cache status", %{tmp_dir: tmp} do
      {base, opts} = https(%{"/ta.cer" => {200, [], ta_bytes("m0-minimal-valid")}})
      dead = closed()
      tal = tal!("m0-minimal-valid", [dead, base <> "/ta.cer"])
      {:ok, _} = TA.retrieve(tal, tmp, [now: @now] ++ opts)

      {:ok, dead_uri} = URI.parse(dead)
      {:ok, good_uri} = URI.parse(base <> "/ta.cer")
      assert {:error, "{:fetch_failed, %{" <> _} = Cache.status(tmp, dead_uri).outcome
      assert %{outcome: :ok, last_success: @now} = Cache.status(tmp, good_uri)
    end
  end
end
