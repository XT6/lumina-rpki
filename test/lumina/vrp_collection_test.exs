defmodule Lumina.VRPCollectionTest do
  @moduledoc """
  Tests collecting VRPs in `Lumina.Validate.run/3` (#164): the VRPs of
  the valid ROAs, each with the trust anchor's name (D-032) and the URI
  of the ROA it comes from, in a fixed order (IPv4 first, then address,
  prefix length, maxLength, AS, trust anchor, URI).

  RFC 9582 §4.3.2.2: without maxLength, "the AS is only authorized to
  advertise the exact prefix", so the VRP's maxLength is the prefix
  length. §5: an invalid ROA "in its entirety" gives nothing. Duplicates
  are kept here, one per ROA; the default output lists a VRP once
  (D-033).

  Each test syncs a Barry fixture from a local rsync daemon and validates
  the cache at 2030-01-01.
  """
  use ExUnit.Case, async: true

  doctest Lumina.Validate

  alias Lumina.{Certificate, ManifestState, Sync, TAL, Validate}
  alias Lumina.Test.{Fixture, RsyncDaemon}

  @now ~U[2030-01-01 00:00:00Z]

  # Serves `root` (default the fixture's modules) and syncs it into a
  # cache. Returns the TAL, the cache and the sync options.
  defp synced!(tmp, id, modules \\ nil) do
    fixture = Fixture.load!(id)
    daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), modules || fixture.modules)
    authority = "127.0.0.1:#{daemon.port}"

    {:ok, tal} =
      fixture.tal_path
      |> File.read!()
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(&1, "https://"))
      |> Enum.map_join("\n", &String.replace(&1, "localhost:8873", authority))
      |> TAL.parse()

    cache = Path.join(tmp, "cache")
    opts = [now: @now, remap: %{"localhost:8873" => authority}]
    {:ok, _} = Sync.run([{"case.tal", tal}], cache, opts)
    {tal, cache, opts}
  end

  defp vrps!(tal, cache) do
    {:ok, result} = Validate.run(tal, cache, now: @now, name: "case")
    result.vrps
  end

  defp shown(vrps) do
    for v <- vrps,
        do:
          {"AS#{v.asn}", Lumina.Resources.format_ip({:prefix, v.address, v.length}, v.afi),
           v.max_length, v.ta, Path.basename(v.uri)}
  end

  describe "Validate.run/3" do
    @describetag :rsync
    @describetag :tmp_dir

    @tag rfc: ["9582#4.3.2.2", "9582#4.3.2.1"],
         doc: """
         m1-roa-prefixes: AS64496 with 1.1.0.0/17-24, 1.1.128.0/24 and
         0101::/16-48, IPv4 first and in address order.
         """
    test "a fixture's VRPs are those its valid ROAs state, in order, with trust anchor and URI",
         %{tmp_dir: tmp} do
      {tal, cache, _} = synced!(tmp, "m1-roa-prefixes")

      assert shown(vrps!(tal, cache)) == [
               {"AS64496", "1.1.0.0/17", 24, "case", "roa1.roa"},
               {"AS64496", "1.1.128.0/24", 24, "case", "roa1.roa"},
               {"AS64496", "101::/16", 48, "case", "roa1.roa"}
             ]

      assert [%{uri: "rsync://localhost:8873/rpki/ca1/roa1.roa"} | _] = vrps!(tal, cache)
    end

    @tag rfc: "9582#4.3.2.2",
         doc: "m1-roa-prefixes' 1.1.128.0/24 has no maxLength: the VRP's is 24."
    test "a prefix without maxLength gives a VRP whose maxLength is the prefix length", %{
      tmp_dir: tmp
    } do
      {tal, cache, _} = synced!(tmp, "m1-roa-prefixes")

      assert %{length: 24, max_length: 24} =
               Enum.find(vrps!(tal, cache), &(&1.address == 0x01018000))
    end

    @tag rfc: "9582#5",
         doc: """
         m7-roa-prefix-outside-ee: roa1.roa is invalid (a prefix outside its
         EE certificate), so none of its prefixes count, not even 1.1.0.0/16,
         which is inside; roa2.roa's do.
         """
    test "an invalid ROA contributes no VRPs, and the other ROAs at the point still do", %{
      tmp_dir: tmp
    } do
      {tal, cache, _} = synced!(tmp, "m7-roa-prefix-outside-ee")

      assert shown(vrps!(tal, cache)) == [
               {"AS1234", "1.2.0.0/16", 16, "case", "roa2.roa"},
               {"AS1234", "102::/16", 16, "case", "roa2.roa"}
             ]
    end

    @tag rfc: "9582#5",
         doc: "m7-vrp-duplicate: both ROAs authorize AS64496 for 1.1.0.0/16 (D-033)."
    test "two ROAs stating the same VRP both appear, each with its URI", %{tmp_dir: tmp} do
      {tal, cache, _} = synced!(tmp, "m7-vrp-duplicate")

      assert shown(vrps!(tal, cache)) == [
               {"AS64496", "1.1.0.0/16", 16, "case", "roa1.roa"},
               {"AS64496", "1.1.0.0/16", 16, "case", "roa2.roa"}
             ]
    end

    @tag rfc: ["9286#6.6", "9582#5"],
         doc: """
         A copy of m0-minimal-valid: after a first sync, a newer manifest
         number is recorded for ca1, so the live point is a replay
         (manifest_number_replay, D-024) and its last valid copy stands in
         (D-023). The ROA there is valid and its VRPs count.
         """
    test "a ROA served from its point's last valid copy contributes its VRPs", %{tmp_dir: tmp} do
      copy = Path.join(tmp, "copy")
      File.cp_r!(Fixture.load!("m0-minimal-valid").rsync_root, copy)
      {tal, cache, _} = synced!(tmp, "m0-minimal-valid", %{"rpki" => copy})
      expected = vrps!(tal, cache)
      assert [_ | _] = expected

      {:ok, ca1} = Certificate.decode(File.read!(Path.join(copy, "ta/ca1.cer")))

      :ok =
        ManifestState.record(cache, ca1, %{
          status: :accepted,
          manifest: "rsync://localhost:8873/rpki/ca1/ca1.mft",
          number: 2,
          this_update: ~U[2025-06-01 00:00:00Z]
        })

      {:ok, result} = Validate.run(tal, cache, now: @now, name: "case")
      assert result.fallback == 1
      assert result.vrps == expected
    end
  end

  test "the trust anchor's name is the TAL file's name without .tal (D-032)" do
    assert Validate.ta_name("tals/apnic-rfc7730-https.tal") == "apnic-rfc7730-https"
    assert Validate.ta_name("/x/lacnic.tal") == "lacnic"
  end
end
