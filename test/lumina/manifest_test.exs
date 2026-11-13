defmodule Lumina.ManifestTest do
  @moduledoc """
  Tests decoding of manifests (RFC 9286). Publication point validation (M5)
  compares each file against the manifest's hash and checks the manifest
  number and times, so these must decode exactly. Decoding is structural:
  an empty file list decodes, and its rejection is validation's job (#37).
  """
  use ExUnit.Case, async: true

  alias Lumina.{Manifest, SignedObject}
  alias Lumina.Test.Fixture

  @fixture Fixture.load!("m0-minimal-valid")
  @sha256 {2, 16, 840, 1, 101, 3, 4, 2, 1}

  defp read(file), do: File.read!(Path.join(@fixture.rsync_root, file))

  defp decode!(file) do
    {:ok, manifest} = Manifest.decode(read(file))
    manifest
  end

  # A bare Manifest eContent from a value, through DER.
  defp econtent(overrides \\ %{}) do
    value =
      Map.merge(
        %{
          manifestNumber: 1,
          thisUpdate: ~c"20260101000000Z",
          nextUpdate: ~c"20360101000000Z",
          fileHashAlg: @sha256,
          fileList: [%{file: ~c"a.roa", hash: <<1::256>>}]
        },
        overrides
      )

    {:ok, der} = Lumina.ASN1.encode(:manifest, :Manifest, value)
    der
  end

  describe "the m0-minimal-valid manifests" do
    @tag rfc: ["9286#4.2", "9286#4.2.1", "6481#2.2"],
         doc:
           "Each manifest lists every other file at its publication point; the manifest itself is not listed."
    test "list exactly the other files in their publication points" do
      for {mft, dir} <- [{"ta/ta.mft", "ta"}, {"ca1/ca1.mft", "ca1"}] do
        manifest = decode!(mft)
        published = File.ls!(Path.join(@fixture.rsync_root, dir)) -- [Path.basename(mft)]

        assert Enum.sort(Manifest.names(manifest)) == Enum.sort(published), mft
      end
    end

    @tag rfc: ["9286#4.2.1", "7935#2"],
         doc:
           "Decode sanity only: each listed hash equals the SHA-256 of the file. Checking it is M5."
    test "each listed hash is the SHA-256 of the file" do
      for {mft, dir} <- [{"ta/ta.mft", "ta"}, {"ca1/ca1.mft", "ca1"}],
          %{name: name, hash: hash} <- decode!(mft).files do
        assert hash == :crypto.hash(:sha256, read(Path.join(dir, name))), "#{dir}/#{name}"
      end
    end

    @tag rfc: "9286#4.2.1"
    test "version, manifest number, times and hash algorithm" do
      manifest = decode!("ca1/ca1.mft")

      assert %Manifest{version: 0, number: 1, file_hash_alg: @sha256} = manifest

      assert {manifest.this_update.at, manifest.next_update.at} ==
               {~U[2026-01-01 00:00:00Z], ~U[2036-01-01 00:00:00Z]}

      assert manifest.this_update.format == :generalized_time
      assert %SignedObject{} = manifest.object
      assert Manifest.hash(manifest, "ca1.crl") == :crypto.hash(:sha256, read("ca1/ca1.crl"))
      assert Manifest.hash(manifest, "nope.roa") == nil
    end
  end

  describe "structural decoding" do
    @tag rfc: ["9286#A", "9286#7"],
         doc: """
         The module allows SIZE (0..MAX). Verified erratum 7118 and §7 forbid an
         empty list, but rejecting it is M5's job (#37, F-001), so it must decode.
         """
    test "an empty file list decodes to no files" do
      assert {:ok, %Manifest{files: []}} = Manifest.decode_econtent(econtent(%{fileList: []}))
    end

    @tag rfc: "9286#4.2.1",
         doc: "Manifest numbers up to 20 octets MUST be processable."
    test "a 20-octet manifest number decodes exactly" do
      big = Bitwise.bsl(1, 159) - 1

      assert {:ok, %Manifest{number: ^big}} =
               Manifest.decode_econtent(econtent(%{manifestNumber: big}))
    end

    @tag rfc: "9286#4.2.1"
    test "a non-zero version decodes with that version" do
      assert {:ok, %Manifest{version: 1}} = Manifest.decode_econtent(econtent(%{version: 1}))
    end

    @tag rfc: "9286#A",
         doc:
           "X.690 11.5: version [0] equal to its DEFAULT 0 must not be encoded; only re-encoding catches it."
    test "an explicitly encoded default version is not DER" do
      <<0x30, _len, contents::binary>> = econtent()

      with_default =
        <<0x30, byte_size(contents) + 5, 0xA0, 0x03, 0x02, 0x01, 0x00, contents::binary>>

      assert {:error, {:der, %{rule: :not_canonical}}} = Manifest.decode_econtent(with_default)
    end

    test "a time that isn't a real date is an error" do
      assert Manifest.decode_econtent(econtent(%{thisUpdate: ~c"20260230000000Z"})) ==
               {:error, {:invalid_time, "20260230000000Z"}}
    end
  end

  describe "errors" do
    test "a signed object that isn't a manifest" do
      assert Manifest.decode(read("ca1/roa1.roa")) == {:error, {:not_manifest, :roa}}
    end

    test "non-DER and unparseable eContent" do
      assert {:error, {:der, %{rule: :trailing_bytes}}} =
               Manifest.decode_econtent(econtent() <> <<0>>)

      assert {:error, {:asn1, _}} = Manifest.decode_econtent(<<0x30, 0x00>>)
    end
  end
end
