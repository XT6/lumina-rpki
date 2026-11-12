defmodule Lumina.Fixtures.M0MinimalValidTest do
  @moduledoc """
  Checks that the m0-minimal-valid fixture loads and contains the files Barry
  should produce for a TA -> CA -> ROA tree. This proves the fixture
  pipeline works end to end (descriptor, generation, metadata, test helper)
  before any object is decoded. Decoding and validation start in M1.
  """
  use ExUnit.Case, async: true

  alias Lumina.Test.Fixture

  @fixture Fixture.load!("m0-minimal-valid")

  # One publication point per CA, each with the CRL and manifest Barry adds.
  @rsync_files [
    "ta.cer",
    "ta/ta.crl",
    "ta/ta.mft",
    "ta/ca1.cer",
    "ca1/ca1.crl",
    "ca1/ca1.mft",
    "ca1/roa1.roa"
  ]

  test "loads with its metadata" do
    assert @fixture.id == "m0-minimal-valid"
    assert @fixture.milestone == "M0"
    assert @fixture.expected == :valid
  end

  test "the rsync tree contains exactly the expected objects, each non-empty and readable" do
    found =
      Path.join(@fixture.rsync_root, "**/*")
      |> Path.wildcard()
      |> Enum.filter(&File.regular?/1)
      |> Enum.map(&Path.relative_to(&1, @fixture.rsync_root))
      |> Enum.sort()

    assert found == Enum.sort(@rsync_files)

    for file <- @rsync_files do
      assert {:ok, <<_, _::binary>>} = File.read(Path.join(@fixture.rsync_root, file)),
             "#{file} is empty or unreadable"
    end
  end

  test "RPKI objects are DER: each file starts with a SEQUENCE tag" do
    # Every RPKI object (certificate, CRL, CMS signed object) is an ASN.1
    # SEQUENCE, so its first byte is 0x30. A text-mode checkout that rewrote
    # line endings would usually break this or the lengths that follow.
    for file <- @rsync_files do
      assert <<0x30, _::binary>> = File.read!(Path.join(@fixture.rsync_root, file)), file
    end
  end

  test "the TAL's rsync URI points to the trust anchor certificate in the tree" do
    {uris, _key} = tal_parts(File.read!(@fixture.tal_path))
    assert "rsync://localhost:8873/rpki/ta.cer" in uris

    # Barry serves rsync/ as the rsync module "rpki".
    "rsync://localhost:8873/rpki/" <> path = Enum.find(uris, &String.starts_with?(&1, "rsync://"))
    assert File.regular?(Path.join(@fixture.rsync_root, path))
  end

  test "the TAL's public key is base64 that decodes to a DER SEQUENCE" do
    {_uris, key} = tal_parts(File.read!(@fixture.tal_path))
    assert {:ok, <<0x30, _::binary>>} = Base.decode64(key)
  end

  test "the RRDP files are present" do
    for file <- ["notification.xml", "snapshot.xml"] do
      assert File.regular?(Path.join(@fixture.rrdp_root, file)), file
    end
  end

  # Splits a TAL into its URIs and its base64 key. This only locates the
  # parts for the test; TAL parsing proper is M2.
  defp tal_parts(tal) do
    [uris, key] = String.split(tal, ~r/\r?\n\r?\n/, parts: 2)
    {String.split(uris, ~r/\r?\n/, trim: true), key |> String.split() |> Enum.join()}
  end
end
