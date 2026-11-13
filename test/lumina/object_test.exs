defmodule Lumina.ObjectTest do
  @moduledoc """
  Tests the entry point that decodes any repository file by its extension.
  Repository processing and `lumina --print` go through it, so every
  registered extension must reach the right decoder, a signed object's
  eContent type must agree with its extension, and failures must name the
  layer that failed.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, CRL, Manifest, Object, ROA, SignedObject}
  alias Lumina.Test.Fixture

  @fixture Fixture.load!("m0-minimal-valid")

  defp read(file), do: File.read!(Path.join(@fixture.rsync_root, file))

  # The ROA re-encoded with a different eContent type.
  defp roa_as(content_type_oid) do
    {:ok, ci} = Lumina.ASN1.decode(:cms, :ContentInfo, read("ca1/roa1.roa"))
    {:ok, sd} = Lumina.ASN1.decode(:cms, :SignedData, ci.content)

    {:ok, sd_der} =
      Lumina.ASN1.encode(
        :cms,
        :SignedData,
        put_in(sd.encapContentInfo.eContentType, content_type_oid)
      )

    {:ok, der} = Lumina.ASN1.encode(:cms, :ContentInfo, %{ci | content: sd_der})
    der
  end

  @tag rfc: ["6481#2.2", "6481#7.2"]
  test "every file in every fixture decodes as the type its extension names" do
    files =
      for fixture_dir <- Mix.Lumina.Fixtures.case_dirs(),
          path <- Path.wildcard(Path.join([fixture_dir, "rsync", "**", "*"])),
          File.regular?(path),
          do: path

    assert length(files) > 20

    for path <- files do
      assert {:ok, %Object{type: type, value: value}} = Object.decode_file(path), path

      expected = %{".cer" => Certificate, ".crl" => CRL, ".mft" => Manifest, ".roa" => ROA}
      assert value.__struct__ == expected[Path.extname(path)], path
      assert type == Object.type(path)
    end
  end

  @tag rfc: ["6481#2.2", "6493#9.2", "9323#9.3", "9691#11.3"]
  test "registered extensions map to their types; others are unknown" do
    assert Enum.map(~w(a.cer a.crl a.mft a.roa a.gbr a.sig a.tak), &Object.type/1) ==
             [:certificate, :crl, :manifest, :roa, :ghostbusters, :rsc, :tak]

    assert Object.type("a.asa") == nil
    assert Object.type("a.CER") == nil
    assert Object.decode("a.txt", "x") == {:error, :unknown_type}
  end

  @tag rfc: ["6481#2.2", "6488#2.1.3.1"],
       doc: "A manifest published under a .roa name must not be taken for a ROA."
  test "a signed object whose eContent type disagrees with its extension is rejected" do
    assert Object.decode("x.roa", read("ca1/ca1.mft")) ==
             {:error, {:content_type_mismatch, %{extension: :roa, content_type: :manifest}}}

    assert {:error, {:content_type_mismatch, %{extension: :manifest, content_type: :roa}}} =
             Object.decode("x.mft", read("ca1/roa1.roa"))
  end

  @tag rfc: ["6493#9.2", "9323#9.3", "9691#11.3"],
       doc:
         "Ghostbusters, RSC and TAK eContent is decoded in M9; until then the envelope is decoded and eContent kept raw."
  test "Ghostbusters, RSC and TAK objects decode their envelope only" do
    for {oid, file, type} <- [
          {35, "x.gbr", :ghostbusters},
          {48, "x.sig", :rsc},
          {50, "x.tak", :tak}
        ] do
      der = roa_as({1, 2, 840, 113_549, 1, 9, 16, 1, oid})

      assert {:ok, %Object{type: ^type, value: %SignedObject{econtent: econtent}}} =
               Object.decode(file, der)

      assert is_binary(econtent)
    end
  end

  describe "errors name the layer" do
    test "DER" do
      assert {:error, {:der, %{rule: :trailing_bytes}} = reason} =
               Object.decode("ta.cer", read("ta.cer") <> <<0>>)

      assert Object.layer(reason) == :der
    end

    test "ASN.1" do
      assert {:error, {:asn1, _} = reason} = Object.decode("x.crl", read("ta.cer"))
      assert Object.layer(reason) == :asn1
    end

    test "envelope" do
      {:ok, der} =
        Lumina.ASN1.encode(:cms, :ContentInfo, %{
          contentType: {1, 2, 840, 113_549, 1, 7, 1},
          content: <<4, 0>>
        })

      assert {:error, {:envelope, {:not_signed_data, _}} = reason} = Object.decode("x.roa", der)
      assert Object.layer(reason) == :envelope
    end

    test "eContent" do
      {:ok, ci} = Lumina.ASN1.decode(:cms, :ContentInfo, read("ca1/roa1.roa"))
      {:ok, sd} = Lumina.ASN1.decode(:cms, :SignedData, ci.content)

      {:ok, sd_der} =
        Lumina.ASN1.encode(
          :cms,
          :SignedData,
          put_in(sd.encapContentInfo.eContent, <<0x30, 0x00>>)
        )

      {:ok, der} = Lumina.ASN1.encode(:cms, :ContentInfo, %{ci | content: sd_der})

      assert {:error, {:econtent, _} = reason} = Object.decode("x.roa", der)
      assert Object.layer(reason) == :econtent
    end

    test "type and file" do
      assert Object.layer(:unknown_type) == :type
      assert Object.layer({:content_type_mismatch, %{}}) == :type
      assert {:error, :enoent} = Object.decode_file("/nonexistent/x.cer")
      assert Object.layer(:enoent) == :file
    end
  end
end
