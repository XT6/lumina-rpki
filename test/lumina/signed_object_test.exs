defmodule Lumina.SignedObjectTest do
  @moduledoc """
  Tests decoding of the CMS SignedData envelope shared by all RPKI signed
  objects (RFC 6488, RFC 5652). Signature checks (M5) need the exact signed
  attributes and the EE certificate, and the ROA and manifest decoders need
  the eContent, so the envelope must expose all of them faithfully.
  Profile violations decode; only non-DER or unparseable input fails.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, SignedObject}
  alias Lumina.Test.Fixture

  @fixture Fixture.load!("m0-minimal-valid")
  @objects ["ca1/roa1.roa", "ca1/ca1.mft", "ta/ta.mft"]

  defp read(file), do: File.read!(Path.join(@fixture.rsync_root, file))

  defp decode!(der) do
    {:ok, object} = SignedObject.decode(der)
    object
  end

  # Re-encodes the ROA after changing its decoded SignedData.
  defp reencode(fun) do
    {:ok, ci} = Lumina.ASN1.decode(:cms, :ContentInfo, read("ca1/roa1.roa"))
    {:ok, sd} = Lumina.ASN1.decode(:cms, :SignedData, ci.content)
    {:ok, sd_der} = Lumina.ASN1.encode(:cms, :SignedData, fun.(sd))
    {:ok, der} = Lumina.ASN1.encode(:cms, :ContentInfo, %{ci | content: sd_der})
    der
  end

  describe "the m0-minimal-valid signed objects" do
    @tag rfc: ["6488#2", "6488#2.1", "6488#2.1.1", "6488#2.1.3.1", "6488#2.1.4"]
    test "decode into SignedData with one EE certificate and the eContent type named" do
      for {file, type} <- Enum.zip(@objects, [:roa, :manifest, :manifest]) do
        object = decode!(read(file))

        assert object.content_type == {1, 2, 840, 113_549, 1, 7, 2}, file
        assert object.version == :v3
        assert SignedObject.content_type(object) == type
        assert [%Certificate{}] = object.certificates
        assert object.crls == []
        assert [%{oid: {2, 16, 840, 1, 101, 3, 4, 2, 1}}] = object.digest_algorithms
      end
    end

    @tag rfc: ["6488#2.1.4", "6488#2.1.6.2"],
         doc:
           "The EE certificate keeps the exact bytes from the object; the signer is named by its SKI."
    test "the EE certificate is decoded from the object's bytes, and the signer ID is its SKI" do
      der = read("ca1/roa1.roa")
      object = decode!(der)
      ee = SignedObject.ee_certificate(object)

      assert :binary.match(der, ee.der) != :nomatch
      assert [%{sid: {:subject_key_identifier, ski}}] = object.signers
      assert ski == Certificate.extension_value(ee, :subject_key_identifier)
    end

    @tag rfc: ["6488#2.1.6.4", "6488#2.1.6.4.1", "6488#2.1.6.4.2", "6488#2.1.6.4.3", "9589#4"],
         doc:
           "Decode sanity only: content-type matches eContentType and message-digest is SHA-256 of eContent."
    test "the signed attributes decode: content type, message digest and signing time" do
      for file <- @objects do
        object = decode!(read(file))
        [signer] = object.signers

        assert Enum.map(signer.signed_attrs, & &1.name) == [
                 :content_type,
                 :signing_time,
                 :message_digest
               ]

        assert SignedObject.signed_attribute(object, :content_type) == object.econtent_type

        assert SignedObject.signed_attribute(object, :message_digest) ==
                 :crypto.hash(:sha256, object.econtent)

        assert SignedObject.signed_attribute(object, :signing_time).at == ~U[2026-01-01 00:00:00Z]
      end
    end

    @tag rfc: ["5652#5.4", "6488#2.1.6.4"],
         doc: """
         The signature covers the DER of signedAttrs as a SET OF (tag 0x31), not
         the [0] IMPLICIT form in the object. Checked structurally here; the
         signature itself is verified in M5.
         """
    test "signed_attrs_der is the object's signedAttrs bytes, re-tagged as a SET OF" do
      der = read("ca1/roa1.roa")
      object = decode!(der)
      [signer] = object.signers

      assert <<0x31, rest::binary>> = signer.signed_attrs_der
      assert :binary.match(der, <<0xA0, rest::binary>>) != :nomatch

      raw = for a <- signer.signed_attrs, do: %{attrType: a.oid, attrValues: a.der}
      assert Lumina.ASN1.encode(:cms, :SignedAttributes, raw) == {:ok, signer.signed_attrs_der}
    end

    @tag rfc: ["6488#2.1.6.3", "6488#2.1.6.5", "6488#2.1.6.6", "7935#2"]
    test "the signer's algorithms and signature" do
      [signer] = decode!(read("ca1/ca1.mft")).signers

      assert signer.version == :v3
      assert signer.digest_algorithm.oid == {2, 16, 840, 1, 101, 3, 4, 2, 1}
      assert signer.signature_algorithm.oid == {1, 2, 840, 113_549, 1, 1, 1}
      assert byte_size(signer.signature) == 256
      assert signer.unsigned_attrs == nil
    end
  end

  describe "content types" do
    @tag rfc: ["9582#4", "9286#4"]
    test "decode_econtent/1 decodes ROA and manifest eContent with their ASN.1 types" do
      assert {:ok, %{asID: _, ipAddrBlocks: _}} =
               SignedObject.decode_econtent(decode!(read("ca1/roa1.roa")))

      assert {:ok, %{manifestNumber: _, fileList: _}} =
               SignedObject.decode_econtent(decode!(read("ca1/ca1.mft")))
    end

    test "the content types not decoded until M9 are named but have no decoder" do
      for {oid, name} <- [{35, :ghostbusters}, {48, :rsc}, {50, :tak}] do
        assert SignedObject.content_type({1, 2, 840, 113_549, 1, 9, 16, 1, oid}) == name
      end
    end

    @tag doc:
           "An unknown eContent type is not a decoding error; the envelope decodes and eContent stays raw."
    test "an unknown eContent type decodes the envelope and leaves eContent raw" do
      oid = {1, 3, 6, 1, 4, 1, 99_999, 7}
      object = decode!(reencode(&put_in(&1.encapContentInfo.eContentType, oid)))

      assert SignedObject.content_type(object) == {:unknown, oid}
      assert is_binary(object.econtent)
      assert SignedObject.decode_econtent(object) == {:error, {:no_decoder, {:unknown, oid}}}
    end
  end

  describe "structural decoding" do
    @tag rfc: ["6488#2.1.6.4", "9589#4"],
         doc: "RFC 9589 removed binary-signing-time; it must still decode so M5 can name it."
    test "a forbidden signed attribute decodes and is named" do
      bst = %{
        attrType: {1, 2, 840, 113_549, 1, 9, 16, 2, 46},
        attrValues: [<<2, 4, 0x69, 0x55, 0xB9, 0x00>>]
      }

      object =
        decode!(
          reencode(
            &update_in(&1, [:signerInfos], fn [si] ->
              [%{si | signedAttrs: si.signedAttrs ++ [bst]}]
            end)
          )
        )

      assert :binary_signing_time in Enum.map(hd(object.signers).signed_attrs, & &1.name)
    end

    @tag rfc: ["6488#2.1", "5652#5.1"]
    test "a ContentInfo that isn't SignedData is an error" do
      {:ok, der} =
        Lumina.ASN1.encode(:cms, :ContentInfo, %{
          contentType: {1, 2, 840, 113_549, 1, 7, 1},
          content: <<4, 0>>
        })

      assert SignedObject.decode(der) ==
               {:error, {:not_signed_data, {1, 2, 840, 113_549, 1, 7, 1}}}
    end

    test "an embedded certificate that doesn't decode is an error naming the certificate" do
      der =
        reencode(fn sd ->
          [certificate: cert] = sd.certificates
          bad = put_in(cert.tbsCertificate.validity.notBefore, {:utcTime, ~c"261340000000Z"})
          %{sd | certificates: [certificate: bad]}
        end)

      assert SignedObject.decode(der) ==
               {:error, {:certificate, {:invalid_time, "261340000000Z"}}}
    end

    @tag rfc: "6488#3",
         doc: """
         signedAttrs is an [0] IMPLICIT SET OF, so a schema-less DER walk can't
         see its order (X.690 11.6). Only re-encoding catches unsorted
         attributes, and the signature covers these exact bytes.
         """
    test "signed attributes out of DER order are rejected as not canonical" do
      der = read("ca1/roa1.roa")
      [signer] = decode!(der).signers
      <<0x31, rest::binary>> = signer.signed_attrs_der
      original = <<0xA0, rest::binary>>

      {:ok, attrs} = Lumina.DER.children(<<0x31, rest::binary>>)

      header =
        binary_part(original, 0, byte_size(original) - Enum.sum(Enum.map(attrs, &byte_size/1)))

      swapped = header <> Enum.join(Enum.reverse(attrs))

      bad = :binary.replace(der, original, swapped)
      assert byte_size(bad) == byte_size(der)
      assert {:error, {:der, %{rule: :not_canonical}}} = SignedObject.decode(bad)
    end

    test "non-DER, truncated and unrelated input are errors naming the layer" do
      der = read("ca1/roa1.roa")

      assert {:error, {:der, %{rule: :trailing_bytes}}} = SignedObject.decode(der <> <<0>>)
      assert {:error, {:der, %{rule: :truncated}}} = SignedObject.decode(binary_part(der, 0, 100))
      assert {:error, {:asn1, _}} = SignedObject.decode(<<0x30, 0x03, 0x02, 0x01, 0x05>>)
      assert SignedObject.decode(nil) == {:error, :not_binary}
    end
  end
end
