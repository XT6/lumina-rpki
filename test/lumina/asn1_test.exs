defmodule Lumina.ASN1Test do
  @moduledoc """
  Tests the wrapper around the ASN.1 modules compiled from the RFCs. Every
  RPKI object is decoded through it, so it must decode real objects
  faithfully, reject trailing data that asn1ct would silently ignore, and
  never raise on malformed input, which a validator receives from
  untrusted repositories.
  """
  use ExUnit.Case, async: true
  doctest Lumina.ASN1

  alias Lumina.ASN1
  alias Lumina.Test.Fixture

  @fixture Fixture.load!("m0-minimal-valid")

  defp read(file), do: File.read!(Path.join(@fixture.rsync_root, file))

  describe "real objects" do
    @tag rfc: ["5280#4.1", "5280#A.1"]
    test "decodes the TA certificate and re-encodes it to identical bytes" do
      der = read("ta.cer")

      assert {:ok, %{tbsCertificate: tbs, signatureAlgorithm: _, signature: sig}} =
               ASN1.decode(:pkix, :Certificate, der)

      assert is_bitstring(sig)
      assert %{version: :v3, serialNumber: _, issuer: _, subject: _} = tbs

      assert ASN1.encode(:pkix, :Certificate, elem(ASN1.decode(:pkix, :Certificate, der), 1)) ==
               {:ok, der}
    end

    @tag rfc: ["5280#5.1", "5280#A.1"]
    test "decodes and re-encodes a CRL" do
      der = read("ta/ta.crl")
      assert {:ok, crl} = ASN1.decode(:pkix, :CertificateList, der)
      assert ASN1.encode(:pkix, :CertificateList, crl) == {:ok, der}
    end

    @tag rfc: ["5652#12.1", "9582#4", "9286#A"],
         doc: "A smoke test across modules; CMS, ROA and manifest decoding proper are #29-#31."
    test "decodes the ROA and manifest contents through the CMS envelope" do
      for {file, key, type} <- [
            {"ca1/roa1.roa", :roa, :RouteOriginAttestation},
            {"ca1/ca1.mft", :manifest, :Manifest}
          ] do
        assert {:ok, %{contentType: _, content: signed_data}} =
                 ASN1.decode(:cms, :ContentInfo, read(file))

        assert {:ok, %{encapContentInfo: %{eContent: econtent}}} =
                 ASN1.decode(:cms, :SignedData, signed_data)

        assert {:ok, %{} = value} = ASN1.decode(key, type, econtent), file
        assert ASN1.encode(key, type, value) == {:ok, econtent}
      end
    end
  end

  describe "malformed input" do
    @tag doc: """
         asn1ct decodes the value and silently drops anything after it. A
         validator must not accept an object with appended data, so the
         wrapper compiles with :undec_rest and rejects any leftover.
         """
    test "rejects trailing bytes after a valid value" do
      assert ASN1.decode(:pkix, :Certificate, read("ta.cer") <> <<0, 1>>) ==
               {:error, {:trailing_bytes, 2}}
    end

    test "rejects empty, truncated and garbage input with an error, not an exception" do
      der = read("ta.cer")

      for input <- [
            <<>>,
            binary_part(der, 0, 100),
            binary_part(der, 0, byte_size(der) - 1),
            "garbage",
            <<0x30>>,
            <<0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF>>
          ] do
        assert {:error, {:asn1, _}} = ASN1.decode(:pkix, :Certificate, input),
               inspect(input, limit: 8)
      end
    end

    @tag doc: "Seeded, so the 2000 inputs are the same on every run."
    test "never raises on random bytes" do
      :rand.seed(:exsss, {24, 24, 24})

      for _ <- 1..2000 do
        input = :rand.bytes(:rand.uniform(64))
        assert {:error, _} = ASN1.decode(:pkix, :Certificate, input)
      end
    end

    @tag rfc: ["9582#4", "9582#4.3.1"],
         doc: """
         RFC 9582's module limits addressFamily to IPv4 and IPv6 with an
         information object set, so the generated decoder exits on any other
         AFI (F-012 in doc/rfc-findings.md). The wrapper must turn that exit
         into an error.
         """
    test "a ROA with an address family other than IPv4 or IPv6 is an error, not a crash" do
      {:ok, %{content: signed_data}} = ASN1.decode(:cms, :ContentInfo, read("ca1/roa1.roa"))

      {:ok, %{encapContentInfo: %{eContent: econtent}}} =
        ASN1.decode(:cms, :SignedData, signed_data)

      # addressFamily is an OCTET STRING: 04 02 00 01 is IPv4; make it AFI 3.
      [before, rest] = :binary.split(econtent, <<4, 2, 0, 1>>)
      bad = before <> <<4, 2, 0, 3>> <> rest

      assert {:error, {:asn1, _}} = ASN1.decode(:roa, :RouteOriginAttestation, bad)
    end

    test "reports an unknown module, an unknown type and non-binary input" do
      der = read("ta.cer")
      assert ASN1.decode(:nope, :Certificate, der) == {:error, {:unknown_module, :nope}}
      assert ASN1.decode(:pkix, :NoSuchType, der) == {:error, {:unknown_type, :pkix, :NoSuchType}}
      assert ASN1.decode(:pkix, :Certificate, :not_a_binary) == {:error, :not_binary}
    end

    test "encoding an invalid value returns an error" do
      assert {:error, {:asn1, _}} = ASN1.encode(:pkix, :CertificateSerialNumber, "not an integer")
    end
  end

  test "every module key names a loaded, compiled ASN.1 module" do
    for {key, mod} <- ASN1.modules() do
      assert {:module, ^mod} = Code.ensure_loaded(mod), "#{key}"
      assert function_exported?(mod, :decode, 2), "#{key}"
    end
  end
end
