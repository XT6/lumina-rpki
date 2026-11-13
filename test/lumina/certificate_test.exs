defmodule Lumina.CertificateTest do
  @moduledoc """
  Tests decoding of RPKI resource certificates (RFC 5280 profiled by RFC
  6487). Every later check (chain building, signatures, resources, URIs)
  reads these structs, so decoding must expose every field faithfully, keep
  the exact signed bytes, and stay structural: profile violations decode,
  and only non-DER or unparseable input fails.
  """
  use ExUnit.Case, async: true

  alias Lumina.Certificate
  alias Lumina.Certificate.Extension
  alias Lumina.Test.Fixture

  @fixture Fixture.load!("m0-minimal-valid")

  defp read(file, fixture \\ @fixture), do: File.read!(Path.join(fixture.rsync_root, file))

  defp decode!(der) do
    {:ok, cert} = Certificate.decode(der)
    cert
  end

  # The EE certificate embedded in a signed object, as DER.
  defp ee_der(file) do
    {:ok, %{content: signed_data}} = Lumina.ASN1.decode(:cms, :ContentInfo, read(file))

    {:ok, %{certificates: [certificate: cert]}} =
      Lumina.ASN1.decode(:cms, :SignedData, signed_data)

    {:ok, der} = Lumina.ASN1.encode(:pkix, :Certificate, cert)
    der
  end

  describe "the m0-minimal-valid certificates" do
    @tag rfc: ["6487#4.1", "6487#4.4", "6487#4.5", "6487#4.6", "6487#4.8.1", "6487#4.8.4"]
    test "the TA certificate is a self-issued v3 CA certificate valid 2026-2036" do
      ta = decode!(read("ta.cer"))

      assert ta.version == 3
      assert ta.serial == 0
      assert ta.issuer == ta.subject and ta.issuer_der == ta.subject_der
      assert [[%{type: {2, 5, 4, 3}, value: cn}]] = ta.subject
      assert is_binary(cn)

      assert {ta.not_before.at, ta.not_after.at} ==
               {~U[2026-01-01 00:00:00Z], ~U[2036-01-01 00:00:00Z]}

      assert ta.not_before.format == :utc_time
      assert Certificate.extension_value(ta, :basic_constraints) == %{ca: true, path_len: nil}
      assert Certificate.extension_value(ta, :key_usage) == [:keyCertSign, :cRLSign]
      assert Certificate.extension(ta, :authority_key_identifier) == nil
    end

    @tag rfc: ["6487#4.8.2", "5280#4.2.1.2"],
         doc: "The key identifier is the SHA-1 of the subjectPublicKey bit string's value."
    test "the Subject Key Identifier is the SHA-1 of the public key bits" do
      for file <- ["ta.cer", "ta/ca1.cer"] do
        cert = decode!(read(file))

        assert Certificate.extension_value(cert, :subject_key_identifier) ==
                 :crypto.hash(:sha, cert.public_key.key),
               file
      end
    end

    @tag rfc: ["6487#4.8.3", "6487#4.4"]
    test "the CA certificate points to the TA: AKI equals the TA's SKI and the issuer is the TA's subject" do
      ta = decode!(read("ta.cer"))
      ca = decode!(read("ta/ca1.cer"))

      assert Certificate.extension_value(ca, :authority_key_identifier).key_identifier ==
               Certificate.extension_value(ta, :subject_key_identifier)

      assert ca.issuer_der == ta.subject_der
      assert ca.serial == 1
    end

    @tag rfc: ["6487#4.8.6", "6487#4.8.7", "6487#4.8.8.1", "6487#4.8.9"]
    test "the CA certificate's CRL, issuer, repository and manifest URIs and policy" do
      ca = decode!(read("ta/ca1.cer"))

      assert [%{full_name: [uri: "rsync://localhost:8873/rpki/ta/ta.crl"]}] =
               Certificate.extension_value(ca, :crl_distribution_points)

      assert Certificate.aia_uris(ca, :ca_issuers) == ["rsync://localhost:8873/rpki/ta.cer"]
      assert Certificate.sia_uris(ca, :ca_repository) == ["rsync://localhost:8873/rpki/ca1"]

      assert Certificate.sia_uris(ca, :rpki_manifest) == [
               "rsync://localhost:8873/rpki/ca1/ca1.mft"
             ]

      assert [%{oid: {1, 3, 6, 1, 5, 5, 7, 14, 2}}] =
               Certificate.extension_value(ca, :certificate_policies)
    end

    @tag rfc: ["6487#4.8.10", "6487#4.8.11"]
    test "resources are decoded through Lumina.Resources" do
      ca = decode!(read("ta/ca1.cer"))

      assert [%{afi: :ipv4, resources: [{:prefix, 0x01000000, 8}]}, %{afi: :ipv6}] =
               Certificate.extension_value(ca, :ip_resources)

      assert Certificate.extension_value(ca, :as_resources) == %{
               asnum: [{:range, 0x01000000, 0x01FFFFFF}],
               rdi: nil
             }
    end

    @tag rfc: ["6487#4.8.4", "6487#4.8.8.2", "6488#2.1.4"],
         doc:
           "An EE certificate has no Basic Constraints, signs objects, and its SIA points to the signed object."
    test "the ROA's EE certificate" do
      ee = decode!(ee_der("ca1/roa1.roa"))

      assert ee.version == 3
      assert Certificate.extension(ee, :basic_constraints) == nil
      assert Certificate.extension_value(ee, :key_usage) == [:digitalSignature]

      assert Certificate.sia_uris(ee, :signed_object) == [
               "rsync://localhost:8873/rpki/ca1/roa1.roa"
             ]
    end

    @tag rfc: "5280#4.1.1.1",
         doc:
           "Signatures are over the exact DER of tbsCertificate, so it must be the input's bytes."
    test "tbs_der is the exact tbsCertificate bytes from the input" do
      der = read("ta/ca1.cer")
      cert = decode!(der)

      assert :binary.match(der, cert.tbs_der) == {4, byte_size(cert.tbs_der)}
      assert cert.tbs_signature_algorithm == cert.signature_algorithm
      assert cert.signature_algorithm.oid == {1, 2, 840, 113_549, 1, 1, 11}
      assert is_bitstring(cert.signature)
      assert :binary.match(cert.tbs_der, cert.public_key.der) != :nomatch
    end
  end

  describe "profile violations still decode (fixtures)" do
    @tag rfc: "6487#4.1"
    test "a version 2 certificate decodes with version 2" do
      cert = decode!(read("ta/ca1.cer", Fixture.load!("m1-cert-version-2")))
      assert cert.version == 2
    end

    @tag rfc: "6487#4.8.2"
    test "a certificate without a Subject Key Identifier decodes without one" do
      cert = decode!(read("ta/ca1.cer", Fixture.load!("m1-cert-no-ski")))
      assert Certificate.extension(cert, :subject_key_identifier) == nil
      assert Certificate.extension(cert, :authority_key_identifier) != nil
    end

    @tag rfc: "6487#4.8"
    test "an unrecognized critical extension is kept, with its OID and criticality" do
      cert = decode!(read("ta/ca1.cer", Fixture.load!("m1-cert-unknown-critical-extension")))

      assert %Extension{
               oid: {1, 3, 6, 1, 4, 1, 99_999, 1},
               name: nil,
               critical: true,
               value: :unknown,
               der: der
             } =
               List.last(cert.extensions)

      assert is_binary(der)
    end
  end

  describe "malformed content" do
    # Re-encodes the CA certificate after changing its decoded value.
    defp reencode(fun) do
      {:ok, cert} = Lumina.ASN1.decode(:pkix, :Certificate, read("ta/ca1.cer"))
      {:ok, der} = Lumina.ASN1.encode(:pkix, :Certificate, fun.(cert))
      der
    end

    @tag doc:
           "A broken known extension is reported in place, so validation can name it, not the whole certificate."
    test "a known extension whose value doesn't decode is marked malformed" do
      der =
        reencode(fn cert ->
          update_in(cert.tbsCertificate.extensions, fn exts ->
            Enum.map(exts, fn
              %{extnID: {1, 3, 6, 1, 5, 5, 7, 1, 11}} = e ->
                %{e | extnValue: <<0x30, 0x03, 0x02, 0x01>>}

              e ->
                e
            end)
          end)
        end)

      cert = decode!(der)
      assert {:malformed, _} = Certificate.extension_value(cert, :subject_info_access)
      assert Certificate.sia_uris(cert, :rpki_manifest) == []
    end

    @tag rfc: "5280#4.1.2.5.1"
    test "a validity time that isn't a real date is an error" do
      der = reencode(&put_in(&1.tbsCertificate.validity.notBefore, {:utcTime, ~c"261330000000Z"}))
      assert Certificate.decode(der) == {:error, {:invalid_time, "261330000000Z"}}
    end

    @tag rfc: ["6487#4", "6481#2.2"]
    test "non-DER, truncated and non-certificate input are errors naming the layer" do
      der = read("ta.cer")

      assert {:error, {:der, %{rule: :trailing_bytes}}} = Certificate.decode(der <> <<0>>)
      assert {:error, {:der, %{rule: :truncated}}} = Certificate.decode(binary_part(der, 0, 200))
      assert {:error, {:asn1, _}} = Certificate.decode(<<0x30, 0x03, 0x02, 0x01, 0x05>>)
      assert Certificate.decode(:nope) == {:error, :not_binary}
    end
  end
end
