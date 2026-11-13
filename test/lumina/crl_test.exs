defmodule Lumina.CRLTest do
  @moduledoc """
  Tests decoding of CRLs (RFC 5280 §5, profiled by RFC 6487 §5). Revocation
  checks and the CRL validation in M4 read these structs, so decoding must
  expose issuer, dates, CRL Number and revoked entries faithfully, keep the
  exact signed bytes, and stay structural: profile violations decode.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, CRL}
  alias Lumina.Test.Fixture

  @fixture Fixture.load!("m0-minimal-valid")

  defp read(file), do: File.read!(Path.join(@fixture.rsync_root, file))

  defp decode!(der) do
    {:ok, crl} = CRL.decode(der)
    crl
  end

  # Re-encodes the CA's CRL after changing its decoded value. The signature
  # no longer matches, which doesn't matter for decoding.
  defp reencode(fun) do
    {:ok, crl} = Lumina.ASN1.decode(:pkix, :CertificateList, read("ca1/ca1.crl"))
    {:ok, der} = Lumina.ASN1.encode(:pkix, :CertificateList, fun.(crl))
    der
  end

  describe "the m0-minimal-valid CRLs" do
    @tag rfc: ["6487#5", "5280#5.1.2.1", "5280#5.1.2.4", "5280#5.1.2.5"]
    test "decode as v2 CRLs valid 2026-2036 with no revoked certificates" do
      for file <- ["ta/ta.crl", "ca1/ca1.crl"] do
        crl = decode!(read(file))

        assert crl.version == 2, file

        assert {crl.this_update.at, crl.next_update.at} ==
                 {~U[2026-01-01 00:00:00Z], ~U[2036-01-01 00:00:00Z]}

        assert crl.revoked == []
        assert Enum.map(crl.extensions, & &1.name) == [:authority_key_identifier, :crl_number]
        assert CRL.number(crl) == 1
      end
    end

    @tag rfc: ["6487#5", "5280#5.1.2.3", "5280#5.2.1"],
         doc: "A CRL is matched to its issuer by name and by AKI = the issuer's SKI."
    test "each CRL names its issuing CA and carries that CA's key identifier" do
      for {crl_file, cert_file} <- [{"ta/ta.crl", "ta.cer"}, {"ca1/ca1.crl", "ta/ca1.cer"}] do
        crl = decode!(read(crl_file))
        {:ok, issuer} = Certificate.decode(read(cert_file))

        assert crl.issuer_der == issuer.subject_der, crl_file

        assert CRL.extension_value(crl, :authority_key_identifier).key_identifier ==
                 Certificate.extension_value(issuer, :subject_key_identifier)
      end
    end

    @tag rfc: "5280#5.1.1.3",
         doc: "Signatures are over the exact DER of tbsCertList, so it must be the input's bytes."
    test "tbs_der is the exact tbsCertList bytes from the input" do
      der = read("ca1/ca1.crl")
      crl = decode!(der)

      {:ok, [tbs | _]} = Lumina.DER.children(der)
      assert crl.tbs_der == tbs
      assert :binary.match(der, tbs) != :nomatch
      assert crl.tbs_signature_algorithm == crl.signature_algorithm
    end
  end

  describe "revoked certificates" do
    @tag rfc: ["5280#5.1.2.6", "5280#5.3.1"],
         doc: """
         Barry can't write revoked entries yet (revokedCertificates is on its
         README's list of unimplemented fields), so this CRL is Barry's,
         decoded, given two entries and re-encoded.
         """
    test "revoked entries decode with serial, date and entry extensions" do
      der =
        reencode(fn crl ->
          put_in(crl.tbsCertList[:revokedCertificates], [
            %{userCertificate: 5, revocationDate: {:utcTime, ~c"260601000000Z"}},
            %{
              userCertificate: 7,
              revocationDate: {:utcTime, ~c"260602000000Z"},
              crlEntryExtensions: [
                %{extnID: {2, 5, 29, 21}, critical: false, extnValue: <<10, 1, 1>>}
              ]
            }
          ])
        end)

      crl = decode!(der)

      assert [%{serial: 5, extensions: []}, %{serial: 7, extensions: [reason]}] = crl.revoked
      assert hd(crl.revoked).revoked_at.at == ~U[2026-06-01 00:00:00Z]
      assert %{name: :reason_code, value: :keyCompromise} = reason
      assert CRL.revoked?(crl, 7)
      refute CRL.revoked?(crl, 6)
    end
  end

  describe "structural decoding" do
    @tag rfc: "5280#5.1.2.1"
    test "a CRL without a version field is version 1" do
      crl =
        decode!(
          reencode(
            &update_in(&1.tbsCertList, fn tbs -> Map.drop(tbs, [:version, :crlExtensions]) end)
          )
        )

      assert crl.version == 1
      assert crl.extensions == []
      assert CRL.number(crl) == nil
    end

    @tag rfc: ["6487#5", "5280#5.1.2.5"],
         doc: "nextUpdate is OPTIONAL in the ASN.1; requiring it is the profile's job (M4)."
    test "a CRL without nextUpdate decodes with next_update nil" do
      crl =
        decode!(reencode(&update_in(&1.tbsCertList, fn tbs -> Map.delete(tbs, :nextUpdate) end)))

      assert crl.next_update == nil
    end

    @tag rfc: ["5280#5.2.3", "9829#3.1"]
    test "a CRL Number that doesn't decode is marked malformed, and number/1 is nil" do
      der =
        reencode(fn crl ->
          update_in(crl.tbsCertList.crlExtensions, fn exts ->
            Enum.map(exts, fn
              %{extnID: {2, 5, 29, 20}} = e -> %{e | extnValue: <<0x04, 0x01, 0x00>>}
              e -> e
            end)
          end)
        end)

      crl = decode!(der)
      assert {:malformed, _} = CRL.extension_value(crl, :crl_number)
      assert CRL.number(crl) == nil
    end

    test "non-DER, truncated and non-CRL input are errors naming the layer" do
      der = read("ca1/ca1.crl")

      assert {:error, {:der, %{rule: :trailing_bytes}}} = CRL.decode(der <> <<0>>)
      assert {:error, {:der, %{rule: :truncated}}} = CRL.decode(binary_part(der, 0, 60))
      assert {:error, {:asn1, _}} = CRL.decode(read("ta.cer"))
      assert CRL.decode(nil) == {:error, :not_binary}
    end
  end
end
