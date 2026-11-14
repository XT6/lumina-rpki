defmodule Lumina.ProfileTest do
  @moduledoc """
  Tests the basic-field checks of the resource certificate profile
  (`Lumina.Profile.basic_fields/2`, #109): RFC 6487 §4.1 to §4.7, with the
  validity check of §7.2.

  Every certificate of the positive Barry fixtures must pass, and each
  `m4-cert-*` fixture (plus `m1-cert-version-2`) breaks one rule, which
  must be the one reported. Cases Barry can't produce, such as unique
  identifiers or a commonName that isn't a PrintableString, change one
  field of a decoded fixture certificate; the profile checks don't verify
  signatures, so the struct needn't be re-signed.

  Fixtures validate at 2030-01-01, inside the default 2026-2036
  validity.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, Name, Object, Profile, SignedObject}
  alias Lumina.Test.Fixture
  alias Mix.Lumina.Fixtures

  @at ~U[2030-01-01 00:00:00Z]

  defp cert!(id, file) do
    {:ok, %Object{value: value}} =
      Object.decode_file(Path.join(Fixture.load!(id).rsync_root, file))

    case value do
      %Certificate{} -> value
      %{object: %SignedObject{} = object} -> SignedObject.ee_certificate(object)
    end
  end

  defp ca1(id), do: cert!(id, "ta/ca1.cer")
  defp rules(cert, at \\ @at), do: Enum.map(Profile.basic_fields(cert, at), & &1.rule)

  # A DER Name of one RDN with the given attributes ({oid bytes, tag,
  # value}), and the decoded form, as a certificate holds both.
  defp name(attributes) do
    atvs =
      for {oid, tag, value} <- attributes,
          do: tlv(0x30, tlv(0x06, oid) <> tlv(tag, value))

    der = tlv(0x30, tlv(0x31, Enum.join(Enum.sort(atvs))))
    {:ok, decoded} = Lumina.ASN1.decode(:pkix, :Name, der)
    {Name.from_asn1(decoded), der}
  end

  defp tlv(tag, contents) when byte_size(contents) < 128,
    do: <<tag, byte_size(contents), contents::binary>>

  defp with_subject(cert, attributes) do
    {subject, der} = name(attributes)
    %{cert | subject: subject, subject_der: der}
  end

  @cn <<0x55, 0x04, 0x03>>
  @serial_number <<0x55, 0x04, 0x05>>
  @printable 0x13
  @utf8 0x0C

  describe "fixtures" do
    @tag rfc: ["6487#4.1", "6487#4.2", "6487#4.3", "6487#4.4", "6487#4.5", "6487#4.6", "6487#4.7"],
         doc:
           "TA, CA and EE certificates (from manifests and ROAs) of every fixture expected valid."
    test "every certificate of every positive Barry fixture passes" do
      for dir <- Fixtures.case_dirs(),
          id = Path.basename(dir),
          Fixture.load!(id).expected == :valid,
          path <- Path.wildcard(Path.join(dir, "rsync/**/*.{cer,mft,roa}")) do
        file = Path.relative_to(path, Path.join(dir, "rsync"))
        assert Profile.basic_fields(cert!(id, file), @at) == [], "#{id} #{file}"
      end
    end

    @tag rfc: "6487#4.1"
    test "m1-cert-version-2: a version 2 certificate is rejected" do
      assert rules(ca1("m1-cert-version-2")) == [:version]
    end

    @tag rfc: "6487#7.2"
    test "m4-cert-expired: a certificate past its notAfter is rejected as expired" do
      assert rules(ca1("m4-cert-expired")) == [:expired]
    end

    @tag rfc: "6487#7.2"
    test "m4-cert-not-yet-valid: a certificate before its notBefore is rejected" do
      assert rules(ca1("m4-cert-not-yet-valid")) == [:not_yet_valid]
    end

    @tag rfc: ["6487#4.2", "5280#4.1.2.2"]
    test "m4-cert-serial-zero: serial number 0 is rejected" do
      assert rules(ca1("m4-cert-serial-zero")) == [:serial_not_positive]
    end

    @tag rfc: ["6487#4.2", "5280#4.1.2.2"]
    test "m4-cert-serial-negative: a negative serial number is rejected" do
      assert rules(ca1("m4-cert-serial-negative")) == [:serial_not_positive]
    end

    @tag rfc: "5280#4.1.2.2"
    test "m4-cert-serial-too-long: a 21-octet serial number is rejected" do
      assert rules(ca1("m4-cert-serial-too-long")) == [:serial_too_long]
    end

    @tag rfc: ["6487#4.3", "5280#4.1.1.2", "7935#2"],
         doc: "sha384WithRSAEncryption inside: both a mismatch and an unsupported algorithm."
    test "m4-cert-inner-signature-algorithm: an inner algorithm unlike the outer one is rejected" do
      assert rules(ca1("m4-cert-inner-signature-algorithm")) ==
               [:signature_algorithm_mismatch, :unsupported_signature_algorithm]
    end

    @tag rfc: ["6487#4.4", "6487#4.5"],
         doc: "The CA's subject, and the issuer of the EE certificates it signs."
    test "m4-cert-name-extra-attribute: a name with an organizationName is rejected" do
      id = "m4-cert-name-extra-attribute"

      assert [%{rule: :name_attribute, field: :subject, rfc: "6487#4.5"}] =
               Profile.basic_fields(ca1(id), @at)

      for file <- ["ca1/ca1.mft", "ca1/roa1.roa"] do
        assert [%{rule: :name_attribute, field: :issuer, rfc: "6487#4.4"}] =
                 Profile.basic_fields(cert!(id, file), @at),
               file
      end
    end
  end

  describe "validity" do
    @tag rfc: "6487#7.2", doc: "notBefore and notAfter are both inside the validity period."
    test "a certificate is valid at exactly its notBefore and its notAfter" do
      ca = ca1("m0-minimal-valid")

      assert rules(ca, ca.not_before.at) == []
      assert rules(ca, ca.not_after.at) == []
      assert rules(ca, DateTime.add(ca.not_after.at, 1)) == [:expired]
      assert rules(ca, DateTime.add(ca.not_before.at, -1)) == [:not_yet_valid]
    end
  end

  describe "serial number" do
    @tag rfc: "5280#4.1.2.2", doc: "2^159 - 1 is the largest positive INTEGER in 20 octets."
    test "a 20-octet serial number is accepted" do
      ca = ca1("m0-minimal-valid")

      assert rules(%{ca | serial: Integer.pow(2, 159) - 1}) == []
      assert rules(%{ca | serial: Integer.pow(2, 159)}) == [:serial_too_long]
    end
  end

  describe "names" do
    @tag rfc: "6487#4.5"
    test "a commonName with a serialNumber is accepted" do
      ca =
        with_subject(ca1("m0-minimal-valid"), [
          {@cn, @printable, "ca1"},
          {@serial_number, @printable, "1234"}
        ])

      assert rules(ca) == []
    end

    @tag rfc: "6487#4.5"
    test "a commonName that isn't a PrintableString is rejected" do
      ca = with_subject(ca1("m0-minimal-valid"), [{@cn, @utf8, "ca1"}])

      assert [%{rule: :common_name_encoding, field: :subject}] = Profile.basic_fields(ca, @at)
    end

    @tag rfc: "6487#4.5"
    test "a name without a commonName is rejected" do
      ca = with_subject(ca1("m0-minimal-valid"), [{@serial_number, @printable, "1234"}])

      assert rules(ca) == [:common_name_count]
    end

    @tag rfc: "6487#4.5"
    test "a name with two commonNames is rejected" do
      ca =
        with_subject(ca1("m0-minimal-valid"), [{@cn, @printable, "a"}, {@cn, @printable, "b"}])

      assert rules(ca) == [:common_name_count]
    end

    @tag rfc: "6487#4.5"
    test "a name with two serialNumbers is rejected" do
      ca =
        with_subject(ca1("m0-minimal-valid"), [
          {@cn, @printable, "ca1"},
          {@serial_number, @printable, "1"},
          {@serial_number, @printable, "2"}
        ])

      assert rules(ca) == [:serial_number_count]
    end
  end

  describe "fields the profile excludes" do
    @tag rfc: "6487#4",
         doc: "RFC 6487 §4: fields not listed in the profile MUST NOT appear."
    test "issuer and subject unique identifiers are rejected" do
      ca = ca1("m0-minimal-valid")

      assert rules(%{ca | issuer_unique_id: <<1::1>>, subject_unique_id: <<0::1>>}) ==
               [:unique_id, :unique_id]
    end
  end

  describe "public key (D-018)" do
    @tag rfc: ["7935#3.1", "4055#1.2"],
         doc: "F-027: allowed by RFC 7935 §3.1's text, not by practice; a warning, so it passes."
    test "a sha256WithRSAEncryption key algorithm is accepted with a warning" do
      ca = ca1("m0-minimal-valid")

      ca = %{
        ca
        | public_key: %{
            ca.public_key
            | algorithm: %{oid: {1, 2, 840, 113_549, 1, 1, 11}, parameters: <<5, 0>>}
          }
      }

      problems = Profile.basic_fields(ca, @at)
      assert [%{rule: :key_algorithm_sha256_with_rsa, severity: :warning}] = problems
      assert Profile.passes?(problems)
    end

    @tag rfc: "7935#3"
    test "a 1024-bit key is rejected" do
      {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
        :public_key.generate_key({:rsa, 1024, 65_537})

      ca = ca1("m0-minimal-valid")

      ca = %{
        ca
        | public_key: %{
            ca.public_key
            | key: :public_key.der_encode(:RSAPublicKey, {:RSAPublicKey, n, e})
          }
      }

      assert [%{rule: :key_size, field: :public_key, severity: :error}] =
               Profile.basic_fields(ca, @at)
    end
  end
end
