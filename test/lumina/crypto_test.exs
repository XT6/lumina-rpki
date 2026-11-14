defmodule Lumina.CryptoTest do
  @moduledoc """
  Tests signature verification of certificates and CRLs (`Lumina.Crypto`,
  #108): RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7935 §2, RFC 8017 §8.2) over
  2048-bit RSA keys with exponent 65,537 (RFC 7935 §3).

  Barry signs every fixture correctly, so all its signatures must verify;
  each rejection is shown by changing one thing in a real signature, or by
  a key generated in the test. Chain validation (#112) builds on this, so
  a wrong `:ok` here would let forged objects through.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, CRL, Crypto, Object, SignedObject}
  alias Lumina.Test.Fixture
  alias Mix.Lumina.Fixtures

  @sha1_with_rsa {1, 2, 840, 113_549, 1, 1, 5}
  @sha256_with_rsa {1, 2, 840, 113_549, 1, 1, 11}
  @sha384_with_rsa {1, 2, 840, 113_549, 1, 1, 12}
  @rsa_encryption {1, 2, 840, 113_549, 1, 1, 1}
  @ec_public_key {1, 2, 840, 10_045, 2, 1}

  defp decode!(path) do
    {:ok, %Object{value: value}} = Object.decode_file(path)
    value
  end

  defp m0(file), do: decode!(Path.join(Fixture.load!("m0-minimal-valid").rsync_root, file))

  # Every certificate (EE certificates of signed objects included) and
  # every CRL in a fixture's rsync tree.
  defp signed_items(id) do
    for path <- Path.wildcard(Path.join(Fixture.load!(id).rsync_root, "**/*.*")),
        File.regular?(path),
        item <- items(decode!(path)),
        do: {Path.relative_to(path, Fixture.load!(id).rsync_root), item}
  end

  defp items(%Certificate{} = cert), do: [cert]
  defp items(%CRL{} = crl), do: [crl]
  defp items(%SignedObject{} = object), do: [SignedObject.ee_certificate(object)]
  defp items(%{object: %SignedObject{} = object}), do: items(object)

  # The issuer: the certificate whose subject is the item's issuer and,
  # when the item names one, whose key identifier is its AKI. A certificate
  # without an SKI (m1-cert-no-ski) is identified by the SHA-1 of its key,
  # as RFC 6487 §4.8.2 computes it.
  defp issuer(item, certs) do
    aki =
      case Lumina.Extension.value(item.extensions, :authority_key_identifier) do
        %{key_identifier: kid} -> kid
        _ -> nil
      end

    Enum.find(certs, fn cert ->
      cert.subject_der == item.issuer_der and
        (aki == nil or key_identifier(cert) == aki)
    end)
  end

  defp key_identifier(cert),
    do:
      Certificate.extension_value(cert, :subject_key_identifier) ||
        :crypto.hash(:sha, cert.public_key.key)

  # A public key map, as in Lumina.Certificate, for an OTP RSA key.
  defp public_key({:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _}),
    do: public_key(n, e, @rsa_encryption, <<5, 0>>)

  defp public_key(n, e, oid, parameters),
    do: %{
      algorithm: %{oid: oid, parameters: parameters},
      key: :public_key.der_encode(:RSAPublicKey, {:RSAPublicKey, n, e})
    }

  defp sha256_with_rsa, do: %{oid: @sha256_with_rsa, parameters: <<5, 0>>}

  defp flip_last_bit(bytes) do
    last = :binary.last(bytes)
    binary_part(bytes, 0, byte_size(bytes) - 1) <> <<Bitwise.bxor(last, 1)>>
  end

  # Objects whose issuer link or signature a fixture breaks on purpose.
  @broken_on_purpose [
    {"m4-crl-aki-mismatch", "ca1/ca1.crl"},
    {"m4-crl-issuer-mismatch", "ca1/ca1.crl"},
    {"m4-crl-bad-signature", "ca1/ca1.crl"},
    {"m4-chain-ta-bad-signature", "ta.cer"},
    {"m4-chain-ca-bad-signature", "ta/ca1.cer"},
    {"m4-chain-issuer-mismatch", "ta/ca1.cer"},
    {"m4-chain-aki-mismatch", "ta/ca1.cer"}
  ]

  describe "valid signatures" do
    @tag rfc: ["7935#2", "8017#8.2.2", "5280#4.1.1.3", "5280#5.1.1.3"],
         doc: """
         Certificates (TA, CA, and the EE certificates in manifests and
         ROAs) and CRLs, each checked with the key of the certificate whose
         subject and key identifier its issuer and AKI name; a TA with its
         own key. Fixtures that break exactly that link or the signature
         are left out; their own tests are in Lumina.ProfileCRLTest and
         Lumina.ChainTest.
         """
    test "every certificate and CRL signature in every Barry fixture verifies with its issuer's key" do
      for dir <- Fixtures.case_dirs(), id = Path.basename(dir) do
        items = signed_items(id)
        certs = for {_, %Certificate{} = cert} <- items, do: cert
        assert certs != [], id

        for {path, item} <- items, {id, path} not in @broken_on_purpose do
          issuer = issuer(item, certs)
          assert issuer, "#{id} #{path}: no issuer"
          assert Crypto.verify(item, issuer.public_key) == :ok, "#{id} #{path}"
        end
      end
    end

    @tag rfc: "8017#8.2",
         doc: """
         An independent check of the implementation: OTP's `:public_key`
         signs with a fresh key, and Lumina verifies.
         """
    test "a signature made by OTP's public_key verifies" do
      key = :public_key.generate_key({:rsa, 2048, 65_537})
      signature = :public_key.sign("signed bytes", :sha256, key)

      assert Crypto.verify("signed bytes", sha256_with_rsa(), signature, public_key(key)) == :ok
    end

    @tag rfc: "4055#5"
    test "sha256WithRSAEncryption with absent parameters is accepted" do
      ta = m0("ta.cer")

      assert Crypto.verify(
               ta.tbs_der,
               %{oid: @sha256_with_rsa, parameters: nil},
               ta.signature,
               ta.public_key
             ) == :ok
    end
  end

  describe "tampering" do
    @tag rfc: "8017#8.2.2"
    test "a flipped bit in the signature is rejected" do
      ca = m0("ta/ca1.cer")
      ta = m0("ta.cer")

      assert {:error, %{rule: :bad_signature, rfc: "8017#8.2.2"}} =
               Crypto.verify(%{ca | signature: flip_last_bit(ca.signature)}, ta.public_key)
    end

    @tag rfc: ["8017#8.2.2", "5280#5.1.1.3"]
    test "a flipped bit in the signed bytes is rejected" do
      crl = m0("ca1/ca1.crl")
      ca = m0("ta/ca1.cer")

      assert Crypto.verify(crl, ca.public_key) == :ok

      assert {:error, %{rule: :bad_signature}} =
               Crypto.verify(%{crl | tbs_der: flip_last_bit(crl.tbs_der)}, ca.public_key)
    end

    @tag rfc: "8017#8.2.2", doc: "The TA's signature over ca1, checked with ca1's own key."
    test "a signature checked with a key other than the issuer's is rejected" do
      ca = m0("ta/ca1.cer")

      assert {:error, %{rule: :bad_signature}} = Crypto.verify(ca, ca.public_key)
    end

    @tag rfc: "8017#5.2.2"
    test "a signature not below the modulus is rejected before exponentiation" do
      ta = m0("ta.cer")

      assert {:error, %{rule: :signature_out_of_range}} =
               Crypto.verify(%{ta | signature: :binary.copy(<<0xFF>>, 256)}, ta.public_key)
    end

    @tag rfc: "8017#8.2.2", doc: "Step 1: the signature must be as long as the modulus."
    test "a signature one octet short is rejected" do
      ta = m0("ta.cer")
      <<_, short::binary>> = ta.signature

      assert {:error, %{rule: :signature_length}} =
               Crypto.verify(%{ta | signature: short}, ta.public_key)
    end

    @tag rfc: "5280#4.1.1.3"
    test "a signature BIT STRING that isn't whole octets is rejected" do
      ta = m0("ta.cer")

      assert {:error, %{rule: :malformed_signature}} =
               Crypto.verify(%{ta | signature: <<ta.signature::bitstring, 1::1>>}, ta.public_key)
    end
  end

  describe "algorithms" do
    @tag rfc: "7935#2"
    test "sha1WithRSAEncryption is rejected as unsupported" do
      ta = m0("ta.cer")

      assert {:error, %{rule: :unsupported_signature_algorithm, rfc: "7935#2"}} =
               Crypto.verify(
                 %{ta | signature_algorithm: %{oid: @sha1_with_rsa, parameters: <<5, 0>>}},
                 ta.public_key
               )
    end

    @tag rfc: "7935#2",
         doc: "A stronger hash is still not the RPKI suite: only SHA-256 is allowed."
    test "sha384WithRSAEncryption is rejected as unsupported" do
      crl = m0("ta/ta.crl")
      ta = m0("ta.cer")

      assert {:error, %{rule: :unsupported_signature_algorithm}} =
               Crypto.verify(
                 %{crl | signature_algorithm: %{oid: @sha384_with_rsa, parameters: <<5, 0>>}},
                 ta.public_key
               )
    end

    @tag rfc: "4055#5"
    test "sha256WithRSAEncryption with parameters other than NULL is rejected" do
      ta = m0("ta.cer")

      assert {:error, %{rule: :signature_algorithm_parameters}} =
               Crypto.verify(
                 %{ta | signature_algorithm: %{oid: @sha256_with_rsa, parameters: <<4, 0>>}},
                 ta.public_key
               )
    end
  end

  describe "keys" do
    @tag rfc: "7935#3",
         doc: "The signature is otherwise valid; only the key size is wrong."
    test "a 1024-bit key is rejected with the key-size reason" do
      key = :public_key.generate_key({:rsa, 1024, 65_537})
      signature = :public_key.sign("signed bytes", :sha256, key)

      assert {:error, %{rule: :key_size, rfc: "7935#3"}} =
               Crypto.verify("signed bytes", sha256_with_rsa(), signature, public_key(key))
    end

    @tag rfc: "7935#3"
    test "a 4096-bit key is rejected with the key-size reason" do
      key = :public_key.generate_key({:rsa, 4096, 65_537})
      signature = :public_key.sign("signed bytes", :sha256, key)

      assert {:error, %{rule: :key_size}} =
               Crypto.verify("signed bytes", sha256_with_rsa(), signature, public_key(key))
    end

    @tag rfc: "7935#3"
    test "a 2048-bit key with exponent 3 is rejected with the exponent reason" do
      key = :public_key.generate_key({:rsa, 2048, 3})
      signature = :public_key.sign("signed bytes", :sha256, key)

      assert {:error, %{rule: :key_exponent, rfc: "7935#3"}} =
               Crypto.verify("signed bytes", sha256_with_rsa(), signature, public_key(key))
    end

    @tag rfc: ["7935#3.1", "4055#1.2"],
         doc: """
         F-027: RFC 7935 §3.1 names sha256WithRSAEncryption as the
         subjectPublicKeyInfo algorithm, RFC 4055 §1.2 rsaEncryption; both
         read the same RSAPublicKey.
         """
    test "a key whose algorithm is sha256WithRSAEncryption is read like rsaEncryption" do
      {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
        key = :public_key.generate_key({:rsa, 2048, 65_537})

      signature = :public_key.sign("signed bytes", :sha256, key)
      spki = public_key(n, e, @sha256_with_rsa, nil)

      assert Crypto.verify("signed bytes", sha256_with_rsa(), signature, spki) == :ok
    end

    @tag rfc: "7935#3.1"
    test "a key that isn't RSA is rejected as unsupported" do
      ta = m0("ta.cer")
      key = %{ta.public_key | algorithm: %{oid: @ec_public_key, parameters: nil}}

      assert {:error, %{rule: :unsupported_key_algorithm}} = Crypto.verify(ta, key)
    end

    @tag rfc: "4055#1.2"
    test "an rsaEncryption key without NULL parameters is rejected" do
      ta = m0("ta.cer")
      key = %{ta.public_key | algorithm: %{oid: @rsa_encryption, parameters: nil}}

      assert {:error, %{rule: :key_algorithm_parameters}} = Crypto.verify(ta, key)
    end

    @tag rfc: "4055#1.2"
    test "a key that isn't a DER RSAPublicKey is rejected as malformed" do
      ta = m0("ta.cer")

      for bad <- [<<0x30, 0x00>>, <<0x02, 0x01, 0x05>>, ta.public_key.key <> <<0>>, <<1::1>>] do
        assert {:error, %{rule: :malformed_key}} =
                 Crypto.verify(ta, %{ta.public_key | key: bad}),
               inspect(bad)
      end
    end

    @tag rfc: "4055#1.2"
    test "an RSAPublicKey with a negative modulus is rejected as malformed" do
      key = %{
        algorithm: %{oid: @rsa_encryption, parameters: <<5, 0>>},
        key: <<0x30, 0x08, 0x02, 0x03, 0x80, 0x00, 0x01, 0x02, 0x01, 0x03>>
      }

      assert {:error, %{rule: :malformed_key}} = Crypto.rsa_public_key(key)
    end
  end
end
