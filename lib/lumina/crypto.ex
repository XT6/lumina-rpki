defmodule Lumina.Crypto do
  @moduledoc """
  Signature verification for certificates and CRLs (#108), with the one
  algorithm suite RPKI allows (RFC 7935): RSASSA-PKCS1-v1_5 with SHA-256,
  over 2048-bit RSA keys with public exponent 65,537. `verify_cms/4`
  checks a signed object's SignerInfo signature (#130).

  `verify/2` checks a decoded `Lumina.Certificate` or `Lumina.CRL` against
  its issuer's public key; `verify/4` checks any signed bytes. Both return
  `:ok` or `{:error, problem}`, where a problem names the rule, the RFC
  section it comes from and a message:

    * `:unsupported_signature_algorithm`, `:signature_algorithm_parameters`:
      the signature algorithm must be sha256WithRSAEncryption (RFC 7935 §2)
      with NULL or absent parameters (RFC 4055 §5);
    * `:unsupported_key_algorithm`, `:key_algorithm_parameters`,
      `:malformed_key`: the key must be an RSAPublicKey (RFC 4055 §1.2), see
      `rsa_public_key/1`;
    * `:key_size`, `:key_exponent`: RFC 7935 §3;
    * `:malformed_signature`, `:signature_length`,
      `:signature_out_of_range`, `:bad_signature`: the signature itself
      (RFC 5280 §4.1.1.3, RFC 8017 §8.2.2).

  Verification follows RFC 8017 §8.2.2 to the letter: the signature is
  raised to the public exponent (RSAVP1, §5.2.2), and the result must
  equal, byte for byte, the encoding EMSA-PKCS1-v1_5 (§9.2) gives for the
  SHA-256 hash of the signed bytes. Nothing in the signature is parsed,
  so there is no DigestInfo parser to fool. RFC 7935 §2 cites RFC 3447
  for the scheme; RFC 8017 obsoletes it with the same algorithm (F-017).

  Only the modular exponentiation (`:crypto.mod_pow/3`) and the hash
  (`:crypto.hash/2`) come from OTP.
  """

  import Bitwise

  alias Lumina.{Certificate, CRL, DER}

  @type problem :: %{rule: atom(), rfc: String.t(), message: String.t()}
  @type algorithm :: %{oid: tuple(), parameters: binary() | nil}
  @type public_key :: %{
          required(:algorithm) => algorithm(),
          required(:key) => bitstring(),
          optional(atom()) => term()
        }
  @type rsa_key :: %{modulus: pos_integer(), exponent: pos_integer(), bits: pos_integer()}

  @rsa_encryption {1, 2, 840, 113_549, 1, 1, 1}
  @sha256_with_rsa {1, 2, 840, 113_549, 1, 1, 11}
  @null <<5, 0>>

  @key_bits 2048
  @exponent 65_537

  # RFC 8017 §9.2, note 1: the DER of DigestInfo for SHA-256, before H.
  @sha256_digest_info <<0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20>>

  @doc """
  Verifies the signature of a certificate or CRL with `issuer_key`, the
  issuer's `public_key` (`Lumina.Certificate`; a TA's own key). The
  algorithm checked is the outer `signature_algorithm`; that it matches
  the one inside the signed part is a profile check (RFC 5280 §4.1.1.2).
  """
  @spec verify(Certificate.t() | CRL.t(), public_key()) :: :ok | {:error, problem()}
  def verify(%struct{} = signed, issuer_key) when struct in [Certificate, CRL],
    do: verify(signed.tbs_der, signed.signature_algorithm, signed.signature, issuer_key)

  @doc """
  Verifies `signature` (a BIT STRING value) over `message` with `key`,
  for signature `algorithm`.
  """
  @spec verify(binary(), algorithm(), bitstring(), public_key()) :: :ok | {:error, problem()}
  def verify(message, algorithm, signature, key) do
    with :ok <- signature_algorithm(algorithm),
         {:ok, rsa} <- check_rsa_key(key),
         {:ok, s} <- signature_octets(signature, div(rsa.bits + 7, 8)) do
      rsassa_pkcs1_v1_5_verify(rsa, message, s)
    end
  end

  @doc """
  Verifies the signature of a CMS SignerInfo (RFC 6488 §3 item 2) over
  `signed_attrs_der`, the DER of the signed attributes (RFC 5652 §5.4),
  with the EE certificate's `key`. In CMS the digest and signature
  algorithms are named apart, so `algorithm` may be rsaEncryption as well
  as sha256WithRSAEncryption (RFC 7935 §2); either way the signature is
  RSASSA-PKCS1-v1_5 over SHA-256. The algorithm's parameters and the
  digest algorithm are `Lumina.CMS.profile/1`'s to check.
  """
  @spec verify_cms(binary(), algorithm(), binary(), public_key()) :: :ok | {:error, problem()}
  def verify_cms(signed_attrs_der, %{oid: oid}, signature, key)
      when oid in [@rsa_encryption, @sha256_with_rsa] do
    with {:ok, rsa} <- check_rsa_key(key),
         {:ok, s} <- signature_octets(signature, div(rsa.bits + 7, 8)) do
      rsassa_pkcs1_v1_5_verify(rsa, signed_attrs_der, s)
    end
  end

  def verify_cms(_signed_attrs_der, %{oid: oid}, _signature, _key),
    do:
      problem(
        :unsupported_signature_algorithm,
        "7935#2",
        "the signature algorithm is #{Lumina.OID.format(oid)}; CMS in RPKI uses rsaEncryption " <>
          "or sha256WithRSAEncryption"
      )

  @doc """
  Reads an RSA public key from a subjectPublicKeyInfo's algorithm and
  key, without checking its size or exponent.

  The key is an RSAPublicKey, DER (RFC 4055 §1.2). Its algorithm is
  rsaEncryption with NULL parameters (RFC 4055 §1.2), or
  sha256WithRSAEncryption with NULL or absent parameters, which RFC 7935
  §3.1 names in its place (F-027).
  """
  @spec rsa_public_key(public_key()) :: {:ok, rsa_key()} | {:error, problem()}
  def rsa_public_key(%{algorithm: algorithm, key: key}) do
    with :ok <- key_algorithm(algorithm),
         {:ok, modulus, exponent} <- rsa_public_key_der(key) do
      {:ok, %{modulus: modulus, exponent: exponent, bits: bit_length(modulus)}}
    end
  end

  @doc """
  Reads an RSA public key, as `rsa_public_key/1`, and checks the RPKI key
  format: a 2048-bit modulus and exponent 65,537 (RFC 7935 §3).
  """
  @spec check_rsa_key(public_key()) :: {:ok, rsa_key()} | {:error, problem()}
  def check_rsa_key(key) do
    with {:ok, rsa} <- rsa_public_key(key),
         :ok <- key_size(rsa),
         :ok <- key_exponent(rsa),
         do: {:ok, rsa}
  end

  @doc """
  Checks a signature algorithm identifier: sha256WithRSAEncryption with
  NULL or absent parameters (RFC 7935 §2, RFC 4055 §5).
  """
  @spec check_signature_algorithm(algorithm()) :: :ok | {:error, problem()}
  def check_signature_algorithm(algorithm), do: signature_algorithm(algorithm)

  defp signature_algorithm(%{oid: @sha256_with_rsa, parameters: params})
       when params in [nil, @null],
       do: :ok

  defp signature_algorithm(%{oid: @sha256_with_rsa}),
    do:
      problem(
        :signature_algorithm_parameters,
        "4055#5",
        "sha256WithRSAEncryption parameters must be NULL or absent"
      )

  defp signature_algorithm(%{oid: oid}),
    do:
      problem(
        :unsupported_signature_algorithm,
        "7935#2",
        "the signature algorithm is #{Lumina.OID.format(oid)}; RPKI uses sha256WithRSAEncryption"
      )

  defp key_algorithm(%{oid: @rsa_encryption, parameters: @null}), do: :ok

  defp key_algorithm(%{oid: @sha256_with_rsa, parameters: params}) when params in [nil, @null],
    do: :ok

  defp key_algorithm(%{oid: oid}) when oid in [@rsa_encryption, @sha256_with_rsa],
    do:
      problem(
        :key_algorithm_parameters,
        "4055#1.2",
        "the public key algorithm parameters must be NULL"
      )

  defp key_algorithm(%{oid: oid}),
    do:
      problem(
        :unsupported_key_algorithm,
        "7935#3.1",
        "the public key algorithm is #{Lumina.OID.format(oid)}; RPKI keys are RSA"
      )

  # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
  defp rsa_public_key_der(key) when is_binary(key) do
    with :ok <- DER.check(key),
         <<0x30, _::binary>> <- key,
         {:ok, [n, e]} <- DER.children(key),
         {:ok, modulus} <- positive_integer(n),
         {:ok, exponent} <- positive_integer(e) do
      {:ok, modulus, exponent}
    else
      _ -> malformed_key()
    end
  end

  defp rsa_public_key_der(_bits), do: malformed_key()

  defp malformed_key,
    do: problem(:malformed_key, "4055#1.2", "the public key is not a DER RSAPublicKey")

  # A DER INTEGER (already checked by DER.check/1) with a positive value.
  defp positive_integer(<<0x02, rest::binary>>) do
    contents =
      case rest do
        <<n, contents::binary-size(n)>> when n < 0x80 -> contents
        <<1::1, size::7, n::size(size)-unit(8), contents::binary-size(n)>> -> contents
      end

    case contents do
      <<0::1, _::bitstring>> = bytes when bytes != <<0>> -> {:ok, :binary.decode_unsigned(bytes)}
      _ -> :error
    end
  end

  defp positive_integer(_other), do: :error

  defp key_size(%{bits: @key_bits}), do: :ok

  defp key_size(%{bits: bits}),
    do:
      problem(
        :key_size,
        "7935#3",
        "the RSA modulus is #{bits} bits; RPKI keys have a 2048-bit modulus"
      )

  defp key_exponent(%{exponent: @exponent}), do: :ok

  defp key_exponent(%{exponent: e}),
    do:
      problem(
        :key_exponent,
        "7935#3",
        "the RSA public exponent is #{e}; RPKI keys use 65,537"
      )

  # A BIT STRING carries the signature octets, first bit first (RFC 4055
  # §3.2); RFC 8017 §8.2.2 step 1 requires exactly k octets.
  defp signature_octets(signature, k) do
    cond do
      not is_binary(signature) ->
        problem(:malformed_signature, "5280#4.1.1.3", "the signature is not whole octets")

      byte_size(signature) != k ->
        problem(
          :signature_length,
          "8017#8.2.2",
          "the signature is #{byte_size(signature)} octets; the key needs #{k}"
        )

      true ->
        {:ok, signature}
    end
  end

  # RFC 8017 §8.2.2, steps 2 to 4.
  defp rsassa_pkcs1_v1_5_verify(%{modulus: n, exponent: e, bits: bits}, message, signature) do
    k = div(bits + 7, 8)
    s = :binary.decode_unsigned(signature)

    # RSAVP1 (§5.2.2) step 1.
    if s >= n do
      problem(
        :signature_out_of_range,
        "8017#5.2.2",
        "the signature representative is not below the modulus"
      )
    else
      m = :crypto.mod_pow(s, e, n)

      if i2osp(m, k) == emsa_pkcs1_v1_5_encode(message, k),
        do: :ok,
        else:
          problem(:bad_signature, "8017#8.2.2", "the signature does not match the signed data")
    end
  end

  # I2OSP (§4.1) of a value :crypto.mod_pow/3 returns as a minimal
  # big-endian binary.
  defp i2osp(m, k) when byte_size(m) <= k, do: <<0::size((k - byte_size(m)) * 8), m::binary>>

  # EMSA-PKCS1-v1_5-ENCODE (§9.2) with SHA-256. k is at least 256 here,
  # far above tLen + 11.
  defp emsa_pkcs1_v1_5_encode(message, k) do
    t = @sha256_digest_info <> :crypto.hash(:sha256, message)
    ps = :binary.copy(<<0xFF>>, k - byte_size(t) - 3)
    <<0x00, 0x01, ps::binary, 0x00, t::binary>>
  end

  defp bit_length(n), do: bit_length(n, 0)
  defp bit_length(0, count), do: count
  defp bit_length(n, count), do: bit_length(n >>> 1, count + 1)

  defp problem(rule, rfc, message), do: {:error, %{rule: rule, rfc: rfc, message: message}}
end
