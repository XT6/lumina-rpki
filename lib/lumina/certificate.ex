defmodule Lumina.Certificate do
  @moduledoc """
  Decodes RPKI resource certificates (TA, CA and EE): X.509 certificates
  (RFC 5280) profiled by RFC 6487.

  Decoding is structural. A certificate that breaks the RPKI profile, for
  example version 2 or a missing Subject Key Identifier, still decodes, so
  validation (M4) can reject it with a precise reason. Decoding fails only
  when the input isn't DER or doesn't parse as a certificate.

  The exact DER of `tbsCertificate`, the names and the public key are kept
  (`tbs_der`, `issuer_der`, `subject_der`, `public_key.der`) because
  signatures and key identifiers are computed over them.

  Field names follow the ASN.1 module (RFC 5280 A.1), which calls the
  signature value `signature`; RFC 5280 §4.1 calls it `signatureValue`
  (F-008 in doc/rfc-findings.md). The algorithm inside `tbsCertificate`
  is `tbs_signature_algorithm`, and the outer one `signature_algorithm`.
  """

  alias Lumina.{ASN1, DER, Extension, Name, Time}

  defstruct [
    :der,
    :tbs_der,
    :version,
    :serial,
    :tbs_signature_algorithm,
    :issuer,
    :issuer_der,
    :not_before,
    :not_after,
    :subject,
    :subject_der,
    :public_key,
    :issuer_unique_id,
    :subject_unique_id,
    :extensions,
    :signature_algorithm,
    :signature
  ]

  @type algorithm :: %{oid: tuple(), parameters: binary() | nil}
  @type t :: %__MODULE__{
          der: binary(),
          tbs_der: binary(),
          version: 1 | 2 | 3,
          serial: integer(),
          tbs_signature_algorithm: algorithm(),
          issuer: Name.t(),
          issuer_der: binary(),
          not_before: Time.t(),
          not_after: Time.t(),
          subject: Name.t(),
          subject_der: binary(),
          public_key: %{algorithm: algorithm(), key: bitstring(), der: binary()},
          issuer_unique_id: bitstring() | nil,
          subject_unique_id: bitstring() | nil,
          extensions: [Extension.t()],
          signature_algorithm: algorithm(),
          signature: bitstring()
        }

  @doc """
  Decodes a DER certificate.

  Errors say which layer failed: `{:der, error}` (not DER, see
  `Lumina.DER`), `{:asn1, reason}` (not a certificate) or
  `{:invalid_time, raw}` (a validity time that isn't a real date).
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, term()}
  def decode(der) when is_binary(der) do
    with :ok <- der_check(DER.check(der)),
         {:ok, cert} <- ASN1.decode(:pkix, :Certificate, der),
         :ok <- der_check(DER.check_canonical(:pkix, :Certificate, der)),
         {:ok, [tbs_der, _algorithm, _signature]} <- DER.children(der),
         {:ok, tbs_parts} <- DER.children(tbs_der),
         tbs = cert.tbsCertificate,
         {:ok, not_before} <- Time.parse(tbs.validity.notBefore),
         {:ok, not_after} <- Time.parse(tbs.validity.notAfter) do
      # tbsCertificate: [version], serial, signature, issuer, validity,
      # subject, subjectPublicKeyInfo, ...; version is explicitly tagged [0].
      parts = if match?(<<0xA0, _::binary>>, hd(tbs_parts)), do: tl(tbs_parts), else: tbs_parts
      [_serial, _sig, issuer_der, _validity, subject_der, spki_der | _] = parts

      {:ok,
       %__MODULE__{
         der: der,
         tbs_der: tbs_der,
         version: version(Map.get(tbs, :version, :v1)),
         serial: tbs.serialNumber,
         tbs_signature_algorithm: algorithm(tbs.signature),
         issuer: Name.from_asn1(tbs.issuer),
         issuer_der: issuer_der,
         not_before: not_before,
         not_after: not_after,
         subject: Name.from_asn1(tbs.subject),
         subject_der: subject_der,
         public_key: %{
           algorithm: algorithm(tbs.subjectPublicKeyInfo.algorithm),
           key: tbs.subjectPublicKeyInfo.subjectPublicKey,
           der: spki_der
         },
         issuer_unique_id: Map.get(tbs, :issuerUniqueID),
         subject_unique_id: Map.get(tbs, :subjectUniqueID),
         extensions: tbs |> Map.get(:extensions, []) |> Enum.map(&Extension.from_asn1/1),
         signature_algorithm: algorithm(cert.signatureAlgorithm),
         signature: cert.signature
       }}
    end
  end

  def decode(_other), do: {:error, :not_binary}

  @doc """
  The first extension named `name`, or `nil`. Certificates should not
  repeat an extension (RFC 5280 §4.2); validation checks for duplicates.
  """
  @spec extension(t(), atom()) :: Extension.t() | nil
  def extension(%__MODULE__{extensions: extensions}, name), do: Extension.find(extensions, name)

  @doc """
  The decoded value of extension `name`, or `nil` if it is absent.
  """
  @spec extension_value(t(), atom()) :: term()
  def extension_value(%__MODULE__{extensions: extensions}, name),
    do: Extension.value(extensions, name)

  @doc """
  The URIs of every access description with `method` in the SIA
  extension, for example `sia_uris(cert, :rpki_manifest)`.
  """
  @spec sia_uris(t(), atom()) :: [String.t()]
  def sia_uris(cert, method),
    do: Extension.access_uris(extension_value(cert, :subject_info_access), method)

  @doc "Like `sia_uris/2`, for the Authority Information Access extension."
  @spec aia_uris(t(), atom()) :: [String.t()]
  def aia_uris(cert, method),
    do: Extension.access_uris(extension_value(cert, :authority_info_access), method)

  defp der_check(:ok), do: :ok
  defp der_check({:error, %{rule: _} = error}), do: {:error, {:der, error}}
  defp der_check({:error, _} = error), do: error

  defp version(:v1), do: 1
  defp version(:v2), do: 2
  defp version(:v3), do: 3

  defp algorithm(%{algorithm: oid} = alg), do: %{oid: oid, parameters: Map.get(alg, :parameters)}
end
