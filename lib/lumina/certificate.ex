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

  alias Lumina.{ASN1, DER, Name, Resources, Time}

  defmodule Extension do
    @moduledoc """
    One certificate extension. `value` is the decoded value for the
    extensions Lumina knows, `:unknown` for others, and
    `{:malformed, reason}` when a known extension's value doesn't decode.
    Validation decides what each of those means.
    """
    defstruct [:oid, :name, :critical, :der, :value]

    @type t :: %__MODULE__{
            oid: tuple(),
            name: atom() | nil,
            critical: boolean(),
            der: binary(),
            value: term()
          }
  end

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

  # Access methods (RFC 5280 §4.2.2, RFC 6487 §4.8.8, RFC 8182 §3.2).
  @access_methods %{
    {1, 3, 6, 1, 5, 5, 7, 48, 1} => :ocsp,
    {1, 3, 6, 1, 5, 5, 7, 48, 2} => :ca_issuers,
    {1, 3, 6, 1, 5, 5, 7, 48, 5} => :ca_repository,
    {1, 3, 6, 1, 5, 5, 7, 48, 10} => :rpki_manifest,
    {1, 3, 6, 1, 5, 5, 7, 48, 11} => :signed_object,
    {1, 3, 6, 1, 5, 5, 7, 48, 13} => :rpki_notify
  }

  # Known extensions: name, ASN.1 module and type, and how to convert.
  @extensions %{
    {2, 5, 29, 19} => {:basic_constraints, :pkix_ext, :BasicConstraints},
    {2, 5, 29, 14} => {:subject_key_identifier, :pkix_ext, :SubjectKeyIdentifier},
    {2, 5, 29, 35} => {:authority_key_identifier, :pkix_ext, :AuthorityKeyIdentifier},
    {2, 5, 29, 15} => {:key_usage, :pkix_ext, :KeyUsage},
    {2, 5, 29, 37} => {:extended_key_usage, :pkix_ext, :ExtKeyUsageSyntax},
    {2, 5, 29, 31} => {:crl_distribution_points, :pkix_ext, :CRLDistributionPoints},
    {1, 3, 6, 1, 5, 5, 7, 1, 1} =>
      {:authority_info_access, :pkix_ext, :AuthorityInfoAccessSyntax},
    {1, 3, 6, 1, 5, 5, 7, 1, 11} => {:subject_info_access, :pkix_ext, :SubjectInfoAccessSyntax},
    {2, 5, 29, 32} => {:certificate_policies, :pkix_ext, :CertificatePolicies},
    {1, 3, 6, 1, 5, 5, 7, 1, 7} => {:ip_resources, :resources, :IPAddrBlocks},
    {1, 3, 6, 1, 5, 5, 7, 1, 8} => {:as_resources, :resources, :ASIdentifiers}
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
         extensions: tbs |> Map.get(:extensions, []) |> Enum.map(&extension/1),
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
  def extension(%__MODULE__{extensions: extensions}, name),
    do: Enum.find(extensions, &(&1.name == name))

  @doc """
  The decoded value of extension `name`, or `nil` if it is absent.
  """
  @spec extension_value(t(), atom()) :: term()
  def extension_value(cert, name) do
    case extension(cert, name) do
      nil -> nil
      %Extension{value: value} -> value
    end
  end

  @doc """
  The URIs of every access description with `method` in the SIA or AIA
  extension, for example `sia_uris(cert, :rpki_manifest)`.
  """
  @spec sia_uris(t(), atom()) :: [String.t()]
  def sia_uris(cert, method), do: access_uris(extension_value(cert, :subject_info_access), method)

  @doc "Like `sia_uris/2`, for the Authority Information Access extension."
  @spec aia_uris(t(), atom()) :: [String.t()]
  def aia_uris(cert, method),
    do: access_uris(extension_value(cert, :authority_info_access), method)

  defp access_uris(descriptions, method) when is_list(descriptions) do
    for %{method: ^method, location: {:uri, uri}} <- descriptions, do: uri
  end

  defp access_uris(_absent_or_malformed, _method), do: []

  defp der_check(:ok), do: :ok
  defp der_check({:error, %{rule: _} = error}), do: {:error, {:der, error}}
  defp der_check({:error, _} = error), do: error

  defp version(:v1), do: 1
  defp version(:v2), do: 2
  defp version(:v3), do: 3

  defp algorithm(%{algorithm: oid} = alg), do: %{oid: oid, parameters: Map.get(alg, :parameters)}

  defp extension(%{extnID: oid, extnValue: value} = ext) do
    critical = Map.get(ext, :critical, false)

    {name, decoded} =
      case Map.fetch(@extensions, oid) do
        {:ok, {name, key, type}} -> {name, decode_extension(name, key, type, value)}
        :error -> {nil, :unknown}
      end

    %Extension{oid: oid, name: name, critical: critical, der: value, value: decoded}
  end

  defp decode_extension(name, key, type, der) do
    with :ok <- der_check(DER.check(der)),
         {:ok, value} <- decode_value(name, key, type, der) do
      value
    else
      {:error, reason} -> {:malformed, reason}
    end
  end

  defp decode_value(:ip_resources, _key, _type, der), do: Resources.decode_ip(der)
  defp decode_value(:as_resources, _key, _type, der), do: Resources.decode_as(der)

  defp decode_value(name, key, type, der) do
    with {:ok, value} <- ASN1.decode(key, type, der), do: {:ok, convert(name, value)}
  end

  defp convert(:basic_constraints, value),
    do: %{ca: Map.get(value, :cA, false), path_len: Map.get(value, :pathLenConstraint)}

  defp convert(:authority_key_identifier, value) do
    %{
      key_identifier: Map.get(value, :keyIdentifier),
      issuer: value |> Map.get(:authorityCertIssuer) |> general_names(),
      serial: Map.get(value, :authorityCertSerialNumber)
    }
  end

  defp convert(:crl_distribution_points, points) do
    for point <- points do
      full_name =
        case Map.get(point, :distributionPoint) do
          {:fullName, names} -> general_names(names)
          other -> other
        end

      %{
        full_name: full_name,
        reasons: Map.get(point, :reasons),
        crl_issuer: point |> Map.get(:cRLIssuer) |> general_names()
      }
    end
  end

  defp convert(name, descriptions) when name in [:authority_info_access, :subject_info_access] do
    for %{accessMethod: oid, accessLocation: location} <- descriptions do
      %{method: Map.get(@access_methods, oid, oid), location: Name.general_name(location)}
    end
  end

  defp convert(:certificate_policies, policies) do
    for policy <- policies do
      %{oid: policy.policyIdentifier, qualifiers: Map.get(policy, :policyQualifiers, [])}
    end
  end

  defp convert(_name, value), do: value

  defp general_names(nil), do: nil
  defp general_names(names), do: Enum.map(names, &Name.general_name/1)
end
