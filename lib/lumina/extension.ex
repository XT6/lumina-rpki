defmodule Lumina.Extension do
  @moduledoc """
  One X.509 extension, from a certificate, a CRL or a CRL entry.

  `value` is the decoded value for the extensions Lumina knows, `:unknown`
  for others, and `{:malformed, reason}` when a known extension's value
  isn't DER or doesn't decode. Validation decides what each means; for
  example an unknown critical extension must make a certificate invalid
  (RFC 6487 §4.8).
  """

  alias Lumina.{ASN1, DER, Name, Resources}

  defstruct [:oid, :name, :critical, :der, :value]

  @type t :: %__MODULE__{
          oid: tuple(),
          name: atom() | nil,
          critical: boolean(),
          der: binary(),
          value: term()
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

  # Known extensions: name, ASN.1 module and type.
  @known %{
    # Certificates (RFC 5280 §4.2, RFC 3779, RFC 6487 §4.8)
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
    {1, 3, 6, 1, 5, 5, 7, 1, 8} => {:as_resources, :resources, :ASIdentifiers},
    # CRLs (RFC 5280 §5.2)
    {2, 5, 29, 20} => {:crl_number, :pkix_ext, :CRLNumber},
    {2, 5, 29, 27} => {:delta_crl_indicator, :pkix_ext, :BaseCRLNumber},
    {2, 5, 29, 28} => {:issuing_distribution_point, :pkix_ext, :IssuingDistributionPoint},
    # CRL entries (RFC 5280 §5.3)
    {2, 5, 29, 21} => {:reason_code, :pkix_ext, :CRLReason},
    {2, 5, 29, 24} => {:invalidity_date, :pkix_ext, :InvalidityDate},
    {2, 5, 29, 29} => {:certificate_issuer, :pkix_ext, :CertificateIssuer}
  }

  @doc """
  Converts a decoded `Extension` (`%{extnID:, critical:, extnValue:}`).
  """
  @spec from_asn1(map()) :: t()
  def from_asn1(%{extnID: oid, extnValue: der} = ext) do
    {name, value} =
      case Map.fetch(@known, oid) do
        {:ok, {name, key, type}} -> {name, decode_value(name, key, type, der)}
        :error -> {nil, :unknown}
      end

    %__MODULE__{
      oid: oid,
      name: name,
      critical: Map.get(ext, :critical, false),
      der: der,
      value: value
    }
  end

  @doc "The first extension named `name` in `extensions`, or `nil`."
  @spec find([t()], atom()) :: t() | nil
  def find(extensions, name), do: Enum.find(extensions, &(&1.name == name))

  @doc "The decoded value of the first extension named `name`, or `nil`."
  @spec value([t()], atom()) :: term()
  def value(extensions, name) do
    case find(extensions, name) do
      nil -> nil
      %__MODULE__{value: value} -> value
    end
  end

  @doc """
  The URIs of every access description with `method` in a decoded AIA or
  SIA value.
  """
  @spec access_uris(term(), atom()) :: [String.t()]
  def access_uris(descriptions, method) when is_list(descriptions) do
    for %{method: ^method, location: {:uri, uri}} <- descriptions, do: uri
  end

  def access_uris(_absent_or_malformed, _method), do: []

  defp decode_value(name, key, type, der) do
    result =
      with :ok <- DER.check(der) do
        case name do
          :ip_resources -> Resources.decode_ip(der)
          :as_resources -> Resources.decode_as(der)
          _ -> with {:ok, value} <- ASN1.decode(key, type, der), do: {:ok, convert(name, value)}
        end
      end

    case result do
      {:ok, value} -> value
      {:error, %{rule: _} = der_error} -> {:malformed, {:der, der_error}}
      {:error, reason} -> {:malformed, reason}
    end
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

  defp convert(:invalidity_date, time), do: time |> Lumina.Time.parse() |> elem_or(time)
  defp convert(:certificate_issuer, names), do: general_names(names)
  defp convert(_name, value), do: value

  defp elem_or({:ok, value}, _fallback), do: value
  defp elem_or({:error, _}, fallback), do: fallback

  defp general_names(nil), do: nil
  defp general_names(names), do: Enum.map(names, &Name.general_name/1)
end
