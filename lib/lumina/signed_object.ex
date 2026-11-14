defmodule Lumina.SignedObject do
  @moduledoc """
  Decodes the CMS SignedData envelope shared by every RPKI signed object
  (RFC 6488, built on RFC 5652): manifests, ROAs, Ghostbusters records, TAKs
  and RSCs.

  The result holds the eContent type and bytes, the embedded certificates
  (the EE certificate, decoded with `Lumina.Certificate`) and the signer
  information, with the signed attributes decoded. The eContent itself is
  left as bytes for the object-specific decoders; `content_type/1` names
  it.

  `signer.signed_attrs_der` is the exact DER the signature covers: the
  `signedAttrs` field re-tagged from `[0] IMPLICIT` to a SET OF, as RFC
  5652 §5.4 specifies.

  Decoding is structural. RFC 6488 §2.1 and §3 limit almost every field
  (exactly one certificate, no CRLs, specific attributes, and so on), but
  violations still decode, so validation (M5) can reject them precisely.
  Decoding fails only when the input isn't DER or doesn't parse.
  """

  alias Lumina.{ASN1, Certificate, DER, Time}

  defstruct [
    :der,
    :content_type,
    :version,
    :digest_algorithms,
    :econtent_type,
    :econtent,
    :certificates,
    :crls,
    :signers
  ]

  @type algorithm :: %{oid: tuple(), parameters: binary() | nil}
  @type attribute :: %{oid: tuple(), name: atom() | nil, values: [term()], der: [binary()]}
  @type signer :: %{
          version: atom(),
          sid: {:subject_key_identifier, binary()} | {:issuer_and_serial, term()},
          digest_algorithm: algorithm(),
          signed_attrs: [attribute()] | nil,
          signed_attrs_der: binary() | nil,
          signature_algorithm: algorithm(),
          signature: binary(),
          unsigned_attrs: [attribute()] | nil
        }
  @type t :: %__MODULE__{
          der: binary(),
          content_type: tuple(),
          version: atom(),
          digest_algorithms: [algorithm()],
          econtent_type: tuple(),
          econtent: binary() | nil,
          certificates: [Certificate.t() | {:other, atom(), term()}],
          crls: [term()] | nil,
          signers: [signer()]
        }

  @signed_data {1, 2, 840, 113_549, 1, 7, 2}

  # eContent types. Each entry replaces the CONTENT-TYPE information object
  # of its RFC's ASN.1 module, which was patched out (#23, F-005): OID ->
  # {name, Lumina.ASN1 module key and type, or nil if not decoded yet}.
  @content_types %{
    # RFC 9582 §4, ct-routeOriginAttestation
    {1, 2, 840, 113_549, 1, 9, 16, 1, 24} => {:roa, {:roa, :RouteOriginAttestation}},
    # RFC 9286 §4 and Appendix A, ct-rpkiManifest
    {1, 2, 840, 113_549, 1, 9, 16, 1, 26} => {:manifest, {:manifest, :Manifest}},
    # RFC 6493 §6 (decoded in M9)
    {1, 2, 840, 113_549, 1, 9, 16, 1, 35} => {:ghostbusters, nil},
    # RFC 9323 §4, ct-rpkiSignedChecklist (decoded in M9)
    {1, 2, 840, 113_549, 1, 9, 16, 1, 48} => {:rsc, nil},
    # RFC 9691 §2.1, ct-signedTAL (decoded in M9)
    {1, 2, 840, 113_549, 1, 9, 16, 1, 50} => {:tak, nil}
  }

  # Signed attributes (RFC 5652 §11, RFC 6488 §2.1.6.4, RFC 9589).
  @attributes %{
    {1, 2, 840, 113_549, 1, 9, 3} => {:content_type, :ContentType},
    {1, 2, 840, 113_549, 1, 9, 4} => {:message_digest, :MessageDigest},
    {1, 2, 840, 113_549, 1, 9, 5} => {:signing_time, :SigningTime},
    # RFC 6019; removed from RPKI by RFC 9589 §4, recognized so validation can say so.
    {1, 2, 840, 113_549, 1, 9, 16, 2, 46} => {:binary_signing_time, nil}
  }

  @doc """
  Decodes a DER signed object.

  Errors say which layer failed: `{:der, error}`, `{:asn1, reason}`,
  `{:not_signed_data, oid}` (a ContentInfo that isn't SignedData) or
  `{:certificate, reason}` (an embedded certificate that doesn't decode).
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, term()}
  def decode(der) when is_binary(der) do
    with :ok <- der_check(DER.check(der)),
         {:ok, %{contentType: content_type, content: sd_der}} <-
           ASN1.decode(:cms, :ContentInfo, der),
         :ok <- signed_data?(content_type),
         {:ok, sd} <- ASN1.decode(:cms, :SignedData, sd_der),
         :ok <- der_check(DER.check_canonical(:cms, :ContentInfo, der)),
         :ok <- der_check(DER.check_canonical(:cms, :SignedData, sd_der)),
         {:ok, parts} <- DER.children(sd_der),
         {:ok, certificates} <- certificates(parts),
         {:ok, signers} <- signers(sd.signerInfos, List.last(parts)) do
      {:ok,
       %__MODULE__{
         der: der,
         content_type: content_type,
         version: sd.version,
         digest_algorithms: Enum.map(sd.digestAlgorithms, &algorithm/1),
         econtent_type: sd.encapContentInfo.eContentType,
         econtent: Map.get(sd.encapContentInfo, :eContent),
         certificates: certificates,
         crls: Map.get(sd, :crls),
         signers: signers
       }}
    end
  end

  def decode(_other), do: {:error, :not_binary}

  @doc """
  The name of the object's eContent type (`:roa`, `:manifest`,
  `:ghostbusters`, `:rsc`, `:tak`), or `{:unknown, oid}`.
  """
  @spec content_type(t() | tuple()) :: atom() | {:unknown, tuple()}
  def content_type(%__MODULE__{econtent_type: oid}), do: content_type(oid)

  def content_type(oid) do
    case Map.fetch(@content_types, oid) do
      {:ok, {name, _decoder}} -> name
      :error -> {:unknown, oid}
    end
  end

  @doc """
  Decodes the eContent with the ASN.1 type its content type names, giving
  the raw ASN.1 value. The ROA and manifest modules build their structs on
  this. Returns `{:error, {:no_decoder, name}}` for types not decoded yet.
  """
  @spec decode_econtent(t()) :: {:ok, term()} | {:error, term()}
  def decode_econtent(%__MODULE__{econtent: nil}), do: {:error, :no_econtent}

  def decode_econtent(%__MODULE__{econtent_type: oid, econtent: econtent}) do
    case Map.get(@content_types, oid) do
      {_name, {key, type}} ->
        with :ok <- der_check(DER.check(econtent)),
             {:ok, value} <- ASN1.decode(key, type, econtent),
             :ok <- der_check(DER.check_canonical(key, type, econtent)),
             do: {:ok, value}

      {name, nil} ->
        {:error, {:no_decoder, name}}

      nil ->
        {:error, {:no_decoder, {:unknown, oid}}}
    end
  end

  @doc "The EE certificate: the first embedded certificate, or `nil`."
  @spec ee_certificate(t()) :: Certificate.t() | nil
  def ee_certificate(%__MODULE__{certificates: certificates}),
    do: Enum.find(certificates, &match?(%Certificate{}, &1))

  @doc """
  The decoded value of signed attribute `name` of the first signer (for
  example `:signing_time`), or `nil` if absent. An attribute should have
  exactly one value (RFC 6488 §2.1.6.4); this returns the first.
  """
  @spec signed_attribute(t(), atom()) :: term()
  def signed_attribute(%__MODULE__{signers: [signer | _]}, name) do
    case Enum.find(signer.signed_attrs || [], &(&1.name == name)) do
      %{values: [value | _]} -> value
      _ -> nil
    end
  end

  def signed_attribute(_object, _name), do: nil

  defp signed_data?(@signed_data), do: :ok
  defp signed_data?(oid), do: {:error, {:not_signed_data, oid}}

  # SignedData: version, digestAlgorithms, encapContentInfo,
  # [0] certificates, [1] crls, signerInfos. Certificates are taken from
  # the input bytes, so the EE certificate keeps its exact DER.
  defp certificates(parts) do
    case Enum.find(parts, &match?(<<0xA0, _::binary>>, &1)) do
      nil ->
        {:ok, []}

      set ->
        with {:ok, encodings} <- DER.children(set) do
          encodings
          |> Enum.map(fn
            <<0x30, _::binary>> = cert_der ->
              case Certificate.decode(cert_der) do
                {:ok, cert} -> {:ok, cert}
                {:error, reason} -> {:error, {:certificate, reason}}
              end

            <<tag, _::binary>> = other ->
              {:ok, {:other, tag, other}}
          end)
          |> collect()
        end
    end
  end

  # signerInfos is the last element of SignedData; its raw encodings give
  # each signer's exact signedAttrs bytes.
  defp signers(decoded, signer_infos_der) do
    with {:ok, encodings} <- DER.children(signer_infos_der) do
      decoded
      |> Enum.zip(encodings)
      |> Enum.map(fn {si, si_der} -> signer(si, si_der) end)
      |> collect()
    end
  end

  defp signer(si, si_der) do
    with {:ok, parts} <- DER.children(si_der) do
      signed_attrs_der =
        case Enum.find(parts, &match?(<<0xA0, _::binary>>, &1)) do
          <<0xA0, rest::binary>> -> <<0x31, rest::binary>>
          nil -> nil
        end

      {:ok,
       %{
         version: si.version,
         sid: sid(si.sid),
         digest_algorithm: algorithm(si.digestAlgorithm),
         signed_attrs: si |> Map.get(:signedAttrs) |> attributes(),
         signed_attrs_der: signed_attrs_der,
         signature_algorithm: algorithm(si.signatureAlgorithm),
         signature: si.signature,
         unsigned_attrs: si |> Map.get(:unsignedAttrs) |> attributes()
       }}
    end
  end

  defp sid({:subjectKeyIdentifier, ski}), do: {:subject_key_identifier, ski}
  defp sid({:issuerAndSerialNumber, value}), do: {:issuer_and_serial, value}

  defp attributes(nil), do: nil

  defp attributes(attrs) do
    for %{attrType: oid, attrValues: values} <- attrs do
      {name, type} = Map.get(@attributes, oid, {nil, nil})
      %{oid: oid, name: name, values: Enum.map(values, &attribute_value(type, &1)), der: values}
    end
  end

  # Each value is the DER of the attribute's type; a value that doesn't
  # decode is kept as {:malformed, der}.
  defp attribute_value(nil, der), do: {:raw, der}

  defp attribute_value(type, der) do
    with :ok <- DER.check(der),
         {:ok, value} <- ASN1.decode(:cms, type, der),
         {:ok, converted} <- convert(type, value) do
      converted
    else
      _ -> {:malformed, der}
    end
  end

  defp convert(:SigningTime, time), do: Time.parse(time)
  defp convert(_type, value), do: {:ok, value}

  defp algorithm(%{algorithm: oid} = alg), do: %{oid: oid, parameters: Map.get(alg, :parameters)}

  defp der_check(:ok), do: :ok
  defp der_check({:error, %{rule: _} = error}), do: {:error, {:der, error}}
  defp der_check({:error, _} = error), do: error

  defp collect(results) do
    Enum.reduce_while(results, {:ok, []}, fn
      {:ok, value}, {:ok, acc} -> {:cont, {:ok, acc ++ [value]}}
      {:error, _} = error, _ -> {:halt, error}
    end)
  end
end
