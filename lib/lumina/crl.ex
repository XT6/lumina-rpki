defmodule Lumina.CRL do
  @moduledoc """
  Decodes certificate revocation lists (RFC 5280 §5, profiled by RFC 6487
  §5 and RFC 9829).

  Decoding is structural: a CRL that breaks the RPKI profile (for example
  with entry extensions, which RFC 6487 §5 forbids) still decodes, so
  validation (M4) can reject it with a precise reason. Decoding fails only
  when the input isn't DER or doesn't parse as a CRL.

  The exact DER of `tbsCertList` and of the issuer name are kept
  (`tbs_der`, `issuer_der`) for signature checks and issuer matching.
  """

  alias Lumina.{ASN1, DER, Extension, Name, Time}

  defstruct [
    :der,
    :tbs_der,
    :version,
    :tbs_signature_algorithm,
    :issuer,
    :issuer_der,
    :this_update,
    :next_update,
    :revoked,
    :extensions,
    :signature_algorithm,
    :signature
  ]

  @type algorithm :: %{oid: tuple(), parameters: binary() | nil}
  @type entry :: %{serial: integer(), revoked_at: Time.t(), extensions: [Extension.t()]}
  @type t :: %__MODULE__{
          der: binary(),
          tbs_der: binary(),
          version: 1 | 2,
          tbs_signature_algorithm: algorithm(),
          issuer: Name.t(),
          issuer_der: binary(),
          this_update: Time.t(),
          next_update: Time.t() | nil,
          revoked: [entry()],
          extensions: [Extension.t()],
          signature_algorithm: algorithm(),
          signature: bitstring()
        }

  @doc """
  Decodes a DER CRL.

  Errors say which layer failed: `{:der, error}`, `{:asn1, reason}` or
  `{:invalid_time, raw}`.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, term()}
  def decode(der) when is_binary(der) do
    with :ok <- der_check(DER.check(der)),
         {:ok, crl} <- ASN1.decode(:pkix, :CertificateList, der),
         :ok <- der_check(DER.check_canonical(:pkix, :CertificateList, der)),
         {:ok, [tbs_der, _algorithm, _signature]} <- DER.children(der),
         {:ok, tbs_parts} <- DER.children(tbs_der),
         tbs = crl.tbsCertList,
         {:ok, this_update} <- Time.parse(tbs.thisUpdate),
         {:ok, next_update} <- optional_time(Map.get(tbs, :nextUpdate)),
         {:ok, revoked} <- tbs |> Map.get(:revokedCertificates, []) |> entries() do
      # tbsCertList: [version], signature, issuer, ...; version is an
      # untagged INTEGER, present only for v2.
      parts = if match?(<<0x02, _::binary>>, hd(tbs_parts)), do: tl(tbs_parts), else: tbs_parts
      [_signature, issuer_der | _] = parts

      {:ok,
       %__MODULE__{
         der: der,
         tbs_der: tbs_der,
         version: if(Map.get(tbs, :version) == :v2, do: 2, else: 1),
         tbs_signature_algorithm: algorithm(tbs.signature),
         issuer: Name.from_asn1(tbs.issuer),
         issuer_der: issuer_der,
         this_update: this_update,
         next_update: next_update,
         revoked: revoked,
         extensions: tbs |> Map.get(:crlExtensions, []) |> Enum.map(&Extension.from_asn1/1),
         signature_algorithm: algorithm(crl.signatureAlgorithm),
         signature: crl.signature
       }}
    end
  end

  def decode(_other), do: {:error, :not_binary}

  @doc "The decoded value of CRL extension `name`, or `nil` if it is absent."
  @spec extension_value(t(), atom()) :: term()
  def extension_value(%__MODULE__{extensions: extensions}, name),
    do: Extension.value(extensions, name)

  @doc "The CRL Number (RFC 5280 §5.2.3), or `nil` if absent or malformed."
  @spec number(t()) :: non_neg_integer() | nil
  def number(crl) do
    case extension_value(crl, :crl_number) do
      n when is_integer(n) -> n
      _ -> nil
    end
  end

  @doc "Whether the CRL lists `serial` as revoked."
  @spec revoked?(t(), integer()) :: boolean()
  def revoked?(%__MODULE__{revoked: revoked}, serial),
    do: Enum.any?(revoked, &(&1.serial == serial))

  defp entries(list) do
    Enum.reduce_while(list, {:ok, []}, fn entry, {:ok, acc} ->
      case Time.parse(entry.revocationDate) do
        {:ok, at} ->
          extensions =
            entry |> Map.get(:crlEntryExtensions, []) |> Enum.map(&Extension.from_asn1/1)

          {:cont,
           {:ok,
            acc ++ [%{serial: entry.userCertificate, revoked_at: at, extensions: extensions}]}}

        error ->
          {:halt, error}
      end
    end)
  end

  defp optional_time(nil), do: {:ok, nil}
  defp optional_time(time), do: Time.parse(time)

  defp der_check(:ok), do: :ok
  defp der_check({:error, %{rule: _} = error}), do: {:error, {:der, error}}
  defp der_check({:error, _} = error), do: error

  defp algorithm(%{algorithm: oid} = alg), do: %{oid: oid, parameters: Map.get(alg, :parameters)}
end
