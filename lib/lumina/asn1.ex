defmodule Lumina.ASN1 do
  @moduledoc """
  Decodes and encodes values with the ASN.1 modules compiled from the RFCs
  (`asn1/build/`, compiled by `Mix.Tasks.Compile.LuminaAsn1` in `mix.exs`).

  Modules are named by a short key:

  | Key | ASN.1 module | Source |
  | --- | --- | --- |
  | `:pkix` | `PKIX1Explicit88` | RFC 5280 A.1: certificates, CRLs, names |
  | `:pkix_ext` | `PKIX1Implicit88` | RFC 5280 A.2: standard extensions |
  | `:cms` | `CryptographicMessageSyntax2004` | RFC 5652 §12.1 |
  | `:resources` | `IPAddrAndASCertExtn` | RFC 3779 App. A |
  | `:roa` | `RPKI-ROA-2023` | RFC 9582 §4 |
  | `:manifest` | `RPKIManifest` | RFC 9286 App. A |

  SEQUENCE and SET values are maps keyed by the ASN.1 field names; absent
  OPTIONAL fields are missing from the map. BIT STRINGs are bitstrings.

  The functions never raise: malformed input returns `{:error, reason}`.
  Trailing bytes after the value are an error, since asn1ct would
  otherwise ignore them silently. Checking that input is strict DER is
  `Lumina.DER`'s job (#25).
  """

  @modules %{
    pkix: :PKIX1Explicit88,
    pkix_ext: :PKIX1Implicit88,
    cms: :CryptographicMessageSyntax2004,
    resources: :IPAddrAndASCertExtn,
    roa: :"RPKI-ROA-2023",
    manifest: :RPKIManifest
  }

  @type module_key :: :pkix | :pkix_ext | :cms | :resources | :roa | :manifest
  @type reason ::
          {:unknown_module, term()}
          | {:unknown_type, module_key(), atom()}
          | :not_binary
          | {:trailing_bytes, pos_integer()}
          | {:asn1, term()}

  @doc "The module keys and the Erlang modules they name."
  @spec modules() :: %{module_key() => module()}
  def modules, do: @modules

  @doc """
  Decodes `der` as `type` from module `key`.

  ## Examples

      iex> Lumina.ASN1.decode(:pkix, :CertificateSerialNumber, <<2, 1, 5>>)
      {:ok, 5}

      iex> Lumina.ASN1.decode(:pkix, :CertificateSerialNumber, <<2, 1, 5, 0>>)
      {:error, {:trailing_bytes, 1}}

  """
  @spec decode(module_key(), atom(), binary()) :: {:ok, term()} | {:error, reason()}
  def decode(key, type, der) do
    with {:ok, mod} <- resolve(key, type),
         :ok <- binary(der) do
      safely(fn ->
        case mod.decode(type, der) do
          {:ok, value, <<>>} -> {:ok, value}
          {:ok, _value, rest} -> {:error, {:trailing_bytes, byte_size(rest)}}
          {:error, {:asn1, reason}} -> {:error, {:asn1, short(reason)}}
        end
      end)
    end
  end

  @doc """
  Encodes `value` as `type` from module `key`, in DER.

  ## Examples

      iex> Lumina.ASN1.encode(:pkix, :CertificateSerialNumber, 5)
      {:ok, <<2, 1, 5>>}

  """
  @spec encode(module_key(), atom(), term()) :: {:ok, binary()} | {:error, reason()}
  def encode(key, type, value) do
    with {:ok, mod} <- resolve(key, type) do
      safely(fn ->
        case mod.encode(type, value) do
          {:ok, der} -> {:ok, IO.iodata_to_binary(der)}
          {:error, {:asn1, reason}} -> {:error, {:asn1, short(reason)}}
        end
      end)
    end
  end

  defp resolve(key, type) do
    with {:ok, mod} <- fetch_module(key) do
      # asn1ct exports dec_<Type>/2 for every type it generates.
      if is_atom(type) and function_exported?(mod, :"dec_#{type}", 2),
        do: {:ok, mod},
        else: {:error, {:unknown_type, key, type}}
    end
  end

  defp fetch_module(key) do
    case Map.fetch(@modules, key) do
      {:ok, mod} ->
        {:module, ^mod} = Code.ensure_loaded(mod)
        {:ok, mod}

      :error ->
        {:error, {:unknown_module, key}}
    end
  end

  defp binary(der) when is_binary(der), do: :ok
  defp binary(_der), do: {:error, :not_binary}

  # Generated code reports most errors as {:error, ...} but can still raise
  # or throw on some malformed input.
  defp safely(fun) do
    fun.()
  rescue
    exception -> {:error, {:asn1, exception}}
  catch
    kind, reason -> {:error, {:asn1, {kind, short(reason)}}}
  end

  # asn1ct wraps reasons with a stacktrace: {reason, [stack frames]}.
  defp short({reason, [{_m, _f, _a, _loc} | _]}), do: reason
  defp short(reason), do: reason
end
