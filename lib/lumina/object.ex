defmodule Lumina.Object do
  @moduledoc """
  Decodes any file found in an RPKI repository, choosing the decoder from
  the file name extension.

  Extensions come from the "RPKI Repository Name Scheme" registry: RFC
  6481 §7.2 (`.cer`, `.crl`, `.mft`, `.roa`), RFC 6493 §9.2 (`.gbr`), RFC
  9323 §9.3 (`.sig`) and RFC 9691 §11.3 (`.tak`). They are matched exactly as
  registered. `.asa` (ASPA) isn't recognized: ASPA is not an RFC yet.

  | Extension | `type` | `value` |
  | --- | --- | --- |
  | `.cer` | `:certificate` | `Lumina.Certificate` |
  | `.crl` | `:crl` | `Lumina.CRL` |
  | `.mft` | `:manifest` | `Lumina.Manifest` |
  | `.roa` | `:roa` | `Lumina.ROA` |
  | `.gbr`, `.sig`, `.tak` | `:ghostbusters`, `:rsc`, `:tak` | `Lumina.SignedObject`, eContent not decoded until M9 |

  For signed objects, the eContent type must agree with the extension.

  Errors name the layer that failed:

    * `{:der, error}`: not DER
    * `{:asn1, reason}`: not the expected ASN.1 structure
    * `{:invalid_time, raw}`: a time that isn't a real date
    * `{:envelope, reason}`: the CMS envelope is broken (not SignedData, or
      its EE certificate doesn't decode)
    * `{:econtent, reason}`: the eContent doesn't decode
    * `{:content_type_mismatch, %{extension:, content_type:}}`
    * `:unknown_type`: the extension isn't registered
  """

  alias Lumina.{Certificate, CRL, Manifest, ROA, SignedObject}

  defstruct [:name, :type, :value]

  @type type :: :certificate | :crl | :manifest | :roa | :ghostbusters | :rsc | :tak
  @type t :: %__MODULE__{name: String.t(), type: type(), value: struct()}

  @types %{
    ".cer" => :certificate,
    ".crl" => :crl,
    ".mft" => :manifest,
    ".roa" => :roa,
    ".gbr" => :ghostbusters,
    ".sig" => :rsc,
    ".tak" => :tak
  }

  @signed [:manifest, :roa, :ghostbusters, :rsc, :tak]

  @doc "The object type for a file name, or `nil` if its extension isn't registered."
  @spec type(String.t()) :: type() | nil
  def type(file_name), do: Map.get(@types, Path.extname(file_name))

  @doc """
  Decodes `bytes` as the object type named by `file_name`'s extension.
  """
  @spec decode(String.t(), binary()) :: {:ok, t()} | {:error, term()}
  def decode(file_name, bytes) when is_binary(bytes) do
    case type(file_name) do
      nil ->
        {:error, :unknown_type}

      type ->
        with {:ok, value} <- decode_as(type, bytes),
             do: {:ok, %__MODULE__{name: file_name, type: type, value: value}}
    end
  end

  @doc "Reads and decodes a file."
  @spec decode_file(Path.t()) :: {:ok, t()} | {:error, term()}
  def decode_file(path) do
    with {:ok, bytes} <- File.read(path), do: decode(Path.basename(path), bytes)
  end

  @doc """
  The layer an error from `decode/2` belongs to: `:der`, `:asn1`,
  `:envelope`, `:econtent`, `:type` or `:file`.
  """
  @spec layer(term()) :: atom()
  def layer({:der, _}), do: :der
  def layer({:asn1, _}), do: :asn1
  def layer({:invalid_time, _}), do: :asn1
  def layer({:envelope, _}), do: :envelope
  def layer({:econtent, _}), do: :econtent
  def layer({:content_type_mismatch, _}), do: :type
  def layer(:unknown_type), do: :type
  def layer(_other), do: :file

  defp decode_as(:certificate, bytes), do: Certificate.decode(bytes)
  defp decode_as(:crl, bytes), do: CRL.decode(bytes)

  defp decode_as(type, bytes) when type in @signed do
    with {:ok, object} <- envelope(bytes),
         :ok <- same_type(type, object) do
      econtent(type, object)
    end
  end

  # A file that isn't DER or doesn't parse at all fails at those layers;
  # a well-formed CMS structure that's wrong fails at the envelope.
  defp envelope(bytes) do
    case SignedObject.decode(bytes) do
      {:ok, object} -> {:ok, object}
      {:error, {layer, _} = error} when layer in [:der, :asn1] -> {:error, error}
      {:error, reason} -> {:error, {:envelope, reason}}
    end
  end

  defp same_type(type, object) do
    case SignedObject.content_type(object) do
      ^type -> :ok
      other -> {:error, {:content_type_mismatch, %{extension: type, content_type: other}}}
    end
  end

  defp econtent(:roa, object), do: econtent_error(ROA.from_signed_object(object))
  defp econtent(:manifest, object), do: econtent_error(Manifest.from_signed_object(object))
  defp econtent(_not_yet_decoded, object), do: {:ok, object}

  defp econtent_error({:ok, value}), do: {:ok, value}
  defp econtent_error({:error, reason}), do: {:error, {:econtent, reason}}
end
