defmodule Lumina.Manifest do
  @moduledoc """
  Decodes RPKI manifests (RFC 9286): the `Manifest` eContent of a signed
  object, listing every file at a publication point with its hash.

  A manifest is `%Lumina.Manifest{version:, number:, this_update:,
  next_update:, file_hash_alg:, files: [%{name:, hash:}]}`. `object`
  holds the decoded envelope (`Lumina.SignedObject`) when the manifest came
  from a full signed object.

  Decoding is structural. The version, manifest number rules (RFC 9286
  §4.2.1, RFC 9981), time rules, file name rules (§4.2.2) and the rest of
  manifest validation (§4.4, §6) are checked in M5. In particular, an
  empty file list decodes: the ASN.1 module allows it, and rejecting it
  (RFC 9286 §7, erratum 7118) is validation's job (#37, F-001 in
  doc/rfc-findings.md).
  """

  alias Lumina.{DER, SignedObject, Time}

  defstruct [:object, :version, :number, :this_update, :next_update, :file_hash_alg, :files]

  @type file :: %{name: String.t(), hash: bitstring()}
  @type t :: %__MODULE__{
          object: SignedObject.t() | nil,
          version: non_neg_integer(),
          number: non_neg_integer(),
          this_update: Time.t(),
          next_update: Time.t(),
          file_hash_alg: tuple(),
          files: [file()]
        }

  @doc """
  Decodes a complete manifest signed object (CMS envelope plus eContent).
  Returns `{:error, {:not_manifest, content_type}}` if the object holds
  something else.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, term()}
  def decode(der) do
    with {:ok, object} <- SignedObject.decode(der), do: from_signed_object(object)
  end

  @doc "Decodes the manifest eContent of an already decoded signed object."
  @spec from_signed_object(SignedObject.t()) :: {:ok, t()} | {:error, term()}
  def from_signed_object(%SignedObject{} = object) do
    case SignedObject.content_type(object) do
      :manifest ->
        with {:ok, value} <- SignedObject.decode_econtent(object),
             {:ok, manifest} <- from_asn1(value),
             do: {:ok, %{manifest | object: object}}

      other ->
        {:error, {:not_manifest, other}}
    end
  end

  @doc "Decodes a bare `Manifest` eContent (no envelope)."
  @spec decode_econtent(binary()) :: {:ok, t()} | {:error, term()}
  def decode_econtent(der) do
    with :ok <- der_check(DER.check(der)),
         {:ok, value} <- Lumina.ASN1.decode(:manifest, :Manifest, der),
         :ok <- der_check(DER.check_canonical(:manifest, :Manifest, der)),
         do: from_asn1(value)
  end

  defp from_asn1(value) do
    with {:ok, this_update} <- Time.parse(value.thisUpdate),
         {:ok, next_update} <- Time.parse(value.nextUpdate) do
      {:ok,
       %__MODULE__{
         version: Map.get(value, :version, 0),
         number: value.manifestNumber,
         this_update: this_update,
         next_update: next_update,
         file_hash_alg: value.fileHashAlg,
         files:
           for(
             %{file: name, hash: hash} <- value.fileList,
             do: %{name: to_string(name), hash: hash}
           )
       }}
    end
  end

  @doc """
  The hash the manifest lists for `name`, or `nil`. A name listed more than
  once returns the first hash; validation checks for duplicates.
  """
  @spec hash(t(), String.t()) :: bitstring() | nil
  def hash(%__MODULE__{files: files}, name) do
    case Enum.find(files, &(&1.name == name)) do
      %{hash: hash} -> hash
      nil -> nil
    end
  end

  @doc "The file names the manifest lists, in order."
  @spec names(t()) :: [String.t()]
  def names(%__MODULE__{files: files}), do: Enum.map(files, & &1.name)

  defp der_check(:ok), do: :ok
  defp der_check({:error, %{rule: _} = error}), do: {:error, {:der, error}}
  defp der_check({:error, _} = error), do: error
end
