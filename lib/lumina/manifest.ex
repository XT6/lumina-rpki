defmodule Lumina.Manifest do
  @moduledoc """
  Decodes RPKI manifests (RFC 9286): the `Manifest` eContent of a signed
  object, listing every file at a publication point with its hash.

  A manifest is `%Lumina.Manifest{version:, number:, this_update:,
  next_update:, file_hash_alg:, files: [%{name:, hash:}]}`. `object`
  holds the decoded envelope (`Lumina.SignedObject`) when the manifest came
  from a full signed object.

  Decoding is structural. `check/1` reports what's wrong with the content
  (#132): version, dates, manifest number, hash algorithm and file names
  (RFC 9286 §4.2.1, §4.2.2, §4.4), and an empty file list (§7, erratum
  7118, #37). An empty file list decodes, as the ASN.1 module as published
  allows it, so that `lumina print` can show it (F-001 in
  doc/rfc-findings.md). What a manifest
  does to its publication point (§6) is #133's.
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

  @sha256 {2, 16, 840, 1, 101, 3, 4, 2, 1}
  @number_limit Integer.pow(2, 159)

  # RFC 9286 §4.2.2: "one or more characters chosen from the set a-z, A-Z,
  # 0-9, - (HYPHEN), or _ (UNDERSCORE), followed by a single . (DOT),
  # followed by a three-letter extension".
  @file_name ~r/\A[a-zA-Z0-9_-]+\.[a-zA-Z0-9]{3}\z/

  # The IANA "RPKI Repository Name Schemes" registry (RFC 6481 §7.2), as
  # published on 2026-11-14 (last updated 2026-07-28), temporary and
  # deprecated entries included (F-032).
  @extensions ~w(asa ccr cdr cer crl gbr mft roa sig tak)

  @doc """
  The problems of `manifest`'s content, in the `Lumina.Profile` shape:

    * `:manifest_version`: not 0 (RFC 9286 §4.2.1, §4.4 item 2);
    * `:manifest_dates`: thisUpdate not before nextUpdate (§4.4 item 3);
    * `:manifest_number_range`: negative, or longer than 20 octets
      (§4.2.1);
    * `:manifest_hash_algorithm`: fileHashAlg not SHA-256 (§4.2.1, RFC
      7935 §2);
    * `:manifest_file_name`, `:manifest_file_extension`: a name outside
      §4.2.2's grammar, or an extension not in the IANA registry;
    * `:manifest_duplicate_name`: a name listed twice (names are compared
      case-sensitively, §4.2.2);
    * `:manifest_empty`: no files listed (§7: "A CA's manifest will always
      contain at least one entry"; verified erratum 7118 corrects the
      module's `SIZE (0..MAX)` to `SIZE (1..MAX)`).

  Dates that differ from the CRL's aren't a problem (§4.4: RPs "MUST NOT
  reject a manifest solely because these fields are not identical").
  """
  @spec check(t()) :: [Lumina.Profile.problem()]
  def check(%__MODULE__{} = manifest) do
    version(manifest.version) ++
      dates(manifest) ++
      number(manifest.number) ++
      hash_algorithm(manifest.file_hash_alg) ++
      empty(manifest.files) ++
      Enum.flat_map(manifest.files, &file_name(&1.name)) ++
      duplicates(manifest.files)
  end

  defp version(0), do: []

  defp version(version),
    do: [
      error(
        :manifest_version,
        "9286#4.4",
        :version,
        "the manifest version is #{version}; it must be 0"
      )
    ]

  defp dates(%{this_update: %{at: this}, next_update: %{at: next}}) do
    if DateTime.compare(this, next) == :lt,
      do: [],
      else: [
        error(
          :manifest_dates,
          "9286#4.4",
          :this_update,
          "thisUpdate (#{DateTime.to_iso8601(this)}) is not before nextUpdate (#{DateTime.to_iso8601(next)})"
        )
      ]
  end

  # 20 octets hold 0..2^159-1 as a DER INTEGER, the CRLNumber range RFC
  # 9286 §4.2.1 points to.
  defp number(number) when number >= 0 and number < @number_limit, do: []

  defp number(number) when number < 0,
    do: [
      error(
        :manifest_number_range,
        "9286#4.2.1",
        :manifest_number,
        "the manifest number is negative"
      )
    ]

  defp number(_number),
    do: [
      error(
        :manifest_number_range,
        "9286#4.2.1",
        :manifest_number,
        "the manifest number is longer than 20 octets"
      )
    ]

  defp hash_algorithm(@sha256), do: []

  defp hash_algorithm(oid),
    do: [
      error(
        :manifest_hash_algorithm,
        "9286#4.2.1",
        :file_hash_alg,
        "the file hash algorithm is #{Lumina.OID.format(oid)}; it must be SHA-256 (RFC 7935 section 2)"
      )
    ]

  defp empty([]),
    do: [
      error(
        :manifest_empty,
        "9286#7",
        :file_list,
        "manifest has no entries (RFC 9286 section 7, erratum 7118)"
      )
    ]

  defp empty(_files), do: []

  defp file_name(name) do
    cond do
      not Regex.match?(@file_name, name) ->
        [
          error(
            :manifest_file_name,
            "9286#4.2.2",
            :file_list,
            "the file name #{inspect(name)} is not letters, digits, - and _, a dot and a three-letter extension"
          )
        ]

      String.slice(name, -3, 3) not in @extensions ->
        [
          error(
            :manifest_file_extension,
            "9286#4.2.2",
            :file_list,
            "the extension of #{inspect(name)} is not in the RPKI Repository Name Schemes registry"
          )
        ]

      true ->
        []
    end
  end

  defp duplicates(files) do
    for {name, n} <- Enum.frequencies_by(files, & &1.name), n > 1 do
      error(
        :manifest_duplicate_name,
        "9286#4.2.1",
        :file_list,
        "#{inspect(name)} is listed #{n} times"
      )
    end
  end

  defp error(rule, rfc, field, message),
    do: %{rule: rule, rfc: rfc, field: field, message: message, severity: :error}

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
