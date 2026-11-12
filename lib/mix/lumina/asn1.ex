defmodule Mix.Lumina.ASN1 do
  @moduledoc """
  Extracts ASN.1 modules from the RFC texts in `doc/rfc/`.

  The extracted modules are the RFC text with only the page furniture
  removed (form feeds, page footers, running headers), runs of blank lines
  collapsed and the common indentation stripped. ASN.1 ignores whitespace,
  so the result is the module exactly as the RFC defines it. See
  `asn1/README.md` and `mix lumina.asn1.extract`.
  """

  alias Mix.Lumina.RFC

  @output_dir "asn1/rfc"

  # The modules Lumina compiles: name, source RFC and the section that holds
  # the module. Add a module here when a milestone needs it.
  @modules [
    %{name: "PKIX1Explicit88", rfc: 5280, section: "A.1"},
    %{name: "PKIX1Implicit88", rfc: 5280, section: "A.2"},
    %{name: "CryptographicMessageSyntax2004", rfc: 5652, section: "12.1"},
    %{name: "AttributeCertificateVersion1", rfc: 5652, section: "12.2"},
    %{name: "IPAddrAndASCertExtn", rfc: 3779, section: "A"},
    %{name: "RPKI-ROA-2023", rfc: 9582, section: "4"},
    %{name: "RPKIManifest", rfc: 9286, section: "A"}
  ]

  @type spec :: %{name: String.t(), rfc: pos_integer(), section: String.t()}

  @doc "The modules to extract."
  @spec modules() :: [spec()]
  def modules, do: @modules

  @doc "Directory the extracted modules are written to."
  @spec output_dir() :: Path.t()
  def output_dir, do: @output_dir

  @doc "File name of an extracted module."
  @spec file_name(spec()) :: String.t()
  def file_name(%{name: name}), do: name <> ".asn1"

  @doc """
  Extracts the module described by `spec` from the text of its RFC and
  returns the file contents, header comment included.
  """
  @spec extract(spec(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def extract(spec, rfc_text) do
    lines = rfc_text |> String.split(~r/\r?\n/) |> remove_page_furniture()

    with {:ok, start} <- find_start(lines, spec.name),
         {:ok, stop} <- find_end(lines, start, spec.name),
         :ok <- check_section(lines, start, spec) do
      body = lines |> Enum.slice(start..stop) |> collapse_blank_lines() |> dedent()
      {:ok, header(spec) <> Enum.join(body, "\n") <> "\n"}
    end
  end

  @doc """
  Removes RFC page furniture: lines containing a form feed, page footers
  ending in `[Page N]` and running headers starting with `RFC NNNN`.

  ## Examples

      iex> Mix.Lumina.ASN1.remove_page_furniture([
      ...>   "   Foo ::= INTEGER",
      ...>   "Cooper, et al.        Standards Track          [Page 117]",
      ...>   "\\f",
      ...>   "RFC 5280        PKIX Certificate and CRL Profile        May 2008",
      ...>   "   Bar ::= BOOLEAN"
      ...> ])
      ["   Foo ::= INTEGER", "   Bar ::= BOOLEAN"]

  """
  @spec remove_page_furniture([String.t()]) :: [String.t()]
  def remove_page_furniture(lines) do
    Enum.reject(lines, fn line ->
      String.contains?(line, "\f") or
        Regex.match?(~r/\[Page \d+\]\s*$/, line) or
        Regex.match?(~r/^RFC \d+ /, line)
    end)
  end

  @doc """
  Collapses each run of blank lines into a single blank line.
  """
  @spec collapse_blank_lines([String.t()]) :: [String.t()]
  def collapse_blank_lines(lines) do
    lines
    |> Enum.chunk_by(&blank?/1)
    |> Enum.flat_map(fn
      [line | _] = chunk -> if blank?(line), do: [""], else: chunk
    end)
  end

  @doc """
  Strips trailing whitespace and the indentation common to all non-blank
  lines.
  """
  @spec dedent([String.t()]) :: [String.t()]
  def dedent(lines) do
    lines = Enum.map(lines, &String.trim_trailing/1)

    indent =
      lines
      |> Enum.reject(&blank?/1)
      |> Enum.map(&(byte_size(&1) - byte_size(String.trim_leading(&1, " "))))
      |> Enum.min(fn -> 0 end)

    Enum.map(lines, &binary_slice(&1, min(indent, byte_size(&1))..-1//1))
  end

  # A module starts at a line holding its name, alone or followed by its
  # OID, with DEFINITIONS within the next few lines.
  defp find_start(lines, name) do
    pattern = ~r/^\s*#{Regex.escape(name)}(\s*\{.*|\s*)$/

    lines
    |> Enum.with_index()
    |> Enum.find_value(fn {line, index} ->
      if Regex.match?(pattern, line) and definitions_follow?(lines, index), do: index
    end)
    |> case do
      nil -> {:error, "module #{name} not found"}
      index -> {:ok, index}
    end
  end

  defp definitions_follow?(lines, index) do
    lines |> Enum.slice(index, 8) |> Enum.any?(&String.contains?(&1, "DEFINITIONS"))
  end

  defp find_end(lines, start, name) do
    lines
    |> Enum.with_index()
    |> Enum.drop(start)
    |> Enum.find_value(fn {line, index} -> if end_line?(line), do: index end)
    |> case do
      nil -> {:error, "module #{name}: no END line after the module header"}
      index -> {:ok, index}
    end
  end

  # The module must sit inside the section the spec names: after that
  # section's heading and before the next heading.
  defp check_section(lines, start, spec) do
    section_at_start =
      lines
      |> Enum.take(start + 1)
      |> Enum.map(&RFC.heading/1)
      |> Enum.reject(&is_nil/1)
      |> List.last()

    if section_at_start == spec.section,
      do: :ok,
      else:
        {:error,
         "module #{spec.name} is in section #{inspect(section_at_start)} of RFC #{spec.rfc}, " <>
           "not #{spec.section}"}
  end

  defp header(spec) do
    """
    -- #{spec.name}: extracted from RFC #{spec.rfc}, section #{spec.section},
    -- by `mix lumina.asn1.extract`. Do not edit; regenerate instead.
    -- Only page furniture, extra blank lines and indentation were removed.

    """
  end

  # "END", optionally followed by a comment ("END -- of Module").
  defp end_line?(line), do: Regex.match?(~r/^\s*END\s*(--.*)?$/, line)

  defp blank?(line), do: String.trim(line) == ""
end
