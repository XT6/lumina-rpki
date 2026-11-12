defmodule Mix.Lumina.RFC do
  @moduledoc """
  References from tests to RFC sections, checked against the RFC library in
  `doc/rfc/`.

  A reference is a string `"<rfc>#<section>"`, for example `"6487#4.8.9"`,
  `"5280#A.1"` or `"3779#B"`. See `doc/testing.md` for the convention.
  """

  @default_dir "doc/rfc"

  @type ref :: %{rfc: pos_integer(), section: String.t()}
  @type library :: %{pos_integer() => MapSet.t(String.t())}

  @ref_regex ~r/\A(?<rfc>[1-9][0-9]*)#(?<section>[0-9]+(?:\.[0-9]+)*|[A-Z](?:\.[0-9]+)*)\z/

  # Section headings start at column 0: "4.8.9.  Title", "A.1.  Title",
  # "Appendix A.  Title" or "Appendix A -- Title".
  @numbered_heading ~r/^([0-9]+(?:\.[0-9]+)*|[A-Z](?:\.[0-9]+)+)\.?\s+\S/m
  @appendix_heading ~r/^Appendix ([A-Z])(?:\.|\s)/m

  @doc """
  Parses a reference string.

  ## Examples

      iex> Mix.Lumina.RFC.parse("6487#4.8.9")
      {:ok, %{rfc: 6487, section: "4.8.9"}}

      iex> Mix.Lumina.RFC.parse("6487")
      {:error, "malformed RFC reference \\"6487\\", expected \\"<rfc>#<section>\\" such as \\"6487#4.8.9\\""}

  """
  @spec parse(term()) :: {:ok, ref()} | {:error, String.t()}
  def parse(string) when is_binary(string) do
    case Regex.named_captures(@ref_regex, string) do
      %{"rfc" => rfc, "section" => section} ->
        {:ok, %{rfc: String.to_integer(rfc), section: section}}

      nil ->
        {:error,
         "malformed RFC reference #{inspect(string)}, expected \"<rfc>#<section>\" such as \"6487#4.8.9\""}
    end
  end

  def parse(other), do: {:error, "RFC reference must be a string, got: #{inspect(other)}"}

  @doc """
  Loads the section numbers of every `rfcNNNN.txt` file in `dir`.
  """
  @spec load_library(Path.t()) :: library()
  def load_library(dir \\ @default_dir) do
    dir
    |> Path.join("rfc*.txt")
    |> Path.wildcard()
    |> Map.new(fn path ->
      "rfc" <> number = Path.basename(path, ".txt")
      {String.to_integer(number), path |> File.read!() |> sections()}
    end)
  end

  @doc """
  Extracts the section numbers from the plain text of an RFC.

  ## Examples

      iex> text = "1.  Introduction\\n\\n   Body text.\\n\\n4.8.9.  Certificate Policies\\nAppendix A.  Example\\nA.1.  Module\\n"
      iex> text |> Mix.Lumina.RFC.sections() |> Enum.sort()
      ["1", "4.8.9", "A", "A.1"]

  """
  @spec sections(String.t()) :: MapSet.t(String.t())
  def sections(text) do
    [@numbered_heading, @appendix_heading]
    |> Enum.flat_map(&Regex.scan(&1, text, capture: :all_but_first))
    |> Enum.map(&hd/1)
    |> MapSet.new()
  end

  @doc """
  Returns the section number if `line` is a section heading, else `nil`.

  ## Examples

      iex> Mix.Lumina.RFC.heading("4.8.9.  Certificate Policies")
      "4.8.9"

      iex> Mix.Lumina.RFC.heading("Appendix A -- ASN.1 Module")
      "A"

      iex> Mix.Lumina.RFC.heading("   indented body text")
      nil

  """
  @spec heading(String.t()) :: String.t() | nil
  def heading(line) do
    Enum.find_value([@numbered_heading, @appendix_heading], fn regex ->
      case Regex.run(regex, line, capture: :all_but_first) do
        [section] -> section
        nil -> nil
      end
    end)
  end

  @doc """
  Checks that a reference is well formed and points to an RFC and section
  that exist in `library`.
  """
  @spec validate(term(), library()) :: {:ok, ref()} | {:error, String.t()}
  def validate(string, library) do
    with {:ok, %{rfc: rfc, section: section} = ref} <- parse(string) do
      case Map.fetch(library, rfc) do
        :error ->
          {:error, "#{inspect(string)}: RFC #{rfc} is not in the RFC library (doc/rfc)"}

        {:ok, sections} ->
          if MapSet.member?(sections, section),
            do: {:ok, ref},
            else: {:error, "#{inspect(string)}: RFC #{rfc} has no section #{section}"}
      end
    end
  end

  @doc """
  Formats a reference back into its string form.
  """
  @spec format(ref()) :: String.t()
  def format(%{rfc: rfc, section: section}), do: "#{rfc}##{section}"

  @doc """
  Sorts section numbers in document order: numbered sections first, then
  appendices.

  ## Examples

      iex> Mix.Lumina.RFC.sort_sections(["10", "A.1", "2.10", "2.9", "A", "1"])
      ["1", "2.9", "2.10", "10", "A", "A.1"]

  """
  @spec sort_sections(Enumerable.t()) :: [String.t()]
  def sort_sections(sections), do: Enum.sort_by(sections, &section_key/1)

  defp section_key(section) do
    section
    |> String.split(".")
    |> Enum.map(fn
      <<letter, _::binary>> = part when letter in ?A..?Z -> {1, part}
      part -> {0, String.to_integer(part)}
    end)
  end
end
