defmodule Mix.Lumina.TALCases do
  @moduledoc """
  The corpus of hand-written test TALs in `test/fixtures/tals/cases/` (#55).

  Each case is a folder holding `case.tal` (the TAL, byte for byte) and
  `case.exs` (literal metadata, read as data like the Barry fixture
  metadata):

      %{
        id: "invalid-two-blank-lines",
        title: "Two blank lines before the key",
        rationale: "...why this case exists...",
        rfc: ["8630#2.2"],
        expected: {:invalid, %{line: 3, rule: :extra_blank_line}}
      }

  `expected` is one of:

    * `:valid`
    * `{:valid, warnings: [%{line: n, rule: warning}, ...]}`
    * `{:invalid, %{line: n, rule: error}}`

  Lines are numbered from 1. A problem found at the end of the file is
  reported at the line after the last one.

  The rule names are the vocabulary the TAL parser (#54) reports;
  `error_rules/0` and `warning_rules/0` list them. See
  `test/fixtures/tals/README.md`.
  """

  alias Mix.Lumina.{Fixtures, RFC}

  @default_dir "test/fixtures/tals/cases"

  @error_rules [
    # RFC 8630 §2.2 structure
    :empty,
    :no_uri,
    :missing_separator,
    :extra_blank_line,
    :comment_after_uris,
    :empty_key,
    # URIs
    :unsupported_scheme,
    :invalid_uri,
    # Comments (UTF-8, RFC 5198 §2)
    :invalid_utf8,
    :invalid_comment_text,
    # The key
    :bad_base64,
    :not_der,
    :not_spki
  ]

  @warning_rules [:trailing_whitespace]

  @type tal_case :: %{
          id: String.t(),
          title: String.t(),
          rationale: String.t(),
          rfc: [String.t()],
          expected: term(),
          dir: Path.t(),
          tal: binary()
        }

  @doc "The corpus directory."
  @spec dir() :: Path.t()
  def dir, do: @default_dir

  @doc "Errors the TAL parser may report."
  @spec error_rules() :: [atom()]
  def error_rules, do: @error_rules

  @doc "Warnings the TAL parser may report."
  @spec warning_rules() :: [atom()]
  def warning_rules, do: @warning_rules

  @doc """
  Loads every case under `dir` and checks its metadata. Returns the cases
  that passed and the problems found.
  """
  @spec load_all(Path.t(), RFC.library()) ::
          {[tal_case()], [%{file: Path.t(), message: String.t()}]}
  def load_all(dir \\ @default_dir, library \\ RFC.load_library()) do
    dir
    |> Fixtures.case_dirs()
    |> Enum.map(&load(&1, library))
    |> Enum.reduce({[], []}, fn
      {:ok, tal_case}, {cases, problems} -> {cases ++ [tal_case], problems}
      {:error, found}, {cases, problems} -> {cases, problems ++ found}
    end)
  end

  @doc "Loads and checks one case folder."
  @spec load(Path.t(), RFC.library()) :: {:ok, tal_case()} | {:error, [map()]}
  def load(case_dir, library \\ RFC.load_library()) do
    meta_file = Fixtures.meta_path(case_dir)
    tal_file = Path.join(case_dir, "case.tal")

    with {:ok, meta} <- Fixtures.read_metadata(case_dir),
         [] <- problems(meta, case_dir, library) ++ tal_problems(tal_file) do
      {:ok, Map.merge(meta, %{dir: case_dir, tal: File.read!(tal_file)})}
    else
      {:error, message} -> {:error, [%{file: meta_file, message: message}]}
      messages -> {:error, Enum.map(messages, &%{file: meta_file, message: &1})}
    end
  end

  defp tal_problems(tal_file), do: if(File.regular?(tal_file), do: [], else: ["missing case.tal"])

  defp problems(meta, case_dir, library) do
    id = Path.basename(case_dir)
    required = [:id, :title, :rationale, :rfc, :expected]

    missing = for key <- required, not Map.has_key?(meta, key), do: "missing required key :#{key}"
    unknown = for key <- Map.keys(meta), key not in required, do: "unknown key #{inspect(key)}"

    missing ++
      unknown ++
      check(meta, :id, fn
        ^id -> []
        other -> ["id #{inspect(other)} must match the folder name #{inspect(id)}"]
      end) ++
      check(meta, :title, &non_blank(&1, :title)) ++
      check(meta, :rationale, &non_blank(&1, :rationale)) ++
      check(meta, :rfc, fn
        [_ | _] = refs ->
          for ref <- refs,
              {:error, message} <- [RFC.validate(ref, library)],
              do: "rfc: #{message}"

        _ ->
          ["rfc must be a non-empty list of RFC references such as \"8630#2.2\""]
      end) ++
      check(meta, :expected, &expected_problems/1)
  end

  defp check(meta, key, fun) do
    case Map.fetch(meta, key) do
      {:ok, value} -> fun.(value)
      :error -> []
    end
  end

  defp non_blank(value, key) do
    if is_binary(value) and String.trim(value) != "",
      do: [],
      else: ["#{key} must be a non-blank string"]
  end

  defp expected_problems(:valid), do: []

  defp expected_problems({:valid, [warnings: [_ | _] = warnings]}) do
    Enum.flat_map(warnings, &finding_problems(&1, @warning_rules, "warning"))
  end

  defp expected_problems({:invalid, finding}),
    do: finding_problems(finding, @error_rules, "error")

  defp expected_problems(other) do
    [
      "expected must be :valid, {:valid, warnings: [...]} or {:invalid, %{line:, rule:}}, got: #{inspect(other)}"
    ]
  end

  defp finding_problems(%{line: line, rule: rule} = finding, rules, kind)
       when map_size(finding) == 2 do
    cond do
      not (is_integer(line) and line > 0) ->
        ["#{kind} line must be a positive integer, got: #{inspect(line)}"]

      rule not in rules ->
        [
          "unknown #{kind} rule #{inspect(rule)} (known: #{Enum.map_join(rules, ", ", &inspect/1)})"
        ]

      true ->
        []
    end
  end

  defp finding_problems(other, _rules, kind),
    do: ["#{kind} must be %{line: n, rule: atom}, got: #{inspect(other)}"]
end
