defmodule Mix.Lumina.RFCTags do
  @moduledoc """
  Finds the RFC references attached to tests by reading test source files.

  Tests reference RFC sections through the `:rfc` tag, set with `@tag`,
  `@describetag` or `@moduletag`. The value is a reference string or a list
  of them:

      @moduletag rfc: "6487#4"

      describe "certificate policies" do
        @describetag rfc: "6487#4.8.9"

        @tag rfc: ["7318#2", "6487#4.8.9"]
        test "accepts a policy qualifier" do
          ...
        end
      end

  A test's references are its own plus those of its `describe` block and
  module. Tags are read from the source rather than from a test run, so the
  report needs no compilation and every reference can be checked.
  """

  alias Mix.Lumina.RFC

  @type tagged_test :: %{
          file: Path.t(),
          line: pos_integer(),
          name: String.t(),
          refs: [String.t()]
        }
  @type problem :: %{file: Path.t(), line: pos_integer(), message: String.t()}

  @doc """
  Scans the test files under `dir` (`**/*_test.exs`).
  """
  @spec scan_dir(Path.t()) :: {[tagged_test()], [problem()]}
  def scan_dir(dir) do
    dir
    |> Path.join("**/*_test.exs")
    |> Path.wildcard()
    |> Enum.sort()
    |> Enum.map(&scan_file(File.read!(&1), &1))
    |> Enum.reduce({[], []}, fn {tests, problems}, {all_tests, all_problems} ->
      {all_tests ++ tests, all_problems ++ problems}
    end)
  end

  @doc """
  Scans the source of one test file. `file` is only used in the results.
  """
  @spec scan_file(String.t(), Path.t()) :: {[tagged_test()], [problem()]}
  def scan_file(source, file) do
    case Code.string_to_quoted(source, file: file) do
      {:ok, ast} ->
        state =
          walk(ast, %{file: file, module: [], describe: [], pending: [], tests: [], problems: []})

        {Enum.reverse(state.tests), Enum.reverse(state.problems)}

      {:error, {meta, message, token}} ->
        {[], [%{file: file, line: line(meta), message: "cannot parse: #{message}#{token}"}]}
    end
  end

  @doc """
  Checks every reference in `tests` against the RFC library.
  """
  @spec validate([tagged_test()], RFC.library()) :: [problem()]
  def validate(tests, library) do
    for test <- tests, ref <- test.refs, {:error, message} <- [RFC.validate(ref, library)] do
      %{file: test.file, line: test.line, message: "#{inspect(test.name)}: #{message}"}
    end
  end

  defp walk({:__block__, _, exprs}, state), do: Enum.reduce(exprs, state, &walk/2)

  defp walk({:defmodule, _, [_name, [do: body]]}, state) do
    inner = walk(body, %{state | module: [], describe: [], pending: []})
    %{inner | module: state.module, describe: state.describe, pending: state.pending}
  end

  defp walk({:describe, _, [_name, [do: body]]}, state) do
    inner = walk(body, %{state | pending: []})
    %{inner | describe: state.describe, pending: []}
  end

  defp walk({:@, meta, [{attr, _, [value]}]}, state)
       when attr in [:tag, :describetag, :moduletag] do
    case rfc_refs(value) do
      :none ->
        state

      {:ok, refs} ->
        key = %{tag: :pending, describetag: :describe, moduletag: :module}[attr]
        Map.update!(state, key, &(&1 ++ refs))

      {:error, message} ->
        problem(state, meta, "@#{attr} #{message}")
    end
  end

  defp walk({:test, meta, [name | _]}, state) do
    state =
      case state.module ++ state.describe ++ state.pending do
        [] ->
          state

        refs ->
          test = %{file: state.file, line: line(meta), name: test_name(name), refs: refs}
          %{state | tests: [test | state.tests]}
      end

    %{state | pending: []}
  end

  defp walk(_other, state), do: state

  defp rfc_refs(value) do
    if Keyword.keyword?(value) and Keyword.has_key?(value, :rfc) do
      case Keyword.fetch!(value, :rfc) do
        ref when is_binary(ref) ->
          {:ok, [ref]}

        refs when is_list(refs) and refs != [] ->
          if Enum.all?(refs, &is_binary/1),
            do: {:ok, refs},
            else: {:error, "rfc: list must contain only literal strings"}

        other ->
          {:error,
           "rfc: must be a literal string or list of strings, got: #{Macro.to_string(other)}"}
      end
    else
      :none
    end
  end

  defp test_name(name) when is_binary(name), do: name
  defp test_name(name), do: Macro.to_string(name)

  defp problem(state, meta, message) do
    %{
      state
      | problems: [%{file: state.file, line: line(meta), message: message} | state.problems]
    }
  end

  defp line(meta) when is_list(meta), do: Keyword.get(meta, :line, 1)
  defp line(_), do: 1
end
