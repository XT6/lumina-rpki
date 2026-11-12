defmodule Mix.Lumina.TestScanner do
  @moduledoc """
  Reads test source files and collects every test module and test, with the
  documentation and RFC references attached to them. Nothing is compiled or
  run.

  Each test module documents what it covers with `@moduledoc`. Each test
  states the behaviour it checks in its name, and can add detail with
  `@tag doc: "..."`. Tests reference RFC sections through the `:rfc` tag,
  set with `@tag`, `@describetag` or `@moduletag`:

      defmodule Lumina.Example.CertificateTest do
        @moduledoc "Certificate policy checks."
        use ExUnit.Case
        @moduletag rfc: "6487#4"

        describe "certificate policies" do
          @describetag rfc: "6487#4.8.9"

          @tag rfc: ["7318#2", "6487#4.8.9"], doc: "Regression for a past bug."
          test "accepts a policy qualifier" do
            ...
          end
        end
      end

  A test's references are its own plus those of its `describe` block and
  module. See `doc/testing.md`.
  """

  alias Mix.Lumina.RFC

  @type test_case :: %{
          file: Path.t(),
          line: pos_integer(),
          module: String.t(),
          describe: String.t() | nil,
          name: String.t(),
          full_name: String.t(),
          refs: [String.t()],
          doc: String.t() | nil
        }
  @type test_module :: %{
          file: Path.t(),
          line: pos_integer(),
          name: String.t(),
          moduledoc: String.t() | false | nil,
          exunit?: boolean(),
          tests: [test_case()]
        }
  @type problem :: %{file: Path.t(), line: pos_integer(), message: String.t()}

  @doc """
  Scans the test files under `dir` (`**/*_test.exs`).
  """
  @spec scan_dir(Path.t()) :: {[test_module()], [problem()]}
  def scan_dir(dir) do
    dir
    |> Path.join("**/*_test.exs")
    |> Path.wildcard()
    |> Enum.sort()
    |> Enum.map(&scan_file(File.read!(&1), &1))
    |> Enum.reduce({[], []}, fn {modules, problems}, {all_modules, all_problems} ->
      {all_modules ++ modules, all_problems ++ problems}
    end)
  end

  @doc """
  Scans the source of one test file. `file` is only used in the results.
  """
  @spec scan_file(String.t(), Path.t()) :: {[test_module()], [problem()]}
  def scan_file(source, file) do
    case Code.string_to_quoted(source, file: file) do
      {:ok, ast} ->
        state = walk(ast, %{file: file, scope: nil, modules: [], problems: []})
        {Enum.reverse(state.modules), Enum.reverse(state.problems)}

      {:error, {meta, message, token}} ->
        {[], [%{file: file, line: line(meta), message: "cannot parse: #{message}#{token}"}]}
    end
  end

  @doc "All tests of `modules`, in source order."
  @spec tests([test_module()]) :: [test_case()]
  def tests(modules), do: Enum.flat_map(modules, & &1.tests)

  @doc """
  Checks every RFC reference in `tests` against the RFC library.
  """
  @spec validate_refs([test_case()], RFC.library()) :: [problem()]
  def validate_refs(tests, library) do
    for test <- tests, ref <- test.refs, {:error, message} <- [RFC.validate(ref, library)] do
      %{file: test.file, line: test.line, message: "#{inspect(test.name)}: #{message}"}
    end
  end

  @doc """
  Checks that every ExUnit test module has a `@moduledoc` and every test a
  non-blank name.
  """
  @spec check_docs([test_module()]) :: [problem()]
  def check_docs(modules) do
    for module <- modules, module.exunit?, message <- doc_problems(module) do
      message
    end
  end

  defp doc_problems(module) do
    moduledoc =
      case module.moduledoc do
        doc when is_binary(doc) ->
          if String.trim(doc) == "", do: ["@moduledoc is blank"], else: []

        false ->
          ["@moduledoc false: test modules must say what they cover and why"]

        nil ->
          ["missing @moduledoc: say what this module covers and why"]
      end

    names =
      for test <- module.tests, String.trim(test.name) == "" do
        %{file: test.file, line: test.line, message: "#{module.name}: test name is blank"}
      end

    Enum.map(
      moduledoc,
      &%{file: module.file, line: module.line, message: "#{module.name}: #{&1}"}
    ) ++
      names
  end

  # The scope is the module being walked: its name, the tags in force and the
  # tests found so far.

  defp walk({:__block__, _, exprs}, state), do: Enum.reduce(exprs, state, &walk/2)

  defp walk({:defmodule, meta, [alias_ast, [do: body]]}, state) do
    name = module_name(alias_ast, state.scope)

    scope = %{
      name: name,
      line: line(meta),
      moduledoc: nil,
      exunit?: false,
      module_refs: [],
      describe: nil,
      describe_refs: [],
      pending: %{refs: [], doc: nil},
      tests: []
    }

    inner = walk(body, %{state | scope: scope})
    done = inner.scope

    module = %{
      file: state.file,
      line: done.line,
      name: name,
      moduledoc: done.moduledoc,
      exunit?: done.exunit?,
      tests: Enum.reverse(done.tests)
    }

    %{inner | scope: state.scope, modules: [module | inner.modules]}
  end

  defp walk(_ast, %{scope: nil} = state), do: state

  defp walk({:use, _, [{:__aliases__, _, [:ExUnit, :Case]} | _]}, state),
    do: update_scope(state, &%{&1 | exunit?: true})

  defp walk({:@, meta, [{:moduledoc, _, [value]}]}, state) do
    case moduledoc(value) do
      {:ok, doc} -> update_scope(state, &%{&1 | moduledoc: doc})
      :error -> problem(state, meta, "@moduledoc must be a literal string or false")
    end
  end

  defp walk({:describe, _, [name, [do: body]]}, state) do
    outer = state.scope
    inner = walk(body, %{state | scope: %{outer | describe: text(name), describe_refs: []}})
    restored = %{inner.scope | describe: nil, describe_refs: [], pending: %{refs: [], doc: nil}}
    %{inner | scope: restored}
  end

  defp walk({:@, meta, [{attr, _, [value]}]}, state)
       when attr in [:tag, :describetag, :moduletag] do
    case tags(value, attr) do
      {:ok, refs, doc} ->
        update_scope(state, fn scope ->
          case attr do
            :tag ->
              %{
                scope
                | pending: %{refs: scope.pending.refs ++ refs, doc: doc || scope.pending.doc}
              }

            :describetag ->
              %{scope | describe_refs: scope.describe_refs ++ refs}

            :moduletag ->
              %{scope | module_refs: scope.module_refs ++ refs}
          end
        end)

      {:error, message} ->
        problem(state, meta, "@#{attr} #{message}")
    end
  end

  defp walk({:test, meta, [name | _]}, state) do
    update_scope(state, fn scope ->
      name = text(name)

      test = %{
        file: state.file,
        line: line(meta),
        module: scope.name,
        describe: scope.describe,
        name: name,
        full_name: Enum.join(["test", scope.describe, name] |> Enum.reject(&is_nil/1), " "),
        refs: scope.module_refs ++ scope.describe_refs ++ scope.pending.refs,
        doc: scope.pending.doc
      }

      %{scope | tests: [test | scope.tests], pending: %{refs: [], doc: nil}}
    end)
  end

  defp walk(_other, state), do: state

  defp update_scope(state, fun), do: %{state | scope: fun.(state.scope)}

  defp module_name({:__aliases__, _, parts}, parent) do
    name = Enum.map_join(parts, ".", &to_string/1)
    if parent, do: "#{parent.name}.#{name}", else: name
  end

  defp module_name(other, _parent), do: Macro.to_string(other)

  defp moduledoc(false), do: {:ok, false}
  defp moduledoc(doc) when is_binary(doc), do: {:ok, doc}

  defp moduledoc({sigil, _, [{:<<>>, _, [doc]}, []]})
       when sigil in [:sigil_S, :sigil_s] and is_binary(doc),
       do: {:ok, doc}

  defp moduledoc(_), do: :error

  # Reads :rfc and :doc from a tag value. Other tags are ignored.
  defp tags(value, attr) do
    if Keyword.keyword?(value) do
      with {:ok, refs} <- rfc_refs(Keyword.get(value, :rfc)),
           {:ok, doc} <- doc_tag(Keyword.fetch(value, :doc), attr) do
        {:ok, refs, doc}
      end
    else
      {:ok, [], nil}
    end
  end

  defp rfc_refs(nil), do: {:ok, []}
  defp rfc_refs(ref) when is_binary(ref), do: {:ok, [ref]}

  defp rfc_refs(refs) when is_list(refs) and refs != [] do
    if Enum.all?(refs, &is_binary/1),
      do: {:ok, refs},
      else: {:error, "rfc: list must contain only literal strings"}
  end

  defp rfc_refs(other),
    do:
      {:error, "rfc: must be a literal string or list of strings, got: #{Macro.to_string(other)}"}

  defp doc_tag(:error, _attr), do: {:ok, nil}

  defp doc_tag({:ok, doc}, :tag) when is_binary(doc) do
    if String.trim(doc) == "", do: {:error, "doc: must not be blank"}, else: {:ok, doc}
  end

  defp doc_tag({:ok, _doc}, :tag), do: {:error, "doc: must be a literal string"}
  defp doc_tag({:ok, _doc}, _attr), do: {:error, "doc: is only supported on @tag (one test)"}

  defp text(name) when is_binary(name), do: name
  defp text(name), do: Macro.to_string(name)

  defp problem(state, meta, message) do
    %{
      state
      | problems: [%{file: state.file, line: line(meta), message: message} | state.problems]
    }
  end

  defp line(meta) when is_list(meta), do: Keyword.get(meta, :line, 1)
  defp line(_), do: 1
end
