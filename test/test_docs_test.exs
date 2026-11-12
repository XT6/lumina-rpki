defmodule Lumina.TestDocsTest do
  @moduledoc """
  Enforces the rule that every unit test is documented (doc/testing.md):
  every test module has a @moduledoc and every test a non-blank name. It
  also checks that the static scanner behind the test catalog sees exactly
  the tests ExUnit runs, so the catalog can't silently miss one.
  """
  # async: false so this runs after ExUnit has loaded every test module.
  use ExUnit.Case, async: false

  alias Mix.Lumina.TestScanner

  @scanned TestScanner.scan_dir("test")

  test "every test module has a @moduledoc and every test a name" do
    {modules, problems} = @scanned
    problems = problems ++ TestScanner.check_docs(modules)

    assert problems == [],
           "undocumented tests:\n" <>
             Enum.map_join(problems, "\n", &"  #{&1.file}:#{&1.line}: #{&1.message}")
  end

  @tag doc: """
       When run with the whole suite, this covers every test module. When a
       single file is run, it covers the modules ExUnit loaded for that run.
       Doctests are excluded: they are documented by the function docs they
       come from.
       """
  test "the scanner finds exactly the tests ExUnit runs, in every loaded test module" do
    {modules, _problems} = @scanned
    scanned = Map.new(modules, &{&1.name, Enum.map(&1.tests, fn test -> test.full_name end)})

    mismatches =
      for {module, _} <- :code.all_loaded(),
          function_exported?(module, :__ex_unit__, 0),
          name = inspect(module),
          ran = exunit_tests(module),
          found = Map.get(scanned, name, []),
          Enum.sort(ran) != Enum.sort(found) do
        "  #{name}\n    only in ExUnit: #{inspect(ran -- found)}\n    only in scanner: #{inspect(found -- ran)}"
      end

    assert mismatches == [],
           "the test catalog would not match the tests ExUnit runs. Tests generated in loops or " <>
             "with interpolated names can't be read from source; use one test with a loop inside.\n" <>
             Enum.join(mismatches, "\n")
  end

  defp exunit_tests(module) do
    module.__ex_unit__().tests
    |> Enum.reject(&Map.has_key?(&1.tags, :doctest))
    |> Enum.map(&Atom.to_string(&1.name))
  end
end
