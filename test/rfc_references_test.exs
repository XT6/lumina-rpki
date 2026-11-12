defmodule Lumina.RFCReferencesTest do
  @moduledoc """
  Enforces that every :rfc tag in the test suite points to an RFC and
  section that exist in doc/rfc, so the coverage report and the catalog
  never cite text we don't have. See doc/testing.md.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.{RFC, TestScanner}

  test "every RFC reference in the test suite is valid" do
    {modules, problems} = TestScanner.scan_dir("test")

    problems =
      problems ++
        TestScanner.validate_refs(TestScanner.tests(modules), RFC.load_library("doc/rfc"))

    assert problems == [],
           "invalid RFC references:\n" <>
             Enum.map_join(problems, "\n", &"  #{&1.file}:#{&1.line}: #{&1.message}")
  end
end
