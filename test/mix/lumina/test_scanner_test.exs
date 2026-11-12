defmodule Mix.Lumina.TestScannerTest do
  @moduledoc """
  Tests the static test scanner that drives the RFC reference check, the
  unit-test documentation check and the unit-test section of the catalog.
  Sample test files are given as source strings and parsed, never compiled.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.{RFC, TestScanner}

  @library RFC.load_library("doc/rfc")

  defp scan(source), do: TestScanner.scan_file(source, "sample_test.exs")

  defp tests(source) do
    {modules, []} = scan(source)
    TestScanner.tests(modules)
  end

  describe "RFC references" do
    test "collects @tag, @describetag and @moduletag references, outermost first" do
      tests =
        tests("""
        defmodule SampleTest do
          use ExUnit.Case
          @moduletag rfc: "6487#4"

          test "module tag only" do
          end

          describe "policies" do
            @describetag rfc: "6487#4.8.9"

            @tag rfc: ["7318#2", "6487#4.8.10"]
            test "all three levels" do
            end

            test "describe and module tags" do
            end
          end

          @tag :slow
          test "unrelated tags are ignored" do
          end
        end
        """)

      assert [
               %{name: "module tag only", refs: ["6487#4"], line: 5},
               %{
                 name: "all three levels",
                 refs: ["6487#4", "6487#4.8.9", "7318#2", "6487#4.8.10"]
               },
               %{name: "describe and module tags", refs: ["6487#4", "6487#4.8.9"]},
               %{name: "unrelated tags are ignored", refs: ["6487#4"]}
             ] = tests
    end

    test "@tag applies only to the next test" do
      assert [%{name: "tagged", refs: ["9582#4"]}, %{name: "untagged", refs: []}] =
               tests("""
               defmodule SampleTest do
                 use ExUnit.Case

                 @tag rfc: "9582#4"
                 test "tagged" do
                 end

                 test "untagged" do
                 end
               end
               """)
    end

    test "@describetag does not leak out of its describe block" do
      assert [%{name: "inside", refs: ["9286#4"]}, %{name: "outside", refs: []}] =
               tests("""
               defmodule SampleTest do
                 use ExUnit.Case

                 describe "a" do
                   @describetag rfc: "9286#4"
                   test "inside" do
                   end
                 end

                 test "outside" do
                 end
               end
               """)
    end

    test "reports tags whose value is not a literal string or list of strings" do
      {_modules, problems} =
        scan("""
        defmodule SampleTest do
          use ExUnit.Case
          @ref "6487#4"

          @tag rfc: @ref
          test "attribute" do
          end

          @tag rfc: [6487]
          test "integer" do
          end
        end
        """)

      assert [
               %{line: 5, message: "@tag rfc: must be" <> _},
               %{line: 9, message: "@tag rfc: list" <> _}
             ] = problems
    end

    test "validate_refs/2 returns one problem per invalid reference, naming the test" do
      tests = [
        %{file: "a_test.exs", line: 3, name: "good", refs: ["6487#4.8.9"]},
        %{file: "a_test.exs", line: 7, name: "bad", refs: ["9999#1", "6487#4.8.99", "6487"]}
      ]

      assert [
               %{line: 7, message: ~s("bad": "9999#1": RFC 9999 is not in) <> _},
               %{line: 7, message: ~s("bad": "6487#4.8.99": RFC 6487 has no section) <> _},
               %{line: 7, message: ~s("bad": malformed RFC reference) <> _}
             ] = TestScanner.validate_refs(tests, @library)
    end
  end

  describe "modules and tests" do
    test "collects every test with its module, describe block and ExUnit name" do
      assert [
               %{module: "SampleTest", describe: nil, full_name: "test top level"},
               %{
                 module: "SampleTest",
                 describe: "parse/1",
                 full_name: "test parse/1 rejects junk"
               }
             ] =
               tests("""
               defmodule SampleTest do
                 use ExUnit.Case
                 test "top level" do
                 end

                 describe "parse/1" do
                   test "rejects junk" do
                   end
                 end
               end
               """)
    end

    test "reads @moduledoc from a string, a heredoc, a ~S sigil, or false" do
      for {attr, expected} <- [
            {~s(@moduledoc "Short."), "Short."},
            {~s(@moduledoc """\n  Long.\n  """), "Long.\n"},
            {~s(@moduledoc ~S"""\n  Raw \#{x}.\n  """), "Raw \#{x}.\n"},
            {"@moduledoc false", false}
          ] do
        {[module], []} = scan("defmodule SampleTest do\n  #{attr}\n  use ExUnit.Case\nend\n")
        assert module.moduledoc == expected, attr
      end
    end

    test "records whether a module uses ExUnit.Case" do
      {[test_module, helper], []} =
        scan("""
        defmodule SampleTest do
          use ExUnit.Case, async: true
        end

        defmodule SampleHelper do
        end
        """)

      assert test_module.exunit?
      refute helper.exunit?
    end

    test "names nested modules after their parent" do
      {modules, []} =
        scan("""
        defmodule Outer do
          defmodule Inner do
          end
        end
        """)

      assert Enum.map(modules, & &1.name) == ["Outer.Inner", "Outer"]
    end

    test "@tag doc: is attached to the next test only" do
      assert [%{name: "first", doc: "Why this matters."}, %{name: "second", doc: nil}] =
               tests("""
               defmodule SampleTest do
                 use ExUnit.Case

                 @tag doc: "Why this matters."
                 test "first" do
                 end

                 test "second" do
                 end
               end
               """)
    end

    test "rejects doc: that is blank, not a literal, or not on @tag" do
      {_modules, problems} =
        scan("""
        defmodule SampleTest do
          use ExUnit.Case
          @moduletag doc: "module"

          @tag doc: " "
          test "blank" do
          end

          @tag doc: @why
          test "attribute" do
          end
        end
        """)

      assert Enum.map(problems, & &1.message) == [
               "@moduletag doc: is only supported on @tag (one test)",
               "@tag doc: must not be blank",
               "@tag doc: must be a literal string"
             ]
    end

    test "reports files that cannot be parsed" do
      assert {[], [%{message: "cannot parse: " <> _}]} = scan("defmodule Broken do")
    end
  end

  describe "check_docs/1" do
    defp doc_problems(source) do
      {modules, []} = scan(source)
      modules |> TestScanner.check_docs() |> Enum.map(& &1.message)
    end

    test "passes a documented module" do
      assert doc_problems("""
             defmodule SampleTest do
               @moduledoc "Covers sampling."
               use ExUnit.Case
               test "samples" do
               end
             end
             """) == []
    end

    test "fails a test module without @moduledoc" do
      assert ["SampleTest: missing @moduledoc" <> _] =
               doc_problems("defmodule SampleTest do\n  use ExUnit.Case\nend\n")
    end

    test "fails a test module with @moduledoc false" do
      assert ["SampleTest: @moduledoc false" <> _] =
               doc_problems(
                 "defmodule SampleTest do\n  @moduledoc false\n  use ExUnit.Case\nend\n"
               )
    end

    test "fails a blank @moduledoc" do
      assert ["SampleTest: @moduledoc is blank"] =
               doc_problems(
                 "defmodule SampleTest do\n  @moduledoc \"  \"\n  use ExUnit.Case\nend\n"
               )
    end

    test "fails a blank test name" do
      assert ["SampleTest: test name is blank"] =
               doc_problems("""
               defmodule SampleTest do
                 @moduledoc "Covers sampling."
                 use ExUnit.Case
                 test " " do
                 end
               end
               """)
    end

    test "ignores helper modules that don't use ExUnit.Case" do
      assert doc_problems("defmodule SampleHelper do\nend\n") == []
    end
  end
end
