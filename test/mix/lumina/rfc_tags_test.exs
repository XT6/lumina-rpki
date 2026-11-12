defmodule Mix.Lumina.RFCTagsTest do
  use ExUnit.Case, async: true

  alias Mix.Lumina.{RFC, RFCTags}

  @library RFC.load_library("doc/rfc")

  defp scan(source), do: RFCTags.scan_file(source, "sample_test.exs")

  test "collects @tag, @describetag and @moduletag references" do
    {tests, []} =
      scan("""
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
             %{name: "all three levels", refs: ["6487#4", "6487#4.8.9", "7318#2", "6487#4.8.10"]},
             %{name: "describe and module tags", refs: ["6487#4", "6487#4.8.9"]},
             %{name: "unrelated tags are ignored", refs: ["6487#4"]}
           ] = tests
  end

  test "@tag applies only to the next test" do
    {tests, []} =
      scan("""
      defmodule SampleTest do
        use ExUnit.Case

        @tag rfc: "9582#4"
        test "tagged" do
        end

        test "untagged" do
        end
      end
      """)

    assert [%{name: "tagged", refs: ["9582#4"]}] = tests
  end

  test "@describetag does not leak out of its describe block" do
    {tests, []} =
      scan("""
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

    assert [%{name: "inside"}] = tests
  end

  test "reports tags whose value is not a literal string or list of strings" do
    {[], problems} =
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
           ] =
             problems
  end

  test "reports files that cannot be parsed" do
    assert {[], [%{message: "cannot parse: " <> _}]} = scan("defmodule Broken do")
  end

  describe "validate/2" do
    test "returns one problem per invalid reference, naming the test" do
      tests = [
        %{file: "a_test.exs", line: 3, name: "good", refs: ["6487#4.8.9"]},
        %{file: "a_test.exs", line: 7, name: "bad", refs: ["9999#1", "6487#4.8.99", "6487"]}
      ]

      assert [
               %{line: 7, message: ~s("bad": "9999#1": RFC 9999 is not in) <> _},
               %{line: 7, message: ~s("bad": "6487#4.8.99": RFC 6487 has no section) <> _},
               %{line: 7, message: ~s("bad": malformed RFC reference) <> _}
             ] = RFCTags.validate(tests, @library)
    end
  end
end
