defmodule Mix.Tasks.Lumina.RfcCoverageTest do
  use ExUnit.Case, async: true

  alias Mix.Lumina.RFC
  alias Mix.Tasks.Lumina.RfcCoverage

  @library RFC.load_library("doc/rfc")

  @tests [
    %{file: "test/a_test.exs", line: 10, name: "policy", refs: ["6487#4.8.9"]},
    %{file: "test/a_test.exs", line: 20, name: "intro", refs: ["6487#1", "5781#2"]},
    %{file: "test/b_test.exs", line: 5, name: "rsync uri", refs: ["5781#2"]}
  ]

  test "lists covered sections per RFC, in document order" do
    assert RfcCoverage.report(@tests, @library) == """
           RFC 5781
             §2
                 test/a_test.exs:20  intro
                 test/b_test.exs:5  rsync uri

           RFC 6487
             §1
                 test/a_test.exs:20  intro
             §4.8.9
                 test/a_test.exs:10  policy\
           """
  end

  test "with an RFC, lists every section and marks the uncovered ones" do
    report = RfcCoverage.report(@tests, @library, 5781)

    assert report =~ ~r/\ARFC 5781: 1 of \d+ sections covered\n/
    assert report =~ "  §1  (not covered)\n"
    assert report =~ "  §2\n      test/a_test.exs:20  intro\n      test/b_test.exs:5  rsync uri\n"
  end

  test "says so when no test references an RFC" do
    assert RfcCoverage.report([], @library) == "No tests reference an RFC section."
  end
end
