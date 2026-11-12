defmodule Lumina.RFCReferencesTest do
  # Every :rfc tag in the test suite must point to an RFC and section that
  # exist in doc/rfc. See doc/testing.md.
  use ExUnit.Case, async: true

  alias Mix.Lumina.{RFC, RFCTags}

  test "every RFC reference in the test suite is valid" do
    {tests, problems} = RFCTags.scan_dir("test")
    problems = problems ++ RFCTags.validate(tests, RFC.load_library("doc/rfc"))

    assert problems == [],
           "invalid RFC references:\n" <>
             Enum.map_join(problems, "\n", &"  #{&1.file}:#{&1.line}: #{&1.message}")
  end
end
