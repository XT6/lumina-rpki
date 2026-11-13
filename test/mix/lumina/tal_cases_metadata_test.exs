defmodule Mix.Lumina.TALCasesMetadataTest do
  @moduledoc """
  Tests the metadata check for test TAL cases (Mix.Lumina.TALCases): every
  way a case can be incomplete or wrong must be reported, so the corpus
  stays documented and its expected outcomes stay meaningful. Cases are
  built in temporary directories.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.{RFC, TALCases}

  @moduletag :tmp_dir
  @library RFC.load_library("doc/rfc")

  defp make_case(tmp_dir, meta, opts \\ []) do
    id = Keyword.get(opts, :id, "sample-case")
    dir = Path.join(tmp_dir, id)
    File.mkdir_p!(dir)
    if meta, do: File.write!(Path.join(dir, "case.exs"), meta)

    if Keyword.get(opts, :tal, true),
      do: File.write!(Path.join(dir, "case.tal"), "rsync://x/ta.cer\n\nAAAA\n")

    dir
  end

  defp meta(expected, extra \\ "") do
    ~s(%{id: "sample-case", title: "Sample", rationale: "Why.", rfc: ["8630#2.2"], expected: #{expected}#{extra}}\n)
  end

  defp messages(dir) do
    {:error, problems} = TALCases.load(dir, @library)
    Enum.map(problems, & &1.message)
  end

  test "a complete case loads, with its TAL bytes", %{tmp_dir: tmp_dir} do
    assert {:ok, %{id: "sample-case", tal: "rsync://x/ta.cer\n\nAAAA\n"}} =
             TALCases.load(make_case(tmp_dir, meta(":valid")), @library)
  end

  test "all three forms of expected outcome are accepted", %{tmp_dir: tmp_dir} do
    for expected <- [
          ":valid",
          "{:valid, warnings: [%{line: 1, rule: :trailing_whitespace}]}",
          "{:invalid, %{line: 3, rule: :empty_key}}"
        ] do
      dir = make_case(tmp_dir, meta(expected))
      assert {:ok, _} = TALCases.load(dir, @library), expected
      File.rm_rf!(dir)
    end
  end

  test "missing keys, an unknown key and a mismatched id are reported", %{tmp_dir: tmp_dir} do
    assert "missing required key :rationale" in messages(
             make_case(
               tmp_dir,
               ~s(%{id: "sample-case", title: "T", rfc: ["8630#2.2"], expected: :valid}\n)
             )
           )

    File.rm_rf!(Path.join(tmp_dir, "sample-case"))

    assert ["unknown key :owner"] = messages(make_case(tmp_dir, meta(":valid", ", owner: \"x\"")))
    File.rm_rf!(Path.join(tmp_dir, "sample-case"))

    assert [message] = messages(make_case(tmp_dir, meta(":valid"), id: "other-name"))
    assert message =~ "must match the folder name"
  end

  test "an unknown rule, a bad line number and a malformed expectation are reported", %{
    tmp_dir: tmp_dir
  } do
    for {expected, fragment} <- [
          {"{:invalid, %{line: 1, rule: :made_up}}", "unknown error rule :made_up"},
          {"{:invalid, %{line: 0, rule: :empty}}", "line must be a positive integer"},
          {"{:valid, warnings: [%{line: 1, rule: :empty}]}", "unknown warning rule :empty"},
          {":invalid", "expected must be"}
        ] do
      dir = make_case(tmp_dir, meta(expected))
      assert Enum.any?(messages(dir), &(&1 =~ fragment)), "#{expected} should report #{fragment}"
      File.rm_rf!(dir)
    end
  end

  test "an invalid RFC reference and a missing case.tal are reported", %{tmp_dir: tmp_dir} do
    assert ["rfc: \"8630#9.9\": RFC 8630 has no section 9.9"] =
             messages(make_case(tmp_dir, String.replace(meta(":valid"), "8630#2.2", "8630#9.9")))

    File.rm_rf!(Path.join(tmp_dir, "sample-case"))
    assert ["missing case.tal"] = messages(make_case(tmp_dir, meta(":valid"), tal: false))
  end
end
