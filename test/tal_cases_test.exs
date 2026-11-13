defmodule Lumina.TALCasesTest do
  @moduledoc """
  Checks the corpus of hand-written test TALs (#55): every case documents
  why it exists, which RFC sections it covers and its exact expected
  outcome. Together the cases cover every rule the TAL parser reports,
  and the files keep the byte-level properties they test (CRLF line ends,
  trailing whitespace, a missing final newline). The parser itself (#54)
  is tested against these cases.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.TALCases

  @cases elem(TALCases.load_all(), 0)
  defp tal(id), do: Enum.find(@cases, &(&1.id == id)).tal

  test "every case has complete metadata and a case.tal" do
    {cases, problems} = TALCases.load_all()

    assert problems == [],
           "test TAL problems:\n" <> Enum.map_join(problems, "\n", &"  #{&1.file}: #{&1.message}")

    assert length(cases) >= 25
  end

  @tag doc: "A rule with no case would go untested in #54."
  test "every error and warning rule has at least one case" do
    errors = for %{expected: {:invalid, %{rule: rule}}} <- @cases, uniq: true, do: rule

    warnings =
      for %{expected: {:valid, warnings: ws}} <- @cases, %{rule: rule} <- ws, uniq: true, do: rule

    assert Enum.sort(errors) == Enum.sort(TALCases.error_rules())
    assert Enum.sort(warnings) == Enum.sort(TALCases.warning_rules())
    assert Enum.any?(@cases, &(&1.expected == :valid))
  end

  @tag rfc: "8630#2.2",
       doc:
         "An editor or a git setting could silently normalize these bytes; the cases would then test nothing."
  test "the byte-level properties the cases rely on are intact" do
    crlf = tal("valid-crlf")
    assert String.contains?(crlf, "\r\n")
    refute String.contains?(String.replace(crlf, "\r\n", ""), "\n")

    refute String.ends_with?(tal("valid-no-final-newline"), "\n")
    assert tal("warning-trailing-whitespace") =~ ~r/[ \t]\n/
    assert tal("invalid-empty") == ""
    refute String.valid?(tal("invalid-utf8-comment"))
    assert String.contains?(tal("invalid-comment-control-character"), <<7>>)
    assert tal("invalid-rfc-8630-example-as-printed") =~ ~r/\A {9}#/
  end

  @tag rfc: "8630#2.4"
  test "the two RFC 8630 example cases differ only in indentation" do
    dedented =
      tal("invalid-rfc-8630-example-as-printed")
      |> String.split("\n")
      |> Enum.map_join("\n", &String.trim_leading/1)

    assert dedented == tal("valid-rfc-8630-example")
  end
end
