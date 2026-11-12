defmodule Mix.Lumina.ASN1Test do
  @moduledoc """
  Tests extraction of ASN.1 modules from RFC text. Every ASN.1 type Lumina
  compiles comes from these files, so extraction must keep the module
  exactly as the RFC defines it and drop only page furniture and
  whitespace. Synthetic RFC text covers the edge cases; the real modules
  are checked too.
  """
  use ExUnit.Case, async: true
  doctest Mix.Lumina.ASN1

  alias Mix.Lumina.ASN1

  @spec_ %{name: "Sample-Module", rfc: 9999, section: "A.1"}

  # A module that spans a page break, ends with a commented END, and is
  # preceded by prose that mentions it in an IMPORTS-like line.
  @rfc_text """
  1.  Introduction

     This document imports from Sample-Module.

  Appendix A.  ASN.1 Modules

  A.1.  The Module

     Sample-Module
       { iso(1) 2 3 }

     DEFINITIONS EXPLICIT TAGS ::=
     BEGIN

     Foo ::= INTEGER



  Author, et al.              Standards Track                    [Page 12]
  \f
  RFC 9999                 Sample Document                  November 2026


     Bar ::= SEQUENCE {
       foo Foo }

     END -- of Sample-Module

  A.2.  Another Module

     Not extracted.
  """

  describe "extract/2" do
    test "returns the module from its header to END, without page furniture" do
      assert {:ok, contents} = ASN1.extract(@spec_, @rfc_text)

      assert contents == """
             -- Sample-Module: extracted from RFC 9999, section A.1,
             -- by `mix lumina.asn1.extract`. Do not edit; regenerate instead.
             -- Only page furniture, extra blank lines and indentation were removed.

             Sample-Module
               { iso(1) 2 3 }

             DEFINITIONS EXPLICIT TAGS ::=
             BEGIN

             Foo ::= INTEGER

             Bar ::= SEQUENCE {
               foo Foo }

             END -- of Sample-Module
             """
    end

    @tag doc:
           "Prose and IMPORTS lines mention module names too; only a header followed by DEFINITIONS counts."
    test "doesn't mistake a mention of the module name for its header" do
      assert {:ok, contents} = ASN1.extract(@spec_, @rfc_text)
      refute contents =~ "This document imports"
    end

    test "fails when the module isn't there" do
      assert {:error, "module Missing not found"} =
               ASN1.extract(%{@spec_ | name: "Missing"}, @rfc_text)
    end

    test "fails when the module has no END line" do
      text = String.replace(@rfc_text, "END -- of Sample-Module", "")
      assert {:error, "module Sample-Module: no END line" <> _} = ASN1.extract(@spec_, text)
    end

    @tag doc: "Catches a wrong entry in the module list, which would cite the wrong RFC section."
    test "fails when the module is not in the section the spec names" do
      assert {:error, message} = ASN1.extract(%{@spec_ | section: "A.2"}, @rfc_text)
      assert message =~ ~s(is in section "A.1" of RFC 9999, not A.2)
    end
  end

  describe "whitespace handling" do
    test "collapses each run of blank lines into one" do
      assert ASN1.collapse_blank_lines(["a", "", "  ", "", "b", "", "c"]) == [
               "a",
               "",
               "b",
               "",
               "c"
             ]
    end

    test "strips the common indentation and trailing whitespace only" do
      assert ASN1.dedent(["   A ::= {  ", "     b }", "", "   END"]) == [
               "A ::= {",
               "  b }",
               "",
               "END"
             ]
    end
  end

  @tag rfc: ["5280#A.1", "5280#A.2", "5652#12.1", "5652#12.2", "3779#A", "9582#4", "9286#A"]
  test "every configured module extracts from its RFC with its header, BEGIN and END" do
    for spec <- ASN1.modules() do
      text = File.read!("doc/rfc/rfc#{spec.rfc}.txt")
      assert {:ok, contents} = ASN1.extract(spec, text), spec.name

      body = contents |> String.split("\n") |> Enum.reject(&String.starts_with?(&1, "--"))

      assert body
             |> Enum.drop_while(&(&1 == ""))
             |> hd()
             |> String.trim_leading()
             |> String.starts_with?(spec.name),
             spec.name

      assert contents =~ ~r/^\s*DEFINITIONS (EXPLICIT|IMPLICIT) TAGS ::=/m
      assert contents =~ ~r/^\s*BEGIN\s*$/m
      assert contents =~ ~r/\n\s*END( -- .*)?\n\z/
      refute contents =~ ~r/\[Page \d+\]|\f|^RFC \d+ /m, "#{spec.name} still has page furniture"
    end
  end
end
