defmodule Mix.Lumina.ASN1.PatchTest do
  @moduledoc """
  Tests the ASN.1 patch applier and the allowed-change check. Patches exist
  only to get the RFC modules past OTP's asn1ct, so the check must refuse
  any patch that could change how a type encodes, such as deleting a field
  or adding a constraint, and the applier must refuse to patch text that
  doesn't match exactly.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.ASN1.Patch

  @original """
  Foo DEFINITIONS ::= BEGIN
  IMPORTS
    CONTENT-TYPE
    FROM CryptographicMessageSyntax-2010
      { iso(1) 2 3 } ;
  Manifest ::= SEQUENCE {
    version [0] INTEGER DEFAULT 0,
    fileList SEQUENCE SIZE (0..MAX) OF FileAndHash }
  END
  """

  defp hunks!(diff) do
    {:ok, hunks} = Patch.parse(diff)
    hunks
  end

  @content_type_patch """
  --- a/Foo.asn1
  +++ b/Foo.asn1
  @@ -2,4 +2,1 @@
  -IMPORTS
  -  CONTENT-TYPE
  -  FROM CryptographicMessageSyntax-2010
  -    { iso(1) 2 3 } ;
  +-- LUMINA PATCH (content-type): removed the import.
  """

  describe "parse/1" do
    test "reads hunks with their start line and operations" do
      assert {:ok, [%{old_start: 2, lines: [{:remove, "IMPORTS"} | _] = lines}]} =
               Patch.parse(@content_type_patch)

      assert List.last(lines) == {:add, "-- LUMINA PATCH (content-type): removed the import."}
    end

    test "rejects a malformed hunk header, text before the first hunk and an empty patch" do
      assert {:error, "malformed hunk header" <> _} = Patch.parse("@@ -x +1 @@\n")
      assert {:error, "content before the first hunk header"} = Patch.parse(" stray\n")
      assert {:error, "no hunks"} = Patch.parse("--- a/x\n+++ b/x\n")
    end
  end

  describe "apply_hunks/2" do
    test "applies a hunk at exactly the line it names" do
      assert {:ok, patched} = Patch.apply_hunks(@original, hunks!(@content_type_patch))

      assert patched ==
               String.replace(
                 @original,
                 "IMPORTS\n  CONTENT-TYPE\n  FROM CryptographicMessageSyntax-2010\n    { iso(1) 2 3 } ;\n",
                 "-- LUMINA PATCH (content-type): removed the import.\n"
               )
    end

    @tag doc:
           "Strictness is the point: a patch that drifted must fail, not land on the wrong lines."
    test "refuses a hunk whose text doesn't match at that line, even if it matches elsewhere" do
      shifted = "-- a new first line\n" <> @original

      assert {:error, "hunk at line 2 does not match the original text"} =
               Patch.apply_hunks(shifted, hunks!(@content_type_patch))
    end

    test "applies several hunks in order and refuses overlapping ones" do
      diff = """
      @@ -1,1 +1,1 @@
      -Foo DEFINITIONS ::= BEGIN
      +Bar DEFINITIONS ::= BEGIN
      @@ -9,1 +9,1 @@
      -END
      +END -- of Bar
      """

      assert {:ok, patched} = Patch.apply_hunks(@original, hunks!(diff))
      assert patched =~ ~r/\ABar DEFINITIONS/
      assert patched =~ "END -- of Bar\n"

      overlapping =
        "@@ -2,1 +2,1 @@\n-IMPORTS\n+IMPORTS\n@@ -1,2 +1,2 @@\n Foo DEFINITIONS ::= BEGIN\n IMPORTS\n"

      assert {:error, "hunk at line 1 overlaps" <> _} =
               Patch.apply_hunks(@original, hunks!(overlapping))
    end
  end

  describe "check_allowed/1" do
    test "accepts a patch that only does what its kind allows" do
      assert Patch.check_allowed(hunks!(@content_type_patch)) == []
    end

    test "requires every hunk to state its kind and reason" do
      diff = "@@ -2,1 +2,0 @@\n-IMPORTS\n"
      assert [message] = Patch.check_allowed(hunks!(diff))
      assert message =~ "no `-- LUMINA PATCH (<kind>): <reason>` comment"
    end

    test "rejects unknown and mixed kinds" do
      unknown = "@@ -2,1 +2,1 @@\n-IMPORTS\n+-- LUMINA PATCH (cleanup): tidy.\n"
      assert [message] = Patch.check_allowed(hunks!(unknown))
      assert message =~ ~s(unknown patch kind "cleanup")

      mixed =
        "@@ -2,1 +2,2 @@\n-IMPORTS\n+-- LUMINA PATCH (content-type): a.\n+-- LUMINA PATCH (builtin-type): b.\n"

      assert [message] = Patch.check_allowed(hunks!(mixed))
      assert message =~ "mixes patch kinds builtin-type, content-type"
    end

    @tag rfc: "9286#A",
         doc: "A field deletion disguised as a compatibility patch would change what decodes."
    test "refuses a patch that deletes a field" do
      diff = """
      @@ -7,1 +7,1 @@
      -  version [0] INTEGER DEFAULT 0,
      +-- LUMINA PATCH (content-type): sneaky.
      """

      assert [message] = Patch.check_allowed(hunks!(diff))
      assert message =~ ~s(a content-type patch may not remove "version [0] INTEGER DEFAULT 0,")
    end

    @tag rfc: "9286#A",
         doc: """
         Applying erratum 7118 here (SIZE 1..MAX) was explicitly decided against
         (#37): errata are enforced in validation, never by patching modules.
         """
    test "refuses a patch that changes a constraint" do
      diff = """
      @@ -8,1 +8,2 @@
      -  fileList SEQUENCE SIZE (0..MAX) OF FileAndHash }
      +-- LUMINA PATCH (content-type): apply erratum.
      +  fileList SEQUENCE SIZE (1..MAX) OF FileAndHash }
      """

      assert [removed, added] = Patch.check_allowed(hunks!(diff))
      assert removed =~ "may not remove"
      assert added =~ "may not add"
    end

    test "attribute-certificate patches may only add the opaque placeholders" do
      ok = """
      @@ -2,1 +2,3 @@
      -  AttributeCertificate
      +-- LUMINA PATCH (attribute-certificate): placeholder.
      +AttributeCertificate ::= SEQUENCE OF ANY
      +  ;
      """

      assert Patch.check_allowed(hunks!(ok)) == []

      other =
        "@@ -2,1 +2,2 @@\n-  AttributeCertificate\n+-- LUMINA PATCH (attribute-certificate): x.\n+Foo ::= SEQUENCE OF ANY\n"

      assert [message] = Patch.check_allowed(hunks!(other))
      assert message =~ ~s(may not add "Foo ::= SEQUENCE OF ANY")
    end
  end

  test "every committed patch passes the allowed-change check" do
    for path <- Path.wildcard("asn1/patches/*.patch") do
      assert {:ok, hunks} = Patch.parse(File.read!(path)), path
      assert Patch.check_allowed(hunks) == [], path
    end
  end
end
