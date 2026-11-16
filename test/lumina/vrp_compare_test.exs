defmodule Lumina.VRPCompareTest do
  @moduledoc """
  Tests comparing Lumina's VRPs with a reference CSV (#168, D-035):
  `Lumina.VRPCompare` and `mix lumina.compare_vrps`.

  The reference is Routinator's published CSV, in the columns `lumina
  vrps` writes (D-032). Both sides are compared per trust anchor as sets
  of VRPs, Lumina's trust anchor names mapped to the reference's; lines
  that aren't VRPs are reported, not fatal. Small CSVs written here cover
  the cases; the `:network` test downloads the live file.
  """
  # Not async: the mix task test swaps the global Mix shell.
  use ExUnit.Case, async: false

  alias Lumina.VRPCompare

  doctest Lumina.VRPCompare

  @header "ASN,IP Prefix,Max Length,Trust Anchor\n"

  defp parse!(rows), do: elem(VRPCompare.parse(@header <> Enum.join(rows, "\n") <> "\n"), 1)

  defp compare(lumina, reference), do: VRPCompare.compare(parse!(lumina), parse!(reference))

  describe "compare/2" do
    test "identical CSVs have no differences" do
      rows = ["AS1,10.0.0.0/8,8,lacnic", "AS2,2001:db8::/32,48,lacnic"]

      assert compare(rows, rows) == [
               %{ta: "lacnic", lumina: 2, reference: 2, only_lumina: [], only_reference: []}
             ]
    end

    test "a VRP only one side has is listed under that side" do
      assert [%{lumina: 2, reference: 2, only_lumina: [ours], only_reference: [theirs]}] =
               compare(
                 ["AS1,10.0.0.0/8,8,lacnic", "AS2,10.1.0.0/16,24,lacnic"],
                 ["AS1,10.0.0.0/8,8,lacnic", "AS2,10.1.0.0/16,16,lacnic"]
               )

      assert VRPCompare.format(ours) == "AS2,10.1.0.0/16,24"
      assert VRPCompare.format(theirs) == "AS2,10.1.0.0/16,16"
    end

    @tag doc: "Lumina validated only LACNIC; the reference has every trust anchor."
    test "a trust anchor only one side has is reported as missing from the other" do
      assert [
               %{ta: "apnic", lumina: nil, reference: 1},
               %{ta: "lacnic", lumina: 1, reference: 1, only_lumina: [], only_reference: []}
             ] =
               compare(
                 ["AS1,10.0.0.0/8,8,lacnic"],
                 ["AS3,1.0.0.0/24,24,apnic", "AS1,10.0.0.0/8,8,lacnic"]
               )

      assert VRPCompare.report(compare(["AS1,10.0.0.0/8,8,lacnic"], []), 10) ==
               "lacnic: not in the reference (Lumina: 1 VRPs)\n"
    end

    @tag doc: "Lumina names trust anchors after its TAL files (D-032)."
    test "Lumina's trust anchor names are mapped to the reference's" do
      assert [
               %{ta: "apnic", only_lumina: [], only_reference: []},
               %{ta: "ripe", only_lumina: [], only_reference: []}
             ] =
               compare(
                 ["AS1,1.0.0.0/24,24,apnic-rfc7730-https", "AS2,2.0.0.0/16,16,ripe-ncc"],
                 ["AS1,1.0.0.0/24,24,apnic", "AS2,2.0.0.0/16,16,ripe"]
               )
    end

    @tag doc:
           "2001:DB8:0:0::/32 and 2001:db8::/32 are the same prefix; a repeated row counts once."
    test "VRPs are compared by value, not by text, and duplicates count once" do
      assert [%{lumina: 1, reference: 1, only_lumina: [], only_reference: []}] =
               compare(
                 ["AS1,2001:DB8:0:0::/32,48,lacnic", "AS1,2001:db8::/32,48,lacnic"],
                 ["AS1,2001:db8::/32,48,lacnic"]
               )
    end
  end

  describe "parse/1" do
    test "a malformed line is reported with its number and skipped" do
      {:ok, parsed} =
        VRPCompare.parse(
          @header <>
            "AS1,10.0.0.0/8,8,lacnic\n" <>
            "AS1,10.0.0.0/8,lacnic\n" <>
            "ASX,10.0.0.0/8,8,lacnic\n" <>
            "AS1,10.0.0.0/33,33,lacnic\n" <>
            "AS1,10.0.0.0/16,8,lacnic\n"
        )

      assert parsed.vrps == %{"lacnic" => MapSet.new([{1, :ipv4, 0x0A000000, 8, 8}])}

      assert parsed.malformed == [
               {3, "AS1,10.0.0.0/8,lacnic", "expected 4 fields (5 with a URI)"},
               {4, "ASX,10.0.0.0/8,8,lacnic", "ASX is not an AS number"},
               {5, "AS1,10.0.0.0/33,33,lacnic", "10.0.0.0/33 is not a prefix"},
               {6, "AS1,10.0.0.0/16,8,lacnic", "8 is not a maxLength from 16 to 32"}
             ]
    end

    test "a CSV without the header is an error" do
      assert {:error, "line 1 is not the header ASN,IP Prefix,Max Length,Trust Anchor"} =
               VRPCompare.parse("AS1,10.0.0.0/8,8,lacnic\n")
    end

    @tag doc: "Lumina.VRP quotes a field holding a comma or quote; --wide adds a URI column."
    test "quoted fields and lumina vrps --wide output are read" do
      {:ok, parsed} =
        VRPCompare.parse(
          "ASN,IP Prefix,Max Length,Trust Anchor,URI\r\n" <>
            ~s(AS1,10.0.0.0/8,8,"my ""ta"", 2","rsync://h/m/a,b.roa"\r\n)
        )

      assert parsed == %{
               vrps: %{~s(my "ta", 2) => MapSet.new([{1, :ipv4, 0x0A000000, 8, 8}])},
               malformed: []
             }
    end
  end

  describe "report/2" do
    test "lists at most limit VRPs per side, and how many more" do
      ours = for i <- 1..4, do: "AS#{i},10.0.0.0/8,8,lacnic"

      assert VRPCompare.report(compare(ours, ["AS1,10.0.0.0/8,8,lacnic"]), 2) == """
             lacnic: Lumina 4, reference 1, only in Lumina 3, only in the reference 0
               only in Lumina:
                 AS2,10.0.0.0/8,8
                 AS3,10.0.0.0/8,8
                 ... and 1 more
             """
    end
  end

  describe "mix lumina.compare_vrps" do
    @describetag :tmp_dir

    test "compares two files and reports both sides' malformed lines", %{tmp_dir: tmp} do
      lumina = Path.join(tmp, "lumina.csv")
      reference = Path.join(tmp, "reference.csv")
      File.write!(lumina, @header <> "AS1,10.0.0.0/8,8,lacnic\nAS2,10.0.0.0/8,8,lacnic\n")
      File.write!(reference, @header <> "AS1,10.0.0.0/8,8,lacnic\nbad\n")
      Mix.shell(Mix.Shell.Process)

      try do
        Mix.Tasks.Lumina.CompareVrps.run(["--csv", reference, lumina])
      after
        Mix.shell(Mix.Shell.IO)
      end

      assert_received {:mix_shell, :info, [report]}

      assert report ==
               "lacnic: Lumina 2, reference 1, only in Lumina 1, only in the reference 0\n" <>
                 "  only in Lumina:\n    AS2,10.0.0.0/8,8\n"

      assert_received {:mix_shell, :error, [summary]}
      assert summary == "#{reference}: 1 lines skipped, not VRPs:"
      assert_received {:mix_shell, :error, ["  line 3: expected 4 fields (5 with a URI): bad"]}
    end
  end

  @tag :network
  @tag timeout: :timer.minutes(5),
       doc: "Downloads Routinator's CSV; about 34 MB and over a million VRPs (2026-11-15)."
  test "the live reference CSV downloads and parses, with every RIR's trust anchor" do
    assert {:ok, text} = VRPCompare.fetch()
    assert String.starts_with?(text, @header)
    assert {:ok, parsed} = VRPCompare.parse(text)
    assert parsed.malformed == []
    assert parsed.vrps |> Map.values() |> Enum.map(&MapSet.size/1) |> Enum.sum() > 900_000
    assert ~w(afrinic apnic arin lacnic ripe) -- Map.keys(parsed.vrps) == []
  end
end
