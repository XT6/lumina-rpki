defmodule Mix.Lumina.RFCTest do
  use ExUnit.Case, async: true
  doctest Mix.Lumina.RFC

  alias Mix.Lumina.RFC

  @library RFC.load_library("doc/rfc")

  describe "parse/1" do
    test "accepts numbered sections, appendices and appendix subsections" do
      assert RFC.parse("6487#4.8.9") == {:ok, %{rfc: 6487, section: "4.8.9"}}
      assert RFC.parse("8897#4") == {:ok, %{rfc: 8897, section: "4"}}
      assert RFC.parse("3779#B") == {:ok, %{rfc: 3779, section: "B"}}
      assert RFC.parse("5280#A.1") == {:ok, %{rfc: 5280, section: "A.1"}}
    end

    test "rejects malformed references" do
      for bad <- [
            "6487",
            "6487#",
            "#4.8.9",
            "rfc6487#4",
            "RFC6487#4",
            "6487#4.",
            "6487#4..1",
            "6487#.4",
            "6487#a.1",
            "06487#4",
            "6487 #4",
            "6487#4 ",
            "6487#§4",
            ""
          ] do
        assert {:error, message} = RFC.parse(bad), "expected #{inspect(bad)} to be rejected"
        assert message =~ "malformed RFC reference"
      end
    end

    test "rejects values that are not strings" do
      assert {:error, "RFC reference must be a string" <> _} = RFC.parse(6487)
      assert {:error, _} = RFC.parse(:"6487#4")
    end
  end

  describe "load_library/1" do
    test "loads every RFC in doc/rfc" do
      files = Path.wildcard("doc/rfc/rfc*.txt")
      assert map_size(@library) == length(files)
      assert Map.has_key?(@library, 6487)
      assert Map.has_key?(@library, 8897)
    end

    test "finds numbered sections, appendices and appendix subsections" do
      assert "4.8.9" in @library[6487]
      assert "A" in @library[6487]
      assert "B" in @library[3779]
      assert "A.1" in @library[5280]
      assert "D.1" in @library[3986]
      assert "2" in @library[5781]
    end

    test "every RFC in the library has a section 1" do
      for {rfc, sections} <- @library do
        assert "1" in sections, "RFC #{rfc}: no section 1 found"
      end
    end
  end

  describe "validate/2" do
    test "accepts a reference to an existing section" do
      assert RFC.validate("6487#4.8.9", @library) == {:ok, %{rfc: 6487, section: "4.8.9"}}
    end

    test "rejects an RFC that is not in the library" do
      assert {:error, message} = RFC.validate("9999#1", @library)
      assert message =~ "RFC 9999 is not in the RFC library"
    end

    test "rejects a section that does not exist" do
      assert {:error, message} = RFC.validate("6487#4.8.99", @library)
      assert message =~ "RFC 6487 has no section 4.8.99"
    end

    test "passes on parse errors" do
      assert {:error, message} = RFC.validate("6487", @library)
      assert message =~ "malformed RFC reference"
    end
  end
end
