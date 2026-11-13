defmodule Lumina.ROATest do
  @moduledoc """
  Tests decoding of ROAs (RFC 9582). VRP output (M7) is built from these
  structs, so the AS, prefixes and maxLength must decode exactly, from both
  the RFC's own example (Appendix A, read from the RFC text) and Barry
  objects. The RFC 9582 §4.3 encoding recommendations are reported by
  issues/1, not enforced.
  """
  use ExUnit.Case, async: true
  doctest Lumina.ROA

  alias Lumina.{ROA, SignedObject}
  alias Lumina.Test.Fixture

  defp roa!(fixture_id) do
    fixture = Fixture.load!(fixture_id)
    {:ok, roa} = ROA.decode(File.read!(Path.join(fixture.rsync_root, "ca1/roa1.roa")))
    roa
  end

  defp vrps(roa), do: roa |> ROA.vrps() |> Enum.map(&ROA.format_vrp/1)

  defp rules(roa), do: roa |> ROA.issues() |> Enum.map(& &1.rule)

  # A ROA from a RouteOriginAttestation value, through DER.
  defp build(value) do
    {:ok, der} = Lumina.ASN1.encode(:roa, :RouteOriginAttestation, value)
    {:ok, roa} = ROA.decode_econtent(der)
    roa
  end

  # The complete signed object in RFC 9582 Appendix A, as printed.
  defp appendix_a_object do
    text = File.read!("doc/rfc/rfc9582.txt")
    [_, after_intro] = String.split(text, "Base64 encoded per\n   [RFC4648].\n", parts: 2)
    [base64_block, _] = String.split(after_intro, "The object in this appendix", parts: 2)

    base64_block
    |> String.split("\n")
    |> Mix.Lumina.ASN1.remove_page_furniture()
    |> Enum.map_join(&String.trim/1)
    |> Base.decode64!()
  end

  describe "RFC 9582 Appendix A" do
    @tag rfc: "9582#A"
    test "the example eContent decodes to AS65536 and 2001:db8::/32" do
      {:ok, roa} =
        ROA.decode_econtent(
          Base.decode16!("301802030100003011300F040200023009300703050020010DB8")
        )

      assert %ROA{version: 0, as_id: 65_536, object: nil} = roa
      assert vrps(roa) == ["2001:db8::/32 => AS65536"]
      assert ROA.issues(roa) == []
    end

    @tag rfc: "9582#A",
         doc: """
         The Base64 is read from the RFC text itself; the size and SHA-256 the RFC
         states prove the transcription is exact before anything is decoded.
         """
    test "the complete example object matches its stated size and digest, and decodes" do
      der = appendix_a_object()

      assert byte_size(der) == 1668

      assert Base.encode16(:crypto.hash(:sha256, der), case: :lower) ==
               "3a39e0b652e79ddf6efdd178ad5e3b29e0121b1e593b89f1e0ac18f3ba60d5e7"

      {:ok, roa} = ROA.decode(der)
      assert vrps(roa) == ["2001:db8::/32 => AS65536"]
      assert %SignedObject{} = roa.object

      assert SignedObject.signed_attribute(roa.object, :signing_time).at ==
               ~U[2024-05-01 00:34:13Z]
    end
  end

  describe "Barry ROAs" do
    @tag rfc: ["9582#4.2", "9582#4.3"]
    test "the m0-minimal-valid ROA authorizes AS1234 for its EE certificate's prefixes" do
      roa = roa!("m0-minimal-valid")
      assert vrps(roa) == ["1.1.0.0/16 => AS1234", "101::/16 => AS1234"]
      assert ROA.issues(roa) == []
    end

    @tag rfc: ["9582#4.3.2.1", "9582#4.3.2.2"],
         doc: "An absent maxLength stays nil; the VRP then uses the prefix length."
    test "IPv4 and IPv6 prefixes with and without maxLength" do
      roa = roa!("m1-roa-prefixes")

      assert roa.as_id == 64_496

      assert [
               %{afi: :ipv4, addresses: [%{max_length: 24}, %{max_length: nil}]},
               %{afi: :ipv6, addresses: [%{max_length: 48}]}
             ] =
               roa.families

      assert vrps(roa) == [
               "1.1.0.0/17-24 => AS64496",
               "1.1.128.0/24 => AS64496",
               "101::/16-48 => AS64496"
             ]

      assert Enum.map(ROA.vrps(roa), & &1.max_length) == [24, 24, 48]
      assert ROA.issues(roa) == []
    end

    @tag rfc: "9582#4.1"
    test "a ROA with version 2 decodes with version 2" do
      assert roa!("m1-roa-version-2").version == 2
    end
  end

  describe "issues/1 (reported, not enforced)" do
    defp family(afi, addresses), do: %{addressFamily: afi, addresses: addresses}

    @tag rfc: "9582#4.3.2.2"
    test "maxLength below the prefix length, or equal to it, is reported" do
      too_small =
        build(%{asID: 1, ipAddrBlocks: [family(<<0, 1>>, [%{address: <<10>>, maxLength: 7}])]})

      superfluous =
        build(%{asID: 1, ipAddrBlocks: [family(<<0, 1>>, [%{address: <<10>>, maxLength: 8}])]})

      assert rules(too_small) == [:max_length_out_of_range]
      assert rules(superfluous) == [:superfluous_max_length]
    end

    @tag rfc: ["9582#4", "9582#4.3.2.2"],
         doc: """
         The module bounds maxLength by the family's address width (INTEGER (0..ub),
         ub = 32 or 128 via the information object set), so a maxLength above it
         fails at decode time rather than in issues/1 (F-012).
         """
    test "maxLength above the address width is a decode error" do
      # asID 1, IPv4, 10.0.0.0/8 with maxLength 33 (02 01 21).
      der = Base.decode16!("3016020101301130" <> "0F04020001300930070302000A020121")
      assert Lumina.DER.check(der) == :ok
      assert {:error, {:asn1, _}} = ROA.decode_econtent(der)
    end

    @tag rfc: "9582#4.3.1"
    test "IPv4-mapped IPv6 prefixes and repeated address families" do
      mapped =
        build(%{
          asID: 1,
          ipAddrBlocks: [family(<<0, 2>>, [%{address: <<0::80, 0xFFFF::16, 10>>}])]
        })

      assert rules(mapped) == [:ipv4_mapped]

      twice =
        build(%{
          asID: 1,
          ipAddrBlocks: [
            family(<<0, 1>>, [%{address: <<10>>}]),
            family(<<0, 1>>, [%{address: <<11>>}])
          ]
        })

      assert :duplicate_family in rules(twice)
    end

    @tag rfc: ["9582#4.3.3", "9582#4.3.3.1"]
    test "elements out of canonical order, and duplicates" do
      unsorted =
        build(%{
          asID: 1,
          ipAddrBlocks: [family(<<0, 1>>, [%{address: <<11>>}, %{address: <<10>>}])]
        })

      assert rules(unsorted) == [:not_canonical_order]

      # Same prefix, shorter maxLength first: sorted by mlen, so canonical.
      by_mlen =
        build(%{
          asID: 1,
          ipAddrBlocks: [
            family(<<0, 1>>, [
              %{address: <<10>>, maxLength: 16},
              %{address: <<10>>, maxLength: 24}
            ])
          ]
        })

      assert rules(by_mlen) == []

      dup =
        build(%{
          asID: 1,
          ipAddrBlocks: [family(<<0, 1>>, [%{address: <<10>>}, %{address: <<10>>}])]
        })

      assert rules(dup) == [:duplicate_address]
    end
  end

  describe "errors" do
    test "a signed object that isn't a ROA" do
      fixture = Fixture.load!("m0-minimal-valid")

      assert ROA.decode(File.read!(Path.join(fixture.rsync_root, "ca1/ca1.mft"))) ==
               {:error, {:not_roa, :manifest}}
    end

    test "non-DER and unparseable eContent" do
      der = Base.decode16!("301802030100003011300F040200023009300703050020010DB8")
      assert {:error, {:der, %{rule: :trailing_bytes}}} = ROA.decode_econtent(der <> <<0>>)
      assert {:error, {:asn1, _}} = ROA.decode_econtent(<<0x30, 0x00>>)
    end

    @tag rfc: "9582#4.3.1",
         doc: "The module's information object set rejects other AFIs at decode time (F-012)."
    test "an address family other than IPv4 or IPv6 is a decode error" do
      der = Base.decode16!("301802030100003011300F040200033009300703050020010DB8")
      assert {:error, {:asn1, _}} = ROA.decode_econtent(der)
    end
  end
end
