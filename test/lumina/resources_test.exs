defmodule Lumina.ResourcesTest do
  @moduledoc """
  Tests decoding of the RFC 3779 IP address and AS identifier extensions,
  which resource-inclusion checks (M4/M6) depend on. Test vectors come from
  the RFC's own worked examples (§2.1, §2.2.3.8, §2.2.3.9, Appendices B
  and C), corrected where a verified erratum says the RFC is wrong
  (erratum 6792, F-002 in doc/rfc-findings.md). The canonical-form checks
  report violations without rejecting, because rejection belongs to
  validation.
  """
  use ExUnit.Case, async: true
  doctest Lumina.Resources

  alias Lumina.Resources
  alias Lumina.Test.Fixture

  defp hex(string), do: string |> String.replace(~r/\s/, "") |> Base.decode16!(case: :mixed)

  # IPAddrBlocks with one family and the given entries.
  defp blocks(afi, entries) do
    {:ok, der} =
      Lumina.ASN1.encode(:resources, :IPAddrBlocks, [
        %{addressFamily: afi, ipAddressChoice: {:addressesOrRanges, entries}}
      ])

    der
  end

  defp decode_one!(der) do
    {:ok, [%{resources: resources} = family]} = Resources.decode_ip(der)
    {family, resources}
  end

  defp formatted(families) do
    for f <- families,
        f.resources != :inherit,
        r <- f.resources,
        do: Resources.format_ip(r, f.afi)
  end

  defp rules(issues), do: Enum.map(issues, & &1.rule)

  describe "RFC 3779 Appendix B" do
    @tag rfc: ["3779#B", "3779#2.2.3.6"]
    test "the first example decodes to the prefixes and range the RFC lists, in canonical form" do
      der =
        hex("""
        30 35 30 2b 04 03 0001 01 30 24
          03 04 04 0a0020  03 04 00 0a0040  03 03 00 0a01
          30 0c 03 04 04 0a0230 03 04 00 0a0240
          03 03 00 0a03
        30 06 04 02 0002 05 00
        """)

      assert {:ok, [ipv4, ipv6]} = Resources.decode_ip(der)
      assert %{afi: :ipv4, safi: 1} = ipv4
      assert %{afi: :ipv6, safi: nil, resources: :inherit} = ipv6

      assert formatted([ipv4]) == [
               "10.0.32.0/20",
               "10.0.64.0/24",
               "10.1.0.0/16",
               "10.2.48.0-10.2.64.255",
               "10.3.0.0/16"
             ]

      assert Resources.ip_issues([ipv4, ipv6]) == []
    end

    @tag rfc: "3779#B",
         doc: """
         The second example as corrected by verified erratum 6792: the IPv4
         prefix 172.16/12 is ac10, not b010 as printed, and the IPv6 prefix is
         /48, not /47 as annotated. The family with SAFI 2 (multicast) inherits.
         """
    test "the second example, as corrected by erratum 6792, decodes to the stated prefixes" do
      der =
        hex("""
        30 2c
          30 10 04 03 0001 01 30 09 03 02 00 0a 03 03 04 ac10
          30 07 04 03 0001 02 05 00
          30 0f 04 02 0002 30 09 03 07 00 200100000002
        """)

      assert {:ok, [unicast, multicast, ipv6] = families} = Resources.decode_ip(der)

      assert {unicast.afi, unicast.safi, multicast.safi, multicast.resources} ==
               {:ipv4, 1, 2, :inherit}

      assert formatted([unicast]) == ["10.0.0.0/8", "172.16.0.0/12"]
      assert formatted([ipv6]) == ["2001:0:2::/48"]
      assert Resources.ip_issues(families) == []
    end

    @tag rfc: "3779#B",
         doc:
           "Why the erratum matters: the bytes as printed in the RFC encode 176.16/12, not 172.16/12."
    test "the second example's bytes as printed decode to 176.16/12" do
      as_printed = hex("30 10 04 03 0001 01 30 09 03 02 00 0a 03 03 04 b010")
      {:ok, [family]} = Resources.decode_ip(<<0x30, byte_size(as_printed)>> <> as_printed)
      assert formatted([family]) == ["10.0.0.0/8", "176.16.0.0/12"]
    end
  end

  describe "RFC 3779 Appendix C" do
    @tag rfc: ["3779#C", "3779#3.2.3.4"]
    test "the AS example decodes to AS135, AS3000-AS3999, AS5001 and inherited RDIs" do
      der = hex("30 1a a0 14 30 12 02 02 0087 30 08 02 02 0bb8 02 02 0f9f 02 02 1389 a1 02 05 00")

      assert {:ok, %{asnum: asnum, rdi: :inherit} = ids} = Resources.decode_as(der)
      assert Enum.map(asnum, &Resources.format_as/1) == ["AS135", "AS3000-AS3999", "AS5001"]
      assert Resources.as_issues(ids) == []
    end
  end

  describe "the worked encodings in RFC 3779 §2.1 and §2.2.3" do
    @tag rfc: "3779#2.1.1"
    test "addresses and prefixes" do
      for {bits, afi, expected} <- [
            {<<10, 5, 0, 4>>, <<0, 1>>, "10.5.0.4/32"},
            {<<10, 5, 0::7>>, <<0, 1>>, "10.5.0.0/23"},
            {hex("2001 0000 0200 0003 0000 0000 0000 0001"), <<0, 2>>, "2001:0:200:3::1/128"},
            {<<0x20, 0x01, 0x00, 0x00, 1::7>>, <<0, 2>>, "2001:0:200::/39"}
          ] do
        {family, [resource]} = decode_one!(blocks(afi, addressPrefix: bits))
        assert Resources.format_ip(resource, family.afi) == expected
      end
    end

    @tag rfc: "3779#2.1.2",
         doc:
           "0/0 is a BIT STRING with no bits (03 01 00), and trailing zero bits are significant."
    test "the all-addresses prefix and significant trailing zeros" do
      der = blocks(<<0, 1>>, addressPrefix: <<>>)
      assert :binary.match(der, <<0x03, 0x01, 0x00>>) != :nomatch
      {_, [all]} = decode_one!(der)

      assert Resources.format_ip(all, :ipv4) == "0.0.0.0/0"

      {_, [p12]} = decode_one!(blocks(<<0, 1>>, addressPrefix: <<10, 4::4>>))
      {_, [p20]} = decode_one!(blocks(<<0, 1>>, addressPrefix: <<10, 64, 0::4>>))

      assert {Resources.format_ip(p12, :ipv4), Resources.format_ip(p20, :ipv4)} ==
               {"10.64.0.0/12", "10.64.0.0/20"}
    end

    @tag rfc: ["3779#2.1.2", "3779#2.2.3.9"],
         doc: "Range ends: unspecified min bits are 0, unspecified max bits are 1."
    test "ranges expand min with zeros and max with ones" do
      # §2.2.3.9: min 1000 0001.01, max 1000 -> 129.64.0.0 to 143.255.255.255
      {_, [range]} =
        decode_one!(blocks(<<0, 1>>, addressRange: %{min: <<0x81, 1::2>>, max: <<8::4>>}))

      assert Resources.format_ip(range, :ipv4) == "129.64.0.0-143.255.255.255"

      # §2.1.2: 2001:0:200/39 as a range, max is 38 bits ending in zero octets.
      {_, [v6]} =
        decode_one!(
          blocks(<<0, 2>>,
            addressRange: %{min: <<0x20, 0x01, 0, 0, 1::7>>, max: <<0x20, 0x01, 0, 0, 0::6>>}
          )
        )

      assert Resources.format_ip(v6, :ipv6) == "2001:0:200::-2001:0:3ff:ffff:ffff:ffff:ffff:ffff"
    end

    @tag rfc: "3779#2.2.3.8"
    test "the §2.2.3.8 prefix 128/4 covers 128.0.0.0 to 143.255.255.255" do
      {_, [prefix]} = decode_one!(blocks(<<0, 1>>, addressPrefix: <<8::4>>))
      assert Resources.bounds(prefix, :ipv4) == {0x80000000, 0x8FFFFFFF}
    end
  end

  describe "edge cases" do
    test "::/0, a single IPv6 address and the IPv4 /32 maximum" do
      {_, [all]} = decode_one!(blocks(<<0, 2>>, addressPrefix: <<>>))
      assert Resources.format_ip(all, :ipv6) == "::/0"

      {_, [one]} = decode_one!(blocks(<<0, 2>>, addressPrefix: :binary.copy(<<0xFF>>, 16)))
      assert Resources.format_ip(one, :ipv6) == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
    end

    test "a prefix longer than the address family is an error" do
      assert {:error, {:prefix_too_long, :ipv4, 40}} =
               Resources.decode_ip(blocks(<<0, 1>>, addressPrefix: <<1, 2, 3, 4, 5>>))
    end

    test "an unknown AFI keeps its bit strings undecoded" do
      {family, resources} = decode_one!(blocks(<<0, 9>>, addressPrefix: <<1::3>>))
      assert family.afi == {:unknown, 9}
      assert resources == [{:raw_prefix, <<1::3>>}]
      assert Resources.ip_issues([family]) == []
    end

    @tag rfc: "3779#2.2.3.9",
         doc: """
         Verified erratum 2537 deleted the rule that a range maximum must contain
         a one bit. A maximum like 0.0.0.255 encodes as 24 zero bits (03 04 00
         00 00 00) and must be accepted.
         """
    test "a range maximum with no one bits is accepted (erratum 2537)" do
      der = blocks(<<0, 1>>, addressRange: %{min: <<0, 0, 0, 1>>, max: <<0, 0, 0>>})
      {family, [range]} = decode_one!(der)
      assert Resources.format_ip(range, :ipv4) == "0.0.0.1-0.0.0.255"
      assert Resources.ip_issues([family]) == []
    end

    test "malformed DER is an error" do
      assert {:error, _} = Resources.decode_ip(<<0x30, 0x03, 0x02>>)
      assert {:error, _} = Resources.decode_as(<<>>)
    end
  end

  describe "canonical form (reported, not enforced)" do
    @tag rfc: "3779#2.2.3.6"
    test "reports unsorted, overlapping and contiguous blocks" do
      {f, _} = decode_one!(blocks(<<0, 1>>, addressPrefix: <<11>>, addressPrefix: <<10>>))
      assert rules(Resources.ip_issues([f])) == [:block_order, :adjacent]

      {f, _} = decode_one!(blocks(<<0, 1>>, addressPrefix: <<10>>, addressPrefix: <<10, 1>>))
      assert rules(Resources.ip_issues([f])) == [:overlap]

      {f, _} = decode_one!(blocks(<<0, 1>>, addressPrefix: <<10>>, addressPrefix: <<12>>))
      assert Resources.ip_issues([f]) == []
    end

    @tag rfc: ["3779#2.2.3.7", "3779#2.2.3.9"]
    test "reports ranges that should be prefixes, non-minimal ends and inverted ranges" do
      {f, _} = decode_one!(blocks(<<0, 1>>, addressRange: %{min: <<5::7>>, max: <<10>>}))
      assert rules(Resources.ip_issues([f])) == [:range_is_prefix]

      {f, _} = decode_one!(blocks(<<0, 1>>, addressRange: %{min: <<10, 0>>, max: <<12, 1::1>>}))
      assert rules(Resources.ip_issues([f])) == [:range_min_not_minimal, :range_max_not_minimal]

      {f, _} = decode_one!(blocks(<<0, 1>>, addressRange: %{min: <<11>>, max: <<10>>}))
      assert :range_inverted in rules(Resources.ip_issues([f]))
    end

    @tag rfc: "3779#2.2.3.3"
    test "reports address families out of order or duplicated" do
      {:ok, der} =
        Lumina.ASN1.encode(:resources, :IPAddrBlocks, [
          %{addressFamily: <<0, 2>>, ipAddressChoice: {:inherit, :NULL}},
          %{addressFamily: <<0, 1>>, ipAddressChoice: {:inherit, :NULL}}
        ])

      {:ok, families} = Resources.decode_ip(der)
      assert rules(Resources.ip_issues(families)) == [:family_order]

      # Same AFI twice: relabel both decoded families as IPv4.
      dup = Enum.map(families, &%{&1 | afi: :ipv4})
      assert rules(Resources.ip_issues(dup)) == [:duplicate_family]
    end

    @tag rfc: ["3779#3.2.3.4", "3779#3.2.3.8"],
         doc: "Equal range ends are reported per erratum 7653, held for document update."
    test "reports AS identifiers that are unsorted, overlapping, contiguous or badly formed ranges" do
      check = fn asnum -> rules(Resources.as_issues(%{asnum: asnum, rdi: nil})) end

      assert check.([{:id, 2}, {:id, 1}]) == [:id_order, :adjacent]
      assert check.([{:range, 1, 10}, {:id, 5}]) == [:overlap]
      assert check.([{:id, 5}, {:range, 1, 3}]) == [:id_order]
      assert check.([{:id, 1}, {:id, 3}]) == []
      assert check.([{:range, 5, 5}]) == [:range_single]
      assert check.([{:range, 9, 5}]) |> hd() == :range_inverted
    end
  end

  describe "Barry fixture" do
    @tag rfc: ["3779#2.2.3", "3779#3.2.3"],
         doc:
           "Barry's README: the TA holds everything, and the first CA gets 1/8, 0100::/8 and AS 0x01000000-0x01FFFFFF."
    test "the m0-minimal-valid certificates carry Barry's default resources" do
      fixture = Fixture.load!("m0-minimal-valid")

      expected = %{
        "ta.cer" => {["0.0.0.0/0", "::/0"], [{:range, 0, 0xFFFFFFFF}]},
        "ta/ca1.cer" => {["1.0.0.0/8", "100::/8"], [{:range, 0x01000000, 0x01FFFFFF}]}
      }

      for {file, {ips, asnum}} <- expected do
        {:ok, cert} =
          Lumina.ASN1.decode(:pkix, :Certificate, File.read!(Path.join(fixture.rsync_root, file)))

        exts = Map.new(cert.tbsCertificate.extensions, &{&1.extnID, &1.extnValue})

        {:ok, families} = Resources.decode_ip(exts[{1, 3, 6, 1, 5, 5, 7, 1, 7}])
        assert formatted(families) == ips, file
        assert Resources.ip_issues(families) == []

        {:ok, ids} = Resources.decode_as(exts[{1, 3, 6, 1, 5, 5, 7, 1, 8}])
        assert ids == %{asnum: asnum, rdi: nil}, file
      end
    end
  end
end
