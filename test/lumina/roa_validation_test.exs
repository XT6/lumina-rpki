defmodule Lumina.ROAValidationTest do
  @moduledoc """
  Tests ROA content validation (#171): `Lumina.ROA.check/2` against the
  ROA's EE certificate, RFC 9582 §4 and §5, and its use by `lumina
  validate`.

  §5 lists what a relying party checks beyond RFC 6488: the EE
  certificate has the IP address delegation extension, without
  `inherit`, and no AS identifier extension; every ROA prefix is within
  the EE certificate's addresses; and the content conforms to §3 and §4.
  "If any of the above checks fail, the ROA in its entirety MUST be
  considered invalid." The §4.3 SHOULDs (a superfluous maxLength, order
  and duplicates) only warn (D-030, F-018).

  Most cases are in memory: the ROA and the EE certificate of
  m0-minimal-valid's roa1.roa (EE 1.1.0.0/16 and 101::/16), changed one
  field at a time, since Barry can't write some of them (an AS extension
  on a ROA's EE certificate, two families with the same AFI, an
  IPv4-mapped prefix). The `m7-roa-*` fixtures cover the rest end to end.
  """
  use ExUnit.Case, async: true
  import Bitwise

  alias Lumina.{CLI, Extension, ROA}
  alias Lumina.Test.{Fixture, RsyncDaemon}

  @now ~U[2030-01-01 00:00:00Z]

  defp roa do
    root = Fixture.load!("m0-minimal-valid").rsync_root
    {:ok, roa} = ROA.decode(File.read!(Path.join(root, "ca1/roa1.roa")))
    roa
  end

  defp ee(roa), do: Lumina.SignedObject.ee_certificate(roa.object)

  # The EE certificate with extension `name`'s decoded value replaced
  # (added if missing, removed with :remove).
  defp with_extension(ee, name, value) do
    extensions = Enum.reject(ee.extensions, &(&1.name == name))

    extensions =
      if value == :remove,
        do: extensions,
        else: extensions ++ [%Extension{name: name, critical: true, value: value}]

    %{ee | extensions: extensions}
  end

  defp ipv4(prefixes), do: %{afi: :ipv4, addresses: Enum.map(prefixes, &address/1)}
  defp ipv6(prefixes), do: %{afi: :ipv6, addresses: Enum.map(prefixes, &address/1)}
  defp address({address, length}), do: %{prefix: {:prefix, address, length}, max_length: nil}

  defp address({address, length, max}),
    do: %{prefix: {:prefix, address, length}, max_length: max}

  defp rules(problems, severity),
    do: for(%{severity: ^severity, rule: rule} <- problems, do: rule)

  describe "ROA.check/2" do
    @tag rfc: ["9582#5", "9582#4.3.2.2"]
    test "a ROA whose prefixes are exactly its EE certificate's addresses has no problems" do
      roa = roa()
      assert ROA.check(roa, ee(roa)) == []
    end

    @tag rfc: "9582#5"
    test "prefixes strictly inside the EE certificate's addresses, with maxLength, are valid" do
      roa = %{
        roa()
        | families: [
            ipv4([{0x01010000, 17, 24}, {0x01018000, 24}]),
            ipv6([{0x0101 <<< 112, 16, 48}])
          ]
      }

      assert ROA.check(roa, ee(roa)) == []
    end

    @tag rfc: "9582#4.1"
    test "a version other than 0 is an error" do
      roa = %{roa() | version: 1}

      assert [%{rule: :roa_version, rfc: "9582#4.1", severity: :error, field: :roa}] =
               ROA.check(roa, ee(roa))
    end

    @tag rfc: "9582#5"
    test "an EE certificate without the IP address delegation extension is an error" do
      roa = roa()
      problems = ROA.check(roa, with_extension(ee(roa), :ip_resources, :remove))

      assert :roa_ee_no_ip_resources in rules(problems, :error)
    end

    @tag rfc: "9582#5"
    test "an EE certificate that uses inherit for an address family is an error" do
      roa = roa()

      ip = [
        %{afi: :ipv4, safi: nil, resources: :inherit},
        %{afi: :ipv6, safi: nil, resources: [{:prefix, 0x0101 <<< 112, 16}]}
      ]

      assert [%{rule: :roa_ee_ip_inherit, rfc: "9582#5"}] =
               ROA.check(roa, with_extension(ee(roa), :ip_resources, ip))
    end

    @tag rfc: "9582#5",
         doc: "Barry can't add the AS extension to a ROA's EE certificate, so this is in memory."
    test "an EE certificate with the AS identifier delegation extension is an error" do
      roa = roa()
      as = %{asnum: [{:id, 64496}], rdi: nil}

      assert [%{rule: :roa_ee_as_resources, rfc: "9582#5"}] =
               ROA.check(roa, with_extension(ee(roa), :as_resources, as))
    end

    @tag rfc: "9582#5"
    test "a prefix outside the EE certificate's addresses is an error naming it" do
      roa = %{roa() | families: [ipv4([{0x01010000, 16}, {0x01020000, 16}])]}

      assert [%{rule: :roa_prefix_outside_ee, message: message}] = ROA.check(roa, ee(roa))
      assert message == "1.2.0.0/16 not in the EE certificate's addresses"
    end

    @tag rfc: "9582#5", doc: "One address past the end: 1.1.0.0/15 covers 1.0.0.0/16 too."
    test "a prefix that only partly overlaps the EE certificate's addresses is outside" do
      roa = %{roa() | families: [ipv4([{0x01000000, 15}])]}

      assert [%{rule: :roa_prefix_outside_ee, message: "1.0.0.0/16 not in" <> _}] =
               ROA.check(roa, ee(roa))
    end

    @tag rfc: "9582#5"
    test "a prefix in a family the EE certificate doesn't list is outside" do
      roa = roa()
      ip = [%{afi: :ipv4, safi: nil, resources: [{:prefix, 0x01010000, 16}]}]

      assert [%{rule: :roa_prefix_outside_ee, message: "101::/16 not in" <> _}] =
               ROA.check(roa, with_extension(ee(roa), :ip_resources, ip))
    end

    @tag rfc: "9582#4.3.2.2"
    test "a maxLength below the prefix length is an error" do
      roa = %{roa() | families: [ipv4([{0x01010000, 16, 12}])]}

      assert [:max_length_out_of_range] = rules(ROA.check(roa, ee(roa)), :error)
    end

    @tag rfc: "9582#4.3.1"
    test "two ROAIPAddressFamily elements with the same AFI are an error" do
      roa = %{roa() | families: [ipv4([{0x01010000, 17}]), ipv4([{0x01018000, 17}])]}

      assert :duplicate_family in rules(ROA.check(roa, ee(roa)), :error)
    end

    @tag rfc: "9582#4.3.1"
    test "an IPv4-mapped IPv6 prefix is an error" do
      roa = %{roa() | families: [ipv6([{0xFFFF01010000, 112}])]}

      assert :ipv4_mapped in rules(ROA.check(roa, ee(roa)), :error)
    end

    @tag rfc: "9582#4.3.2.2"
    test "a maxLength equal to the prefix length only warns" do
      roa = %{roa() | families: [ipv4([{0x01010000, 16, 16}])]}
      problems = ROA.check(roa, ee(roa))

      assert rules(problems, :error) == []
      assert rules(problems, :warning) == [:superfluous_max_length]
    end

    @tag rfc: ["9582#4.3.3", "9582#4.3.3.1"]
    test "prefixes out of canonical order, or repeated, only warn" do
      unsorted = %{roa() | families: [ipv4([{0x01018000, 24}, {0x01010000, 24}])]}
      repeated = %{roa() | families: [ipv4([{0x01010000, 24}, {0x01010000, 24}])]}

      assert rules(ROA.check(unsorted, ee(unsorted)), :warning) == [:not_canonical_order]
      assert rules(ROA.check(unsorted, ee(unsorted)), :error) == []
      assert rules(ROA.check(repeated, ee(repeated)), :warning) == [:duplicate_address]
      assert rules(ROA.check(repeated, ee(repeated)), :error) == []
    end
  end

  describe "decoding" do
    @tag rfc: "9582#4.3.1",
         doc: """
         The ASN.1 module's information object set makes the decoder reject
         AFI 0003 (F-012); the error names the rule instead of a generic
         ASN.1 failure.
         """
    test "an address family other than IPv4 or IPv6 is reported with the rule it breaks" do
      der = Base.decode16!("301802030100003011300F040200033009300703050020010DB8")

      assert {:error, {:econtent, %{rule: :invalid_address_family, rfc: "9582#4.3.1"} = error}} =
               ROA.decode_econtent(der)

      assert Lumina.Print.error({:econtent, error}, "x.roa") ==
               "eContent layer: address family 0003 is neither IPv4 (0001) nor IPv6 (0002) " <>
                 "(invalid_address_family, RFC 9582 §4.3.1)"
    end
  end

  describe "lumina validate" do
    @describetag :tmp_dir

    defp run(args, internal) do
      {:ok, out} = StringIO.open("")
      {:ok, err} = StringIO.open("")
      code = CLI.run(args, out, err, internal)
      {code, elem(StringIO.contents(out), 1)}
    end

    defp synced!(tmp, id) do
      fixture = Fixture.load!(id)
      daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), fixture.modules)
      authority = "127.0.0.1:#{daemon.port}"
      tal = Path.join(tmp, "case.tal")

      File.write!(
        tal,
        fixture.tal_path
        |> File.read!()
        |> String.split("\n")
        |> Enum.reject(&String.starts_with?(&1, "https://"))
        |> Enum.map_join("\n", &String.replace(&1, "localhost:8873", authority))
      )

      cache = Path.join(tmp, "cache")
      internal = [now: @now, remap: %{"localhost:8873" => authority}]
      {0, _} = run(["sync", "--cache", cache, "--tal", tal], internal)
      {["validate", "--cache", cache, "--tal", tal], internal}
    end

    @tag :rsync
    @tag rfc: "9582#5",
         doc: """
         m7-roa-prefix-outside-ee: roa1.roa lists 1.2.0.0/16 outside its EE
         certificate; roa2.roa, in the same publication point, is fine.
         """
    test "an invalid ROA is listed with its rule, and the other ROAs at the point stay valid",
         %{tmp_dir: tmp} do
      {args, internal} = synced!(tmp, "m7-roa-prefix-outside-ee")
      assert {1, out} = run(args, internal)

      assert out =~
               "    invalid: rsync://localhost:8873/rpki/ca1/roa1.roa (roa_prefix_outside_ee)\n"

      # Only Barry's usual envelope warning (F-031), no error.
      assert out =~
               "    warning: rsync://localhost:8873/rpki/ca1/roa2.roa " <>
                 "(signature_algorithm_parameters_absent)\n"

      assert out =~ "  ROAs: 1 valid, 1 invalid\n"
    end

    @tag :rsync
    @tag rfc: "9582#4.3.2.2",
         doc: "m7-roa-max-length-superfluous: a SHOULD, so a warning on a valid ROA (D-030)."
    test "a ROA breaking only a SHOULD is valid, with a warning", %{tmp_dir: tmp} do
      {args, internal} = synced!(tmp, "m7-roa-max-length-superfluous")
      assert {0, out} = run(args, internal)

      assert out =~
               "    warning: rsync://localhost:8873/rpki/ca1/roa1.roa " <>
                 "(signature_algorithm_parameters_absent, superfluous_max_length)\n"

      assert out =~ "  ROAs: 1 valid, 0 invalid\n"
    end
  end
end
