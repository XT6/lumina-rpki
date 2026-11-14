defmodule Lumina.ResourceInclusionTest do
  @moduledoc """
  Tests resource inclusion (#154): `Lumina.Chain.child/6` rejects a CA or
  EE certificate whose effective resources aren't encompassed by its
  issuer's (RFC 6487 §7.2 point 6; RFC 3779 §2.3 and §3.3: "Validation
  MUST fail when this is not the case"), with rule
  `resources_not_encompassed` and a message naming the resources outside.

  The comparison itself (sets, kinds separately, D-027) is
  `EncompassTest`'s. Here: the rule in the chain, through in-memory
  changes to m0-minimal-valid's ca1 (an IP address range, which Barry
  can't write in a certificate) and through the `m6-overclaim-*`
  fixtures, one per way of overclaiming, at 2030-01-01; that an
  overclaim deep in a chain invalidates only that branch (over rsync,
  with `Lumina.Validate.run/3`); and that equal or inherited resources
  stay valid. The certificate is invalid as a whole: RFC 8360 isn't
  applied (#121).
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, Chain, Extension, Object, SignedObject, Sync, TAL, Validate}
  alias Lumina.Test.{Fixture, RsyncDaemon}

  @at ~U[2030-01-01 00:00:00Z]
  @no_crl %{crl: nil, valid: true, problems: []}

  defp ca1 do
    path = Path.join(Fixture.load!("m0-minimal-valid").rsync_root, "ta/ca1.cer")
    {:ok, cert} = Certificate.decode(File.read!(path))
    cert
  end

  defp ta do
    path = Path.join(Fixture.load!("m0-minimal-valid").rsync_root, "ta.cer")
    {:ok, cert} = Certificate.decode(File.read!(path))
    cert
  end

  # ca1 with its IP extension replaced by `ip`, a list of {afi, choice},
  # each resource with its DER encoding (`encoded`).
  defp with_ip(ip) do
    cert = ca1()
    others = Enum.reject(cert.extensions, &(&1.name == :ip_resources))

    ext = %Extension{
      oid: {1, 3, 6, 1, 5, 5, 7, 1, 7},
      name: :ip_resources,
      critical: true,
      value:
        for(
          {afi, r} <- ip,
          do: %{afi: afi, safi: nil, resources: part(r, 0), encoded: part(r, 1)}
        )
    }

    %{cert | extensions: others ++ [ext]}
  end

  # Each resource is {decoded, encoded}; `inherit` is both.
  defp part(:inherit, _index), do: :inherit
  defp part(list, index), do: Enum.map(list, &elem(&1, index))

  defp overclaims(result),
    do: for(%{rule: :resources_not_encompassed} = p <- result.problems, do: p)

  describe "Chain.child/6" do
    @tag rfc: ["6487#7.2", "3779#2.3"],
         doc: """
         ca1 holds 1.0.0.0/8, 100::/8 and an AS range; the issuer is
         given as holding 1.0.0.0/9 and the rest, so ca1's upper half of
         1.0.0.0/8 lies outside. Only that is reported, as a prefix.
         """
    test "a certificate holding addresses outside its issuer's is invalid, naming them" do
      held = Lumina.Resources.effective(ca1(), nil)
      issuer = %{held | ipv4: [{:prefix, 0x01000000, 9}]}

      result = Chain.child(ca1(), :ca, ta(), @no_crl, @at, resources: issuer)

      refute result.valid

      assert [
               %{
                 rfc: "6487#7.2",
                 field: :resources,
                 severity: :error,
                 message: "1.128.0.0/9 not held by the issuer"
               }
             ] = overclaims(result)
    end

    @tag rfc: ["6487#7.2", "3779#2.3"],
         doc: """
         Barry writes only prefixes in certificates, so the address range
         is set in memory: 1.0.0.0-1.0.1.9 against an issuer holding
         1.0.0.0/24. The part outside, 1.0.1.0-1.0.1.9, isn't a prefix and
         is shown as a range.
         """
    test "an address range partly outside the issuer's is reported as the range outside" do
      # Minimal encodings (RFC 3779 §2.2.3.9): 1.0.0.0 without its trailing
      # zero bits, 1.0.1.9 without its trailing one bit.
      bits = %{min: <<1::8>>, max: <<1, 0, 1, 0b0000100::7>>}
      cert = with_ip(ipv4: [{{:range, 0x01000000, 0x01000109}, {:addressRange, bits}}])
      issuer = %{ipv4: [{:prefix, 0x01000000, 24}], ipv6: [], as: [{:range, 0, 4_294_967_295}]}

      result = Chain.child(cert, :ca, ta(), @no_crl, @at, resources: issuer)

      refute result.valid

      assert [%{message: "1.0.1.0-1.0.1.9 not held by the issuer"}] = overclaims(result)
    end

    @tag rfc: ["6487#7.2", "3779#2.3", "3779#3.3"],
         doc: "IPv4, then IPv6, then AS numbers, in one message."
    test "resources outside in several kinds are all named in one problem" do
      issuer = %{ipv4: [], ipv6: [], as: []}

      result = Chain.child(ca1(), :ca, ta(), @no_crl, @at, resources: issuer)

      assert [%{message: "1.0.0.0/8, 100::/8, AS16777216-AS33554431 not held by the issuer"}] =
               overclaims(result)
    end

    @tag rfc: ["6487#7.1", "6487#7.2"],
         doc: "Without a CRL the result is invalid for other reasons; only point 6 is checked."
    test "a certificate holding exactly its issuer's resources is encompassed" do
      held = Lumina.Resources.effective(ca1(), nil)
      result = Chain.child(ca1(), :ca, ta(), @no_crl, @at, resources: held)
      assert overclaims(result) == []
    end

    @tag rfc: ["6487#7.2", "3779#2.2.3.5"],
         doc: """
         Inherited kinds are the issuer's set, so they never lie outside,
         even when the issuer holds none of a kind (D-026).
         """
    test "a certificate inheriting every kind is encompassed by any issuer" do
      cert = with_ip(ipv4: :inherit, ipv6: :inherit)
      cert = %{cert | extensions: Enum.reject(cert.extensions, &(&1.name == :as_resources))}
      issuer = %{ipv4: [{:prefix, 0x0A000000, 8}], ipv6: [], as: []}

      result = Chain.child(cert, :ca, ta(), @no_crl, @at, resources: issuer)

      assert overclaims(result) == []
      assert result.resources == issuer
    end
  end

  describe "fixtures" do
    # Validates `files` down from the TA, each against the one before,
    # carrying effective resources (as `EffectiveResourcesTest` does).
    defp down(id, files) do
      fixture = Fixture.load!(id)
      {:ok, tal} = TAL.decode_file(fixture.tal_path)

      decode = fn file ->
        elem(Object.decode_file(Path.join(fixture.rsync_root, file)), 1).value
      end

      ta = decode.("ta.cer")
      ta_result = Chain.ta(ta, tal, @at)

      Enum.map_reduce(files, {ta, ta_result.resources, "ta"}, fn file, {issuer, held, dir} ->
        {cert, kind} =
          case decode.(file) do
            %Certificate{} = cert -> {cert, :ca}
            %{object: %SignedObject{} = o} -> {SignedObject.ee_certificate(o), :ee}
          end

        crl = Chain.crl(decode.(dir <> "/" <> dir <> ".crl"), issuer, @at)
        result = Chain.child(cert, kind, issuer, crl, @at, resources: held)
        {result, {cert, result.resources, Path.rootname(Path.basename(file))}}
      end)
      |> elem(0)
    end

    # The fixture's one reject: ca1 valid, the named certificate invalid
    # only for the overclaim, with the reason the metadata states.
    defp rejected!(id, files) do
      {:invalid, [%{reason: reason, rule: :resources_not_encompassed}]} =
        Fixture.load!(id).expected

      [ca1 | rest] = down(id, files)
      assert ca1.valid
      last = List.last(rest)
      refute last.valid
      assert Enum.reject(last.problems, &(&1.severity == :warning)) == overclaims(last)
      assert [%{message: ^reason}] = overclaims(last)
    end

    @tag rfc: ["6487#7.2", "3779#2.3"]
    test "m6-overclaim-ipv4: a CA claiming an IPv4 prefix outside its issuer's is invalid" do
      rejected!("m6-overclaim-ipv4", ~w(ta/ca1.cer ca1/ca2.cer))
    end

    @tag rfc: ["6487#7.2", "3779#2.3"]
    test "m6-overclaim-ipv6: a CA claiming an IPv6 prefix outside its issuer's is invalid" do
      rejected!("m6-overclaim-ipv6", ~w(ta/ca1.cer ca1/ca2.cer))
    end

    @tag rfc: ["6487#7.2", "3779#3.3"]
    test "m6-overclaim-as: a CA claiming an AS number outside its issuer's is invalid" do
      rejected!("m6-overclaim-as", ~w(ta/ca1.cer ca1/ca2.cer))
    end

    @tag rfc: ["6487#7.2", "3779#3.3"]
    test "m6-overclaim-as-range: a CA claiming an AS range partly outside its issuer's is invalid, naming the part outside" do
      rejected!("m6-overclaim-as-range", ~w(ta/ca1.cer ca1/ca2.cer))
    end

    @tag rfc: ["6487#7.2", "3779#2.3"]
    test "m6-overclaim-ipv4-partial: a CA claiming a prefix that contains its issuer's is invalid, naming the part outside" do
      rejected!("m6-overclaim-ipv4-partial", ~w(ta/ca1.cer ca1/ca2.cer))
    end

    @tag rfc: ["6487#7.2", "3779#2.3"]
    test "m6-overclaim-family: a CA claiming an address family its issuer doesn't have is invalid" do
      rejected!("m6-overclaim-family", ~w(ta/ca1.cer ca1/ca2.cer))
    end

    @tag rfc: ["6487#7.2", "6488#3", "3779#2.3"]
    test "m6-overclaim-roa-ee: a ROA whose EE certificate overclaims is invalid" do
      rejected!("m6-overclaim-roa-ee", ~w(ta/ca1.cer ca1/roa1.roa))
    end

    @tag rfc: ["6487#7.1", "6487#7.2", "3779#2.3", "3779#3.3"]
    test "m6-encompass-equal: a CA holding exactly its issuer's resources is valid" do
      results = down("m6-encompass-equal", ~w(ta/ca1.cer ca1/ca2.cer))
      assert Enum.all?(results, & &1.valid)
      [ca1, ca2] = results
      assert ca2.resources == ca1.resources
    end

    @tag rfc: ["6487#7.2", "3779#2.2.3.5", "3779#3.2.3.3"]
    test "m6-inherit-two-levels: certificates inheriting everything are encompassed" do
      results =
        down("m6-inherit-two-levels", ~w(ta/ca1.cer ca1/ca2.cer ca2/ca3.cer ca3/roa1.roa))

      assert Enum.all?(results, &(&1.valid and overclaims(&1) == []))
    end
  end

  describe "a branch below an overclaim" do
    @describetag :tmp_dir

    @tag :rsync
    @tag rfc: ["6487#7.2", "3779#2.3"],
         doc: """
         m6-overclaim-grandchild, synced from a local rsync daemon and
         validated offline: ca3 claims a prefix ca1 holds but ca2, its
         issuer, doesn't. ca3 is invalid, its publication point is never
         processed (no manifest entry, roa1 not reached), and its
         sibling ca4 and everything else validate.
         """
    test "an overclaim deep in a chain invalidates only that certificate and what is below it",
         %{tmp_dir: tmp} do
      fixture = Fixture.load!("m6-overclaim-grandchild")
      daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), fixture.modules)
      authority = "127.0.0.1:#{daemon.port}"

      text =
        fixture.tal_path
        |> File.read!()
        |> String.split("\n")
        |> Enum.reject(&String.starts_with?(&1, "https://"))
        |> Enum.map_join("\n", &String.replace(&1, "localhost:8873", authority))

      path = Path.join(tmp, "case.tal")
      File.write!(path, text)
      {:ok, tal} = TAL.decode_file(path)
      cache = Path.join(tmp, "cache")

      {:ok, [_report]} =
        Sync.run([{path, tal}], cache, now: @at, remap: %{"localhost:8873" => authority})

      {:ok, result} = Validate.run(tal, cache, now: @at)
      uri = &("rsync://localhost:8873/rpki/" <> &1)
      by_uri = Map.new(result.objects, &{&1.uri, &1})

      refute by_uri[uri.("ca2/ca3.cer")].valid
      assert [%{rule: :resources_not_encompassed}] = overclaims(by_uri[uri.("ca2/ca3.cer")])

      assert for(%{valid: false} = o <- result.objects, do: o.uri) == [uri.("ca2/ca3.cer")]

      refute Map.has_key?(by_uri, uri.("ca3/ca3.mft"))
      refute Map.has_key?(by_uri, uri.("ca3/roa1.roa"))

      for valid <- ~w(ta/ca1.cer ca1/ca2.cer ca2/ca4.cer ca4/roa2.roa ca2/ca2.mft ca4/ca4.mft),
          do: assert(by_uri[uri.(valid)].valid, valid)
    end
  end
end
