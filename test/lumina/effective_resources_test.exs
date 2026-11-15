defmodule Lumina.EffectiveResourcesTest do
  @moduledoc """
  Tests effective resources (#153): `Lumina.Resources.effective/2`
  resolves `inherit` from the issuer's effective resources (RFC 3779
  §2.2.3.5 for each address family, §3.2.3.3 for AS numbers), and
  `Lumina.Chain` carries them down a chain.

  Resource inclusion itself (RFC 6487 §7.2 point 6) is
  `ResourceInclusionTest`'s (#154); here only
  what a certificate holds is decided. Resolving gives no errors:
  inheriting a kind the issuer doesn't hold is holding nothing of it
  (D-026), as every manifest's EE certificate does under a CA that lacks
  a kind (RFC 9286 §5.1). The unit tests change m0-minimal-valid's ca1
  certificate in memory; the `m6-inherit-*` and
  m1-resources-inherit fixtures check the same through real chains, at
  2030-01-01.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, Chain, Extension, Object, Resources, SignedObject, TAL}
  alias Lumina.Test.Fixture

  @at ~U[2030-01-01 00:00:00Z]
  @v4 [{:prefix, 0x0A000000, 8}]
  @v6 [{:prefix, 0x20010DB8000000000000000000000000, 32}]
  @as [{:id, 64496}, {:range, 65000, 65010}]
  @issuer %{ipv4: @v4, ipv6: @v6, as: @as}

  defp ca1 do
    path = Path.join(Fixture.load!("m0-minimal-valid").rsync_root, "ta/ca1.cer")
    {:ok, cert} = Certificate.decode(File.read!(path))
    cert
  end

  # ca1 with its resource extensions replaced: `ip` a list of {afi,
  # choice}, `as` an asnum choice; nil leaves the extension out.
  defp with_resources(ip, as) do
    cert = ca1()
    others = Enum.reject(cert.extensions, &(&1.name in [:ip_resources, :as_resources]))

    ip_ext =
      if ip,
        do: [
          %Extension{
            oid: {1, 3, 6, 1, 5, 5, 7, 1, 7},
            name: :ip_resources,
            critical: true,
            value: for({afi, r} <- ip, do: %{afi: afi, safi: nil, resources: r, encoded: r})
          }
        ],
        else: []

    as_ext =
      if as,
        do: [
          %Extension{
            oid: {1, 3, 6, 1, 5, 5, 7, 1, 8},
            name: :as_resources,
            critical: true,
            value: %{asnum: as, rdi: nil}
          }
        ],
        else: []

    %{cert | extensions: others ++ ip_ext ++ as_ext}
  end

  describe "Resources.effective/2" do
    @tag rfc: ["6487#4.8.10", "6487#4.8.11"]
    test "explicit resources are taken as they are, whatever the issuer holds" do
      cert = with_resources([ipv4: [{:prefix, 1, 32}], ipv6: @v6], [{:id, 1}])

      assert Resources.effective(cert, @issuer) ==
               %{ipv4: [{:prefix, 1, 32}], ipv6: @v6, as: [{:id, 1}]}
    end

    @tag rfc: ["3779#2.2.3.5", "3779#3.2.3.3"]
    test "an inherited kind takes the issuer's effective set, each address family on its own" do
      cert = with_resources([ipv4: :inherit, ipv6: [{:prefix, 0, 0}]], :inherit)

      assert Resources.effective(cert, @issuer) ==
               %{ipv4: @v4, ipv6: [{:prefix, 0, 0}], as: @as}
    end

    @tag rfc: ["6487#4.8.10", "6487#4.8.11"],
         doc: "Only AS numbers, or one address family: the rest is held by nobody."
    test "a kind the certificate doesn't list is empty" do
      assert Resources.effective(with_resources(nil, @as), @issuer) ==
               %{ipv4: [], ipv6: [], as: @as}

      assert Resources.effective(with_resources([ipv6: :inherit], nil), @issuer) ==
               %{ipv4: [], ipv6: @v6, as: []}
    end

    @tag rfc: ["3779#2.2.3.5", "3779#3.2.3.3", "9286#5.1"],
         doc: """
         D-026. A manifest's EE certificate must inherit every kind (RFC
         9286 §5.1), so under a CA without IPv6 or AS numbers it inherits
         them from nothing; LACNIC's repository has over 1,500 such
         manifests.
         """
    test "inheriting a kind the issuer doesn't hold is holding nothing of it" do
      issuer = %{ipv4: @v4, ipv6: [], as: []}
      cert = with_resources([ipv4: :inherit, ipv6: :inherit], :inherit)

      assert Resources.effective(cert, issuer) == %{ipv4: @v4, ipv6: [], as: []}
    end

    @tag rfc: "8630#2.3",
         doc: "The TA's inherit is rejected against its TAL; resolving adds nothing."
    test "a TA's inherit resolves to nothing" do
      assert Resources.effective(with_resources([ipv4: :inherit], :inherit), nil) ==
               %{ipv4: [], ipv6: [], as: []}
    end
  end

  describe "Chain" do
    @tag rfc: ["3779#2.2.3.5", "6487#7.2"]
    test "a child's result carries its effective resources, from the issuer's passed in" do
      fixture = Fixture.load!("m0-minimal-valid")
      {:ok, tal} = TAL.decode_file(fixture.tal_path)
      {:ok, ta} = Certificate.decode(File.read!(Path.join(fixture.rsync_root, "ta.cer")))
      cert = with_resources([ipv4: :inherit, ipv6: :inherit], :inherit)

      held = Chain.ta(ta, tal, @at).resources
      assert held.ipv4 == [{:prefix, 0, 0}]

      result =
        Chain.child(cert, :ca, ta, %{crl: nil, valid: true, problems: []}, @at, resources: held)

      assert result.resources == held

      result =
        Chain.child(cert, :ca, ta, %{crl: nil, valid: true, problems: []}, @at,
          resources: %{ipv4: [], ipv6: [], as: []}
        )

      assert result.resources == %{ipv4: [], ipv6: [], as: []}
      refute Enum.any?(result.problems, &(&1.field in [:ip_resources, :as_resources]))
    end
  end

  describe "fixtures" do
    defp chain(id) do
      fixture = Fixture.load!(id)
      {:ok, tal} = TAL.decode_file(fixture.tal_path)
      root = fixture.rsync_root
      decode = fn file -> elem(Object.decode_file(Path.join(root, file)), 1).value end
      ta = decode.("ta.cer")
      {decode, Chain.ta(ta, tal, @at), ta}
    end

    defp crl(decode, dir, issuer),
      do: Chain.crl(decode.(dir <> "/" <> dir <> ".crl"), issuer, @at)

    # Validates `files` (CA certificates, then optionally a signed object)
    # down from the TA, each against the one before, carrying resources.
    defp down(id, files) do
      {decode, ta_result, ta} = chain(id)

      Enum.map_reduce(files, {ta, ta_result.resources, "ta"}, fn file, {issuer, held, dir} ->
        {cert, kind} =
          case decode.(file) do
            %Certificate{} = cert -> {cert, :ca}
            %{object: %SignedObject{} = o} -> {SignedObject.ee_certificate(o), :ee}
          end

        result = Chain.child(cert, kind, issuer, crl(decode, dir, issuer), @at, resources: held)
        {result, {cert, result.resources, Path.rootname(Path.basename(file))}}
      end)
      |> elem(0)
    end

    @tag rfc: ["3779#2.2.3.5", "3779#3.2.3.3"],
         doc: "ca2 and ca3 inherit, and so does the EE certificate of ca3's ROA."
    test "m6-inherit-two-levels: inheritance two levels deep resolves to ca1's resources" do
      [ca1, ca2, ca3, ee] =
        down("m6-inherit-two-levels", ~w(ta/ca1.cer ca1/ca2.cer ca2/ca3.cer ca3/roa1.roa))

      assert Enum.all?([ca1, ca2, ca3, ee], & &1.valid)
      assert ca1.resources.ipv4 != []
      assert ca1.resources.as != []
      assert ca2.resources == ca1.resources
      assert ca3.resources == ca1.resources
      assert ee.resources.ipv4 == ca1.resources.ipv4
    end

    @tag rfc: ["3779#2.2.3.5", "6487#4.8.10"]
    test "m6-inherit-ee: an EE certificate that inherits holds its CA's addresses" do
      [ca1, ee] = down("m6-inherit-ee", ~w(ta/ca1.cer ca1/roa1.roa))
      assert ee.valid
      assert ee.resources.ipv4 == ca1.resources.ipv4
      assert ee.resources.ipv6 == ca1.resources.ipv6
    end

    @tag rfc: ["3779#2.2.3.5", "9286#5.1"]
    test "m6-inherit-from-empty: inheriting IPv6 from an IPv4-only issuer holds no IPv6, and is valid" do
      [ca1, ca2] = down("m6-inherit-from-empty", ~w(ta/ca1.cer ca1/ca2.cer))
      assert ca1.valid
      assert ca1.resources.ipv6 == []
      assert ca2.valid
      assert ca2.resources == %{ca1.resources | as: ca2.resources.as}
      assert ca2.resources.ipv6 == []
    end

    @tag rfc: ["3779#2.2.3.5", "3779#3.2.3.3"]
    test "m1-resources-inherit: ca2 inherits everything from ca1" do
      [ca1, ca2] = down("m1-resources-inherit", ~w(ta/ca1.cer ca1/ca2.cer))
      assert ca2.valid
      assert ca2.resources == ca1.resources
    end
  end
end
