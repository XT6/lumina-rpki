defmodule Lumina.ChainTest do
  @moduledoc """
  Tests chain validation (`Lumina.Chain`, #112): RFC 6487 §7.2 points 1
  to 5 and 7 (point 5 as RFC 9829 §3.2 updates it), for a TA against its
  TAL and for each certificate against its issuer and the issuer's CRL.

  A small top-down walk over a fixture's files (`validate/1`) stands in
  for the repository walk (#113): it validates the TA, then each
  certificate in the publication point of each valid CA, with the CRL its
  CRLDP names. Every positive Barry fixture must validate to its leaves,
  and each `m4-chain-*` fixture fails at one certificate with its rule;
  certificates under an invalid CA are not validated at all.

  Fixtures validate at 2030-01-01.
  """
  use ExUnit.Case, async: true
  doctest Lumina.Chain

  alias Lumina.{Certificate, Chain, CRL, Object, SignedObject, TAL}
  alias Lumina.Test.Fixture
  alias Mix.Lumina.Fixtures

  @at ~U[2030-01-01 00:00:00Z]

  # Validates fixture `id` from its TAL down, returning
  # %{file => Chain result} for every certificate reached; EE certificates
  # are keyed by their signed object's file.
  defp validate(id, at \\ @at) do
    fixture = Fixture.load!(id)
    {:ok, tal} = TAL.decode_file(fixture.tal_path)
    ta = decode!(fixture, "ta.cer")
    result = Chain.ta(ta, tal, at)
    acc = %{"ta.cer" => result}

    if result.valid,
      do: elem(walk(fixture, {ta, result.resources}, at, {acc, MapSet.new()}), 0),
      else: acc
  end

  # `held`: the CA's effective resources, which its children inherit from.
  defp walk(fixture, {ca, held}, at, {acc, seen}) do
    [repository | _] = Certificate.sia_uris(ca, :ca_repository)
    dir = local(fixture, repository)

    if MapSet.member?(seen, dir) do
      {acc, seen}
    else
      seen = MapSet.put(seen, dir)

      dir
      |> File.ls!()
      |> Enum.sort()
      |> Enum.reject(&String.ends_with?(&1, ".crl"))
      |> Enum.filter(&File.regular?(Path.join(dir, &1)))
      |> Enum.map(&Path.relative_to(Path.join(dir, &1), fixture.rsync_root))
      |> Enum.map(&{&1, certificate(fixture, &1)})
      |> Enum.reject(fn {_file, {cert, _kind}} -> other_issuer?(cert, ca) end)
      |> Enum.reduce({acc, seen}, fn {file, {cert, kind}}, {acc, seen} ->
        result = Chain.child(cert, kind, ca, crl(fixture, cert, ca, at), at, resources: held)
        acc = Map.put(acc, file, result)

        if kind == :ca and result.valid,
          do: walk(fixture, {cert, result.resources}, at, {acc, seen}),
          else: {acc, seen}
      end)
    end
  end

  # A product of another CA sharing the directory (m3-walk-loop puts ca2's
  # manifest in ca1's): both its issuer name and its AKI name someone else.
  # Until manifests say which files a CA published (M5), that is the only
  # way to tell; one mismatch alone is a fault this test must see.
  defp other_issuer?(cert, ca) do
    aki = Certificate.extension_value(cert, :authority_key_identifier)

    cert.issuer_der != ca.subject_der and
      match?(%{key_identifier: kid} when kid != nil, aki) and
      aki.key_identifier != :crypto.hash(:sha, ca.public_key.key)
  end

  defp crl(fixture, cert, issuer, at) do
    crl =
      with uri when is_binary(uri) <- Chain.crl_uri(cert),
           path = local(fixture, uri),
           true <- File.regular?(path),
           {:ok, %Object{value: %CRL{} = crl}} <- Object.decode_file(path) do
        crl
      else
        _ -> nil
      end

    Chain.crl(crl, issuer, at)
  end

  # Where a fixture keeps the file at an rsync URI: localhost:8873's
  # modules, or a directory named after the first label of another host
  # (other.example:8873/repo is other/).
  defp local(fixture, "rsync://" <> rest) do
    [authority, module | path] = String.split(rest, "/")

    base =
      if authority == "localhost:8873",
        do: Map.fetch!(fixture.modules, module),
        else: Path.join(fixture.rsync_root, hd(String.split(authority, ".")))

    Path.join([base | path])
  end

  defp certificate(fixture, file) do
    case decode!(fixture, file) do
      %Certificate{} = cert -> {cert, :ca}
      %{object: %SignedObject{} = object} -> {SignedObject.ee_certificate(object), :ee}
    end
  end

  defp decode!(fixture, file) do
    {:ok, %Object{value: value}} = Object.decode_file(Path.join(fixture.rsync_root, file))
    value
  end

  defp errors(result), do: for(p <- result.problems, p.severity == :error, do: p.rule)

  describe "fixtures" do
    @tag rfc: ["6487#7.2", "9829#3.2", "8630#3"],
         doc: """
         Every certificate reached (TA, CAs, EE certificates of manifests
         and ROAs) is valid. Warnings are allowed: m4-cert-unknown-extension
         (D-013) and m4-crl-stale (D-016).
         """
    test "every positive Barry fixture validates down to its leaves" do
      for dir <- Fixtures.case_dirs(),
          id = Path.basename(dir),
          Fixture.load!(id).expected == :valid do
        results = validate(id)
        assert map_size(results) > 1, id

        for {file, result} <- results,
            do: assert(result.valid, "#{id} #{file}: #{inspect(result.problems)}")
      end
    end

    @tag rfc: ["6487#7.2", "8630#3"]
    test "m4-chain-ta-bad-signature: a TA whose self-signature fails is invalid, and nothing below is validated" do
      assert %{"ta.cer" => result} = validate("m4-chain-ta-bad-signature")
      assert errors(result) == [:bad_signature]
    end

    @tag rfc: "6487#7.2"
    test "m4-chain-ta-expired: an expired TA is invalid" do
      assert %{"ta.cer" => result} = validate("m4-chain-ta-expired")
      assert errors(result) == [:expired]
    end

    @tag rfc: "6487#7.2", doc: "Its own publication point (ca1/) is not validated."
    test "m4-chain-ca-bad-signature: a CA whose signature fails with the TA's key is invalid" do
      results = validate("m4-chain-ca-bad-signature")

      assert errors(results["ta/ca1.cer"]) == [:bad_signature]
      refute Map.has_key?(results, "ca1/ca1.mft")
      assert results["ta/ta.mft"].valid
    end

    @tag rfc: ["6487#7.2", "5280#6.1.3"]
    test "m4-chain-issuer-mismatch: a CA whose issuer isn't the TA's subject is invalid" do
      assert errors(validate("m4-chain-issuer-mismatch")["ta/ca1.cer"]) == [:issuer_mismatch]
    end

    @tag rfc: "6487#4.8.3"
    test "m4-chain-aki-mismatch: a CA whose AKI isn't the TA's key identifier is invalid" do
      assert errors(validate("m4-chain-aki-mismatch")["ta/ca1.cer"]) == [:aki_mismatch]
    end

    @tag rfc: ["6487#7.2", "9829#3.2"]
    test "m4-chain-crl-missing: a CA whose CRLDP names a missing CRL is invalid" do
      results = validate("m4-chain-crl-missing")

      assert errors(results["ta/ca1.cer"]) == [:crl_missing]
    end

    @tag rfc: ["6487#7.2", "9829#3.2"],
         doc: "D-021: Barry writes and signs the revoked entry; nothing is re-signed."
    test "m4-chain-revoked-ca: a revoked CA is invalid and its sibling stays valid" do
      results = validate("m4-chain-revoked-ca")

      assert errors(results["ta/ca1.cer"]) == [:revoked]
      assert results["ta/ca2.cer"].valid
      assert results["ca2/ca2.mft"].valid
      refute Map.has_key?(results, "ca1/ca1.mft")
    end
  end

  describe "CRL results" do
    setup do
      fixture = Fixture.load!("m0-minimal-valid")
      ta = decode!(fixture, "ta.cer")
      ca = decode!(fixture, "ta/ca1.cer")
      %{ta: ta, ca: ca, crl: decode!(fixture, "ta/ta.crl")}
    end

    @tag rfc: "6487#7.2"
    test "an invalid CRL makes its children invalid, naming the CRL's rules", %{
      ta: ta,
      ca: ca,
      crl: crl
    } do
      crl_result = Chain.crl(%{crl | version: 1}, ta, @at)
      refute crl_result.valid

      result = Chain.child(ca, :ca, ta, crl_result, @at)
      assert [%{rule: :crl_invalid, message: message}] = result.problems
      assert message =~ "crl_version"
    end

    @tag rfc: "5280#5.1.2.5", doc: "D-016: the child is valid and keeps the stale_crl warning."
    test "a stale CRL's warning is passed on to its children", %{ta: ta, ca: ca, crl: crl} do
      result = Chain.child(ca, :ca, ta, Chain.crl(crl, ta, ~U[2037-01-01 00:00:00Z]), @at)

      assert result.valid
      assert [%{rule: :stale_crl, severity: :warning}] = result.problems
    end

    @tag rfc: "6487#4.8.6"
    test "crl_uri/1 gives the rsync URI of the CRLDP, and nil for a TA", %{ta: ta, ca: ca} do
      assert Chain.crl_uri(ca) == "rsync://localhost:8873/rpki/ta/ta.crl"
      assert Chain.crl_uri(ta) == nil
    end
  end
end
