defmodule Lumina.ProfileCRLTest do
  @moduledoc """
  Tests the CRL profile (`Lumina.Profile.crl/3`, #111): RFC 6487 §5 as
  updated by RFC 9829 §3.1, with the CRL's signature checked against the
  issuing CA's key.

  Every CRL of the positive Barry fixtures must pass, and each `m4-crl-*`
  fixture breaks one rule; `m4-crl-stale` is accepted with a `stale_crl`
  warning (D-016). Cases Barry can't produce (revoked entries, #52) change
  one field of a decoded fixture CRL; the signature covers the unchanged
  `tbs_der`, so it still verifies.

  Fixtures validate at 2030-01-01.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, CRL, Extension, Object, Profile}
  alias Lumina.Test.Fixture
  alias Mix.Lumina.Fixtures

  @at ~U[2030-01-01 00:00:00Z]

  defp decode!(id, file) do
    {:ok, %Object{value: value}} =
      Object.decode_file(Path.join(Fixture.load!(id).rsync_root, file))

    value
  end

  # A fixture's CRLs with their issuers: Barry names a CA's CRL after it
  # (ta/ta.crl is the TA's, ca1/ca1.crl is ca1's).
  defp crls(id) do
    root = Fixture.load!(id).rsync_root

    for path <- Path.wildcard(Path.join(root, "**/*.crl")) do
      file = Path.relative_to(path, root)
      name = Path.basename(path, ".crl")

      issuer =
        if name == "ta",
          do: "ta.cer",
          else:
            root
            |> Path.join("**/#{name}.cer")
            |> Path.wildcard()
            |> hd()
            |> Path.relative_to(root)

      {file, decode!(id, file), decode!(id, issuer)}
    end
  end

  defp ca1_crl(id), do: {decode!(id, "ca1/ca1.crl"), decode!(id, "ta/ca1.cer")}

  defp problems(id) do
    {crl, ca} = ca1_crl(id)
    Profile.crl(crl, ca, @at)
  end

  defp rules({%CRL{} = crl, %Certificate{} = ca}, at \\ @at),
    do: Enum.map(Profile.crl(crl, ca, at), & &1.rule)

  defp m0, do: ca1_crl("m0-minimal-valid")

  # Changes one field of m0's ca1 CRL. The signature covers `tbs_der`,
  # which stays as it is, so it still verifies.
  defp m0_with(changes) do
    {crl, ca} = m0()
    {struct!(crl, changes), ca}
  end

  describe "fixtures" do
    @tag rfc: ["6487#5", "9829#3.1"],
         doc: "Each CRL checked with the certificate of the CA it belongs to."
    test "every CRL of every positive Barry fixture passes" do
      for dir <- Fixtures.case_dirs(),
          id = Path.basename(dir),
          Fixture.load!(id).expected == :valid,
          {file, crl, issuer} <- crls(id) do
        problems = Profile.crl(crl, issuer, @at)

        if id == "m4-crl-stale",
          do: assert(Profile.passes?(problems), "#{id} #{file}"),
          else: assert(problems == [], "#{id} #{file}")
      end
    end

    @tag rfc: "6487#5"
    test "m4-crl-version-1: a version 1 CRL is rejected" do
      assert [%{rule: :crl_version}] = problems("m4-crl-version-1")
    end

    @tag rfc: "9829#3.1",
         doc: "Unlike in certificates (D-013), a non-critical unknown extension rejects a CRL."
    test "m4-crl-extra-extension: a third extension is rejected" do
      assert [%{rule: :crl_extension, field: {:extension, {1, 3, 6, 1, 4, 1, 99_999, 3}}}] =
               problems("m4-crl-extra-extension")
    end

    @tag rfc: "9829#3.1"
    test "m4-crl-number-critical: a critical CRL Number is rejected" do
      assert [%{rule: :critical, field: :crl_number}] = problems("m4-crl-number-critical")
    end

    @tag rfc: "9829#3.1"
    test "m4-crl-number-too-large: a CRL Number of 2^159 is rejected" do
      assert [%{rule: :crl_number_range}] = problems("m4-crl-number-too-large")
    end

    @tag rfc: "9829#3.1"
    test "m4-crl-number-negative: a negative CRL Number is rejected" do
      assert [%{rule: :crl_number_range}] = problems("m4-crl-number-negative")
    end

    @tag rfc: ["9829#3.1", "5280#5.2.1"]
    test "m4-crl-aki-mismatch: an AKI other than the issuer's key identifier is rejected" do
      assert [%{rule: :aki_mismatch}] = problems("m4-crl-aki-mismatch")
    end

    @tag rfc: "6487#5"
    test "m4-crl-issuer-mismatch: a CRL whose issuer isn't the CA's subject is rejected" do
      assert [%{rule: :crl_issuer_mismatch}] = problems("m4-crl-issuer-mismatch")
    end

    @tag rfc: ["6487#7.2", "8017#8.2.2"]
    test "m4-crl-bad-signature: a CRL whose signature doesn't verify is rejected" do
      assert [%{rule: :bad_signature, field: :signature}] = problems("m4-crl-bad-signature")
    end

    @tag rfc: "5280#5.1.2.5", doc: "D-016: a stale CRL is still used."
    test "m4-crl-stale: a CRL past its nextUpdate is accepted with a stale_crl warning" do
      problems = problems("m4-crl-stale")

      assert [%{rule: :stale_crl, severity: :warning}] = problems
      assert Profile.passes?(problems)
    end

    @tag rfc: ["6487#5", "6487#4.4"]
    test "m4-cert-name-extra-attribute: a CRL whose issuer name breaks §4.4 is rejected" do
      assert [%{rule: :name_attribute, field: :issuer, rfc: "6487#5"}] =
               problems("m4-cert-name-extra-attribute")
    end

    @tag rfc: ["9829#3.1", "6487#4.8.3"],
         doc:
           "The AKI is compared with the SHA-1 of the issuer's key, not with its SKI extension."
    test "m1-cert-no-ski: the CRL of a CA without an SKI still matches its AKI" do
      assert problems("m1-cert-no-ski") == []
    end
  end

  describe "dates" do
    @tag rfc: "5280#5.1.2.5"
    test "a CRL is stale only after its nextUpdate" do
      {crl, _ca} = m0 = m0()

      assert rules(m0, crl.next_update.at) == []
      assert rules(m0, DateTime.add(crl.next_update.at, 1)) == [:stale_crl]
    end

    @tag rfc: "5280#5.1.2.4"
    test "a CRL before its thisUpdate is rejected" do
      {crl, _ca} = m0 = m0()

      assert rules(m0, DateTime.add(crl.this_update.at, -1)) == [:crl_not_yet_valid]
    end

    @tag rfc: "5280#5.1.2.5"
    test "a CRL without nextUpdate is rejected" do
      assert rules(m0_with(next_update: nil)) == [:next_update_missing]
    end
  end

  describe "extensions" do
    @tag rfc: "9829#3.1"
    test "a CRL without an AKI or without a CRL Number is rejected" do
      {crl, _ca} = m0()

      for name <- [:authority_key_identifier, :crl_number] do
        extensions = Enum.reject(crl.extensions, &(&1.name == name))

        assert rules(m0_with(extensions: extensions)) == [:missing_extension],
               inspect(name)
      end
    end

    @tag rfc: "5280#4.2"
    test "an extension that appears twice is rejected" do
      {crl, _ca} = m0()
      number = Extension.find(crl.extensions, :crl_number)

      assert rules(m0_with(extensions: crl.extensions ++ [number])) ==
               [:duplicate_extension]
    end

    @tag rfc: "9829#3.1", doc: "0 and 2^159-1 are the bounds RFC 9829 allows."
    test "CRL Numbers 0 and 2^159-1 are accepted" do
      {crl, _ca} = m0()

      for n <- [0, Integer.pow(2, 159) - 1] do
        extensions =
          for e <- crl.extensions, do: if(e.name == :crl_number, do: %{e | value: n}, else: e)

        assert rules(m0_with(extensions: extensions)) == [], inspect(n)
      end
    end
  end

  describe "entries and algorithms" do
    @tag rfc: "6487#5",
         doc: "Barry can't write revoked entries (#52), so the decoded entry list is changed."
    test "a revoked entry with extensions is rejected; one without is accepted" do
      {crl, _ca} = m0()
      reason = %Extension{oid: {2, 5, 29, 21}, name: :reason_code, critical: false, der: <<>>}
      entry = %{serial: 5, revoked_at: crl.this_update, extensions: []}

      assert rules(m0_with(revoked: [entry])) == []

      assert rules(m0_with(revoked: [%{entry | extensions: [reason]}])) ==
               [:entry_extensions]
    end

    @tag rfc: ["5280#5.1.1.2", "7935#2"]
    test "a tbsCertList algorithm unlike the outer one is rejected" do
      sha384 = %{oid: {1, 2, 840, 113_549, 1, 1, 12}, parameters: <<5, 0>>}

      assert rules(m0_with(tbs_signature_algorithm: sha384)) ==
               [:signature_algorithm_mismatch, :unsupported_signature_algorithm]
    end
  end
end
