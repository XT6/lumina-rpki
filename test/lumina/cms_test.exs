defmodule Lumina.CMSTest do
  @moduledoc """
  Tests the CMS profile of signed objects (#129): `Lumina.CMS.profile/1`
  against RFC 6488 §2.1 and §3 item 1, as updated by RFC 9589 §4, with
  the algorithms of RFC 7935 §2.

  Every signed object of the positive fixtures must pass, and each
  `m5-cms-*` fixture must fail with exactly its one rule. Barry (pinned
  `478ee89`) can't write signed attributes other than its own, unsigned
  attributes, CRLs or SignedData digest algorithms (doc/barry.md), so
  those rules are tested on a decoded m0-minimal-valid ROA changed in
  memory: the profile checks the decoded structure, so nothing needs
  re-encoding.
  """
  use ExUnit.Case, async: true

  alias Lumina.{CMS, Object, SignedObject}
  alias Lumina.Test.Fixture
  alias Mix.Lumina.Fixtures

  @sha1 {1, 3, 14, 3, 2, 26}
  @binary_signing_time {1, 2, 840, 113_549, 1, 9, 16, 2, 46}

  defp signed_object!(path) do
    {:ok, %Object{value: value}} = Object.decode_file(path)

    case value do
      %SignedObject{} = object -> object
      %{object: %SignedObject{} = object} -> object
    end
  end

  defp roa(id \\ "m0-minimal-valid"),
    do: signed_object!(Path.join(Fixture.load!(id).rsync_root, "ca1/roa1.roa"))

  defp rules(object), do: Enum.map(CMS.profile(object), & &1.rule)

  defp with_signer(object, fun) do
    [signer] = object.signers
    %{object | signers: [fun.(signer)]}
  end

  defp with_attrs(object, fun),
    do: with_signer(object, &%{&1 | signed_attrs: fun.(&1.signed_attrs)})

  defp attr(object, name), do: Enum.find(hd(object.signers).signed_attrs, &(&1.name == name))

  describe "fixtures" do
    @tag rfc: ["6488#3", "9589#4", "7935#2"],
         doc: "Manifests and ROAs; Barry writes content-type, signing-time and message-digest."
    test "every signed object of the positive Barry fixtures follows the CMS profile" do
      for dir <- Fixtures.case_dirs(),
          Fixture.load!(Path.basename(dir)).expected == :valid,
          path <- Path.wildcard(Path.join(dir, "rsync/**/*.{mft,roa}")) do
        assert CMS.profile(signed_object!(path)) == [], path
      end
    end

    @tag rfc: ["6488#2.1.1", "6488#3"]
    test "m5-cms-version-1: a SignedData version other than 3 is rejected" do
      assert rules(roa("m5-cms-version-1")) == [:signed_data_version]
    end

    @tag rfc: ["6488#2.1.6.1", "6488#3"]
    test "m5-cms-signer-version-1: a SignerInfo version other than 3 is rejected" do
      assert rules(roa("m5-cms-signer-version-1")) == [:signer_version]
    end

    @tag rfc: ["6488#2.1.6.2", "6488#3"]
    test "m5-cms-sid-issuer-serial: a signer identified by issuer and serial number is rejected" do
      assert rules(roa("m5-cms-sid-issuer-serial")) == [:sid_not_ski]
    end

    @tag rfc: ["6488#2.1.6.2", "6488#3"]
    test "m5-cms-sid-mismatch: a sid that isn't the EE certificate's SKI is rejected" do
      assert rules(roa("m5-cms-sid-mismatch")) == [:sid_mismatch]
    end

    @tag rfc: ["6488#2.1.6.3", "7935#2"]
    test "m5-cms-digest-sha1: a SignerInfo digest algorithm other than SHA-256 is rejected" do
      assert [%{rule: :digest_algorithm, field: :digest_algorithm}] =
               CMS.profile(roa("m5-cms-digest-sha1"))
    end

    @tag rfc: ["6488#2.1.6.5", "7935#2"]
    test "m5-cms-signature-algorithm: sha1WithRSAEncryption as the signature algorithm is rejected" do
      assert rules(roa("m5-cms-signature-algorithm")) == [:signature_algorithm]
    end

    @tag rfc: ["6488#2.1.6.4.1", "6488#3"]
    test "m5-cms-content-type-mismatch: a content-type attribute that isn't the eContentType is rejected" do
      assert rules(roa("m5-cms-content-type-mismatch")) == [:content_type_mismatch]
    end
  end

  describe "SignedData" do
    @tag rfc: ["6488#2.1.2", "6488#3"]
    test "two digest algorithms, or none, are rejected" do
      [sha256] = roa().digest_algorithms

      assert rules(%{roa() | digest_algorithms: [sha256, sha256]}) == [:digest_algorithm_count]
      assert rules(%{roa() | digest_algorithms: []}) == [:digest_algorithm_count]
    end

    @tag rfc: ["6488#2.1.2", "7935#2"]
    test "a SignedData digest algorithm other than SHA-256 is rejected" do
      assert [%{rule: :digest_algorithm, field: :digest_algorithms}] =
               CMS.profile(%{roa() | digest_algorithms: [%{oid: @sha1, parameters: nil}]})
    end

    @tag rfc: ["7935#2", "5754#2"],
         doc:
           "RFC 5754 §2: absent and NULL parameters must both be accepted; anything else isn't."
    test "SHA-256 parameters may be absent or NULL, nothing else" do
      [sha256] = roa().digest_algorithms

      assert rules(%{roa() | digest_algorithms: [%{sha256 | parameters: <<5, 0>>}]}) == []

      assert rules(%{roa() | digest_algorithms: [%{sha256 | parameters: <<4, 0>>}]}) ==
               [:digest_algorithm_parameters]
    end

    @tag rfc: ["6488#2.1.4", "6488#3"]
    test "no certificate, or two, is rejected" do
      [ee] = roa().certificates

      assert :certificate_count in rules(%{roa() | certificates: []})
      assert rules(%{roa() | certificates: [ee, ee]}) == [:certificate_count]
    end

    @tag rfc: ["6488#2.1.5", "6488#3"],
         doc:
           "Decoding keeps an absent crls field as nil and an empty one as [], so both are told apart."
    test "a crls field is rejected, even an empty one" do
      assert rules(%{roa() | crls: []}) == [:crls_present]
    end

    @tag rfc: "6488#2.1.3.2"
    test "an absent eContent is rejected" do
      assert rules(%{roa() | econtent: nil}) == [:no_econtent]
    end

    @tag rfc: ["6488#2.1", "6488#3"]
    test "two SignerInfos are rejected" do
      object = roa()
      assert rules(%{object | signers: object.signers ++ object.signers}) == [:signer_count]
    end
  end

  describe "SignerInfo" do
    @tag rfc: ["6488#2.1.6.5", "7935#2"],
         doc: "RFC 7935 §2: RPs accept either; Barry writes rsaEncryption."
    test "sha256WithRSAEncryption is accepted as the signature algorithm" do
      object =
        with_signer(roa(), fn signer ->
          %{
            signer
            | signature_algorithm: %{oid: {1, 2, 840, 113_549, 1, 1, 11}, parameters: <<5, 0>>}
          }
        end)

      assert rules(object) == []
    end

    @tag rfc: ["6488#2.1.6.7", "6488#3"]
    test "unsigned attributes are rejected" do
      object = with_signer(roa(), &%{&1 | unsigned_attrs: []})
      assert rules(object) == [:unsigned_attrs_present]
    end
  end

  describe "signed attributes" do
    @tag rfc: ["6488#2.1.6.4", "6488#3"]
    test "absent signed attributes are rejected" do
      assert rules(with_attrs(roa(), fn _ -> nil end)) == [:no_signed_attrs]
    end

    @tag rfc: ["9589#4", "6488#3"],
         doc: "RFC 9589 §4 makes signing-time mandatory; RFC 6488 alone allowed leaving it out."
    test "a missing signing-time attribute is rejected" do
      object = with_attrs(roa(), fn attrs -> Enum.reject(attrs, &(&1.name == :signing_time)) end)

      assert [%{rule: :missing_signed_attribute, field: :signing_time, rfc: "9589#4"}] =
               CMS.profile(object)
    end

    @tag rfc: ["6488#2.1.6.4.1", "6488#2.1.6.4.2", "6488#3"]
    test "a missing content-type or message-digest attribute is rejected" do
      for name <- [:content_type, :message_digest] do
        object = with_attrs(roa(), fn attrs -> Enum.reject(attrs, &(&1.name == name)) end)
        assert [%{rule: :missing_signed_attribute, field: ^name}] = CMS.profile(object)
      end
    end

    @tag rfc: ["9589#4", "6488#3"],
         doc: "RFC 9589 §4 removes binary-signing-time from the allowed attributes."
    test "a binary-signing-time attribute is rejected" do
      bst = %{
        oid: @binary_signing_time,
        name: :binary_signing_time,
        values: [{:raw, <<2, 1, 1>>}]
      }

      object = with_attrs(roa(), &(&1 ++ [bst]))

      assert [%{rule: :signed_attribute_not_allowed, rfc: "9589#4"}] = CMS.profile(object)
    end

    @tag rfc: ["6488#2.1.6.4", "6488#3"]
    test "any other attribute is rejected" do
      other = %{oid: {1, 2, 3}, name: nil, values: [{:raw, <<5, 0>>}]}
      object = with_attrs(roa(), &(&1 ++ [other]))

      assert [%{rule: :signed_attribute_not_allowed, field: {:attribute, {1, 2, 3}}}] =
               CMS.profile(object)
    end

    @tag rfc: "6488#2.1.6.4"
    test "an attribute twice, or with two values, is rejected" do
      object = roa()
      time = attr(object, :signing_time)

      assert rules(with_attrs(object, &(&1 ++ [time]))) == [:repeated_signed_attribute]

      twice = %{time | values: time.values ++ time.values}

      assert rules(
               with_attrs(object, fn attrs ->
                 Enum.map(attrs, &if(&1 == time, do: twice, else: &1))
               end)
             ) ==
               [:signed_attribute_values]
    end

    @tag rfc: "6488#2.1.6.4"
    test "an attribute value that doesn't decode is rejected" do
      object = roa()
      time = attr(object, :signing_time)
      broken = %{time | values: [{:malformed, <<4, 0>>}]}

      object =
        with_attrs(object, fn attrs -> Enum.map(attrs, &if(&1 == time, do: broken, else: &1)) end)

      assert rules(object) == [:malformed_signed_attribute]
    end
  end
end
