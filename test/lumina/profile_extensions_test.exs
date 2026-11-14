defmodule Lumina.ProfileExtensionsTest do
  @moduledoc """
  Tests the extension checks of the resource certificate profile
  (`Lumina.Profile.extensions/2`, #110): RFC 6487 §4.8, as updated by
  RFC 7318, for TA, CA and EE certificates.

  Every certificate of the positive Barry fixtures must pass the whole
  profile (`certificate/3`), and each `m4-cert-*` extension fixture, plus
  `m1-cert-no-ski` and `m1-cert-unknown-critical-extension`, breaks one
  rule. `m4-cert-unknown-extension` is valid with one warning (D-013,
  #42). Cases Barry can't produce (it can't set the certificatePolicies
  value, F-030) change one extension of a decoded fixture certificate;
  the profile checks don't verify signatures, so it needn't be re-signed.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, Extension, Object, Profile, SignedObject}
  alias Lumina.Test.Fixture
  alias Mix.Lumina.Fixtures

  @at ~U[2030-01-01 00:00:00Z]

  # A fixture certificate and its kind: the TA, a CA, or the EE
  # certificate of a manifest or ROA.
  defp cert!(id, file) do
    {:ok, %Object{value: value}} =
      Object.decode_file(Path.join(Fixture.load!(id).rsync_root, file))

    case value do
      %Certificate{} when file == "ta.cer" -> {value, :ta}
      %Certificate{} -> {value, :ca}
      %{object: %SignedObject{} = object} -> {SignedObject.ee_certificate(object), :ee}
    end
  end

  defp ta, do: elem(cert!("m0-minimal-valid", "ta.cer"), 0)
  defp ca, do: elem(cert!("m0-minimal-valid", "ta/ca1.cer"), 0)
  defp ee, do: elem(cert!("m0-minimal-valid", "ca1/roa1.roa"), 0)

  defp rules(cert, kind), do: Enum.map(Profile.extensions(cert, kind), & &1.rule)

  defp ca1_problems(id) do
    {cert, :ca} = cert!(id, "ta/ca1.cer")
    Profile.certificate(cert, :ca, @at)
  end

  # Changes the value (or other fields) of extension `name`.
  defp update(cert, name, changes) do
    extensions =
      for ext <- cert.extensions,
          do: if(ext.name == name, do: struct!(ext, changes), else: ext)

    %{cert | extensions: extensions}
  end

  defp drop(cert, name),
    do: %{cert | extensions: Enum.reject(cert.extensions, &(&1.name == name))}

  defp add(cert, %Extension{} = ext), do: %{cert | extensions: cert.extensions ++ [ext]}

  describe "fixtures" do
    @tag rfc: ["6487#4", "6487#4.8"],
         doc: """
         TA, CA and EE certificates (from manifests and ROAs) of every
         fixture expected valid; m4-cert-unknown-extension passes with a
         warning, the others without any problem.
         """
    test "every certificate of every positive Barry fixture passes the whole profile" do
      for dir <- Fixtures.case_dirs(),
          id = Path.basename(dir),
          Fixture.load!(id).expected == :valid,
          path <- Path.wildcard(Path.join(dir, "rsync/**/*.{cer,mft,roa}")) do
        file = Path.relative_to(path, Path.join(dir, "rsync"))
        {cert, kind} = cert!(id, file)
        problems = Profile.certificate(cert, kind, @at)

        if id == "m4-cert-unknown-extension" and file == "ta/ca1.cer",
          do: assert(Profile.passes?(problems), "#{id} #{file}"),
          else: assert(problems == [], "#{id} #{file}")
      end
    end

    @tag rfc: "6487#4.8.2"
    test "m1-cert-no-ski: a certificate without a Subject Key Identifier is rejected" do
      assert [%{rule: :missing_extension, field: :subject_key_identifier}] =
               ca1_problems("m1-cert-no-ski")
    end

    @tag rfc: "6487#4.8"
    test "m1-cert-unknown-critical-extension: an unknown critical extension is rejected" do
      assert [
               %{
                 rule: :unknown_critical_extension,
                 field: {:extension, {1, 3, 6, 1, 4, 1, 99_999, 1}},
                 severity: :error
               }
             ] = ca1_problems("m1-cert-unknown-critical-extension")
    end

    @tag rfc: ["6487#4.8", "5280#4.2"],
         doc: "D-013, #42: accepted, with a warning that names the OID."
    test "m4-cert-unknown-extension: an unknown non-critical extension is accepted with a warning" do
      problems = ca1_problems("m4-cert-unknown-extension")

      assert [%{rule: :unknown_extension, severity: :warning, message: message}] = problems
      assert message =~ "1.3.6.1.4.1.99999.2"
      assert Profile.passes?(problems)
    end

    @tag rfc: "6487#4.8.1"
    test "m4-cert-ca-no-basic-constraints: a CA certificate without Basic Constraints is rejected" do
      assert [%{rule: :missing_extension, field: :basic_constraints}] =
               ca1_problems("m4-cert-ca-no-basic-constraints")
    end

    @tag rfc: "6487#4.8.4"
    test "m4-cert-key-usage-not-critical: a non-critical Key Usage is rejected" do
      assert [%{rule: :not_critical, field: :key_usage}] =
               ca1_problems("m4-cert-key-usage-not-critical")
    end

    @tag rfc: "6487#4.8.5"
    test "m4-cert-ca-eku: an Extended Key Usage in a CA certificate is rejected" do
      assert [%{rule: :extension_present, field: :extended_key_usage}] =
               ca1_problems("m4-cert-ca-eku")
    end

    @tag rfc: "6487#4.8.8.1"
    test "m4-cert-sia-no-manifest: a CA certificate whose SIA has no rpkiManifest is rejected" do
      assert [%{rule: :access_method, field: :subject_info_access, rfc: "6487#4.8.8.1"}] =
               ca1_problems("m4-cert-sia-no-manifest")
    end

    @tag rfc: ["6487#4.8.10", "6487#4.8.11"]
    test "m4-cert-no-resources: a certificate with neither IP nor AS resources is rejected" do
      assert [%{rule: :no_resources}] = ca1_problems("m4-cert-no-resources")
    end
  end

  describe "general rules" do
    @tag rfc: "5280#4.2"
    test "an extension that appears twice is rejected" do
      ca = add(ca(), Extension.find(ca().extensions, :key_usage))

      assert rules(ca, :ca) == [:duplicate_extension]
    end

    @tag rfc: "5280#4.2"
    test "a profile extension whose value doesn't decode is rejected as malformed" do
      ca = update(ca(), :key_usage, value: {:malformed, :test})

      assert rules(ca, :ca) == [:malformed_extension]
    end

    @tag rfc: "6487#4.8",
         doc: "A CRL extension is known to Lumina but has no place in a certificate."
    test "a known extension outside the certificate profile is handled like an unknown one" do
      crl_number = %Extension{
        oid: {2, 5, 29, 20},
        name: :crl_number,
        critical: false,
        der: <<2, 1, 1>>,
        value: 1
      }

      assert [%{rule: :unknown_extension, severity: :warning}] =
               Profile.extensions(add(ca(), crl_number), :ca)

      assert rules(add(ca(), %{crl_number | critical: true}), :ca) == [
               :unknown_critical_extension
             ]
    end
  end

  describe "basic constraints, key identifiers, key usage" do
    @tag rfc: "6487#4.8.1"
    test "an EE certificate with Basic Constraints is rejected" do
      ee = add(ee(), Extension.find(ca().extensions, :basic_constraints))

      assert rules(ee, :ee) == [:extension_present]
    end

    @tag rfc: "6487#4.8.1"
    test "a CA certificate with a path length constraint or without cA is rejected" do
      assert rules(update(ca(), :basic_constraints, value: %{ca: true, path_len: 0}), :ca) ==
               [:path_len_present]

      assert rules(update(ca(), :basic_constraints, value: %{ca: false, path_len: nil}), :ca) ==
               [:not_ca]
    end

    @tag rfc: "6487#4.8.2"
    test "a Subject Key Identifier that isn't the SHA-1 of the key is rejected" do
      assert rules(update(ca(), :subject_key_identifier, value: <<0::160>>), :ca) ==
               [:ski_mismatch]
    end

    @tag rfc: "6487#4.8.3"
    test "a CA certificate without an Authority Key Identifier is rejected; a TA may omit it" do
      assert rules(drop(ca(), :authority_key_identifier), :ca) == [:missing_extension]
      assert rules(drop(ta(), :authority_key_identifier), :ta) == []
    end

    @tag rfc: "6487#4.8.3"
    test "a TA whose Authority Key Identifier differs from its SKI is rejected" do
      aki = %{Extension.find(ca().extensions, :authority_key_identifier) | value: nil}

      ta =
        add(ta(), %{aki | value: %{key_identifier: <<1::160>>, issuer: nil, serial: nil}})

      assert rules(ta, :ta) == [:aki_mismatch]
    end

    @tag rfc: "6487#4.8.3"
    test "an Authority Key Identifier with authorityCertSerialNumber is rejected" do
      ca =
        update(ca(), :authority_key_identifier,
          value: %{
            Certificate.extension_value(ca(), :authority_key_identifier)
            | serial: 1
          }
        )

      assert rules(ca, :ca) == [:aki_issuer_fields]
    end

    @tag rfc: "6487#4.8.4"
    test "Key Usage bits other than the kind's are rejected" do
      assert rules(update(ca(), :key_usage, value: [:keyCertSign]), :ca) == [:key_usage_bits]

      assert rules(update(ee(), :key_usage, value: [:digitalSignature, :nonRepudiation]), :ee) ==
               [:key_usage_bits]

      assert rules(update(ee(), :key_usage, value: [:keyCertSign, :cRLSign]), :ee) ==
               [:key_usage_bits]
    end

    @tag rfc: "6487#4.8.5",
         doc: "A well-formed EKU (id-kp-bgpsec-router) on the EE certificate of a ROA."
    test "an Extended Key Usage in the EE certificate of a signed object is rejected" do
      eku = %Extension{
        oid: {2, 5, 29, 37},
        name: :extended_key_usage,
        critical: false,
        der: <<>>,
        value: [{1, 3, 6, 1, 5, 5, 7, 3, 30}]
      }

      assert rules(add(ee(), eku), :ee) == [:extension_present]
    end
  end

  describe "CRLDP, AIA and SIA" do
    @tag rfc: ["6487#4.8.6", "6487#4.8.7"]
    test "a self-signed certificate with a CRLDP or an AIA is rejected" do
      cdp = Extension.find(ca().extensions, :crl_distribution_points)
      aia = Extension.find(ca().extensions, :authority_info_access)

      assert rules(add(ta(), cdp), :ta) == [:extension_present]
      assert rules(add(ta(), aia), :ta) == [:extension_present]
    end

    @tag rfc: ["6487#4.8.6", "6487#4.8.7"]
    test "a CA certificate without a CRLDP or an AIA is rejected" do
      assert rules(drop(ca(), :crl_distribution_points), :ca) == [:missing_extension]
      assert rules(drop(ca(), :authority_info_access), :ca) == [:missing_extension]
    end

    @tag rfc: "6487#4.8.6"
    test "a CRLDP with two DistributionPoints, a cRLIssuer or no rsync URI is rejected" do
      point = %{full_name: [uri: "rsync://a.example/x.crl"], reasons: nil, crl_issuer: nil}

      for value <- [
            [point, point],
            [%{point | crl_issuer: [uri: "rsync://a.example/"]}],
            [%{point | full_name: [uri: "https://a.example/x.crl"]}],
            [%{point | full_name: {:nameRelativeToCRLIssuer, []}}]
          ] do
        assert rules(update(ca(), :crl_distribution_points, value: value), :ca) ==
                 [:crl_distribution_point],
               inspect(value)
      end
    end

    @tag rfc: "6487#4.8.7"
    test "an AIA without an rsync caIssuers URI is rejected" do
      value = [%{method: :ca_issuers, location: {:uri, "https://a.example/ta.cer"}}]

      assert rules(update(ca(), :authority_info_access, value: value), :ca) == [:access_method]
    end

    @tag rfc: "6487#4.8.8.2"
    test "an EE certificate's SIA with an access method other than signedObject is rejected" do
      value =
        Certificate.extension_value(ee(), :subject_info_access) ++
          [%{method: :ca_repository, location: {:uri, "rsync://a.example/repo/"}}]

      assert [%{rule: :access_method, rfc: "6487#4.8.8.2"}] =
               Profile.extensions(update(ee(), :subject_info_access, value: value), :ee)
    end

    @tag rfc: "6487#4.8.8.1"
    test "a CA certificate's SIA without an rsync caRepository is rejected" do
      value =
        for %{method: m} = d <- Certificate.extension_value(ca(), :subject_info_access),
            m != :ca_repository,
            do: d

      assert rules(update(ca(), :subject_info_access, value: value), :ca) == [:access_method]
    end

    @tag rfc: "6487#4.8.8.1"
    test "a critical SIA is rejected" do
      assert rules(update(ca(), :subject_info_access, critical: true), :ca) == [:critical]
    end
  end

  describe "certificate policies (RFC 7318)" do
    @tag rfc: "6487#4.8.9", doc: "F-030: Barry can't write this, so the decoded value is changed."
    test "a policy other than the RPKI CP is rejected" do
      value = [%{oid: {1, 2, 3, 4}, qualifiers: []}]

      assert rules(update(ca(), :certificate_policies, value: value), :ca) == [:policy]
    end

    @tag rfc: "6487#4.8.9",
         doc: "RFC 8360's policy needs the v2 resource extensions, which Lumina doesn't support."
    test "the RFC 8360 policy is rejected as unsupported" do
      value = [%{oid: {1, 3, 6, 1, 5, 5, 7, 14, 3}, qualifiers: []}]

      assert [%{rule: :policy, message: message}] =
               Profile.extensions(update(ca(), :certificate_policies, value: value), :ca)

      assert message =~ "RFC 8360"
    end

    @tag rfc: "6487#4.8.9"
    test "two policies are rejected" do
      [policy] = Certificate.extension_value(ca(), :certificate_policies)

      assert rules(update(ca(), :certificate_policies, value: [policy, policy]), :ca) == [:policy]
    end

    @tag rfc: "7318#2"
    test "one CPS pointer qualifier is accepted, any other qualifier is rejected" do
      [policy] = Certificate.extension_value(ca(), :certificate_policies)
      cps = %{policyQualifierId: {1, 3, 6, 1, 5, 5, 7, 2, 1}, qualifier: "https://a.example/cps"}
      notice = %{cps | policyQualifierId: {1, 3, 6, 1, 5, 5, 7, 2, 2}}

      with_qualifiers = &update(ca(), :certificate_policies, value: [%{policy | qualifiers: &1}])

      assert rules(with_qualifiers.([cps]), :ca) == []
      assert rules(with_qualifiers.([notice]), :ca) == [:policy_qualifier]
      assert rules(with_qualifiers.([cps, cps]), :ca) == [:policy_qualifier]
    end

    @tag rfc: "6487#4.8.9"
    test "non-critical certificate policies are rejected" do
      assert rules(update(ca(), :certificate_policies, critical: false), :ca) == [:not_critical]
    end
  end

  describe "resources" do
    @tag rfc: "6487#4.8.10"
    test "IP resources with a SAFI are rejected" do
      [v4 | rest] = Certificate.extension_value(ca(), :ip_resources)

      assert :safi in rules(update(ca(), :ip_resources, value: [%{v4 | safi: 1} | rest]), :ca)
    end

    @tag rfc: "6487#4.8.11"
    test "AS resources with RDIs are rejected" do
      as = Certificate.extension_value(ca(), :as_resources)

      assert rules(update(ca(), :as_resources, value: %{as | rdi: [{:id, 1}]}), :ca) == [:rdi]
    end

    @tag rfc: ["6487#4.8.10", "6487#4.8.11"]
    test "an empty resource set is rejected, and inherit is accepted" do
      as = Certificate.extension_value(ca(), :as_resources)

      assert rules(update(ca(), :as_resources, value: %{as | asnum: []}), :ca) ==
               [:empty_resources]

      assert rules(update(ca(), :as_resources, value: %{as | asnum: :inherit}), :ca) == []
    end

    @tag rfc: ["6487#4.8.10", "6487#4.8.11"]
    test "non-critical resource extensions are rejected" do
      assert rules(update(ca(), :ip_resources, critical: false), :ca) == [:not_critical]
      assert rules(update(ca(), :as_resources, critical: false), :ca) == [:not_critical]
    end

    @tag rfc: "6487#4.8.10", doc: "An EE certificate of a ROA carries IP resources only."
    test "one resource extension is enough" do
      assert rules(drop(ca(), :as_resources), :ca) == []
    end
  end
end
