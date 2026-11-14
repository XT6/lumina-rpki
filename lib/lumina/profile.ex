defmodule Lumina.Profile do
  @moduledoc """
  Checks resource certificates against the RPKI profile (RFC 6487 §4).

    * `basic_fields/2` checks RFC 6487 §4.1 to §4.7 (#109): version,
      serial number, signature algorithm, issuer and subject names,
      validity at a given time, unique identifiers and the public key. These
      rules are the same for every kind of certificate.
    * `extensions/2` checks RFC 6487 §4.8 (#110) for a kind of certificate:
      `:ta` (self-signed, from a TAL), `:ca` or `:ee` (the EE certificate
      of a signed object).
    * `certificate/3` does both.
    * `crl/3` checks a CRL against RFC 6487 §5 as updated by RFC 9829 (#111),
      including its signature, with the certificate of the CA that issued
      it.

  The result is a list of problems, each with a `rule`, the `rfc` section,
  the `field` it concerns (a field name, an extension name, or
  `{:extension, oid}` for one Lumina doesn't know), a `message` and a
  `severity`. A certificate passes when no problem has severity `:error`;
  `:warning`s are reported but don't reject it (D-013, D-018).

  The validation time is always an argument, never "now", so fixtures
  validate at a fixed time. Checks that need another certificate (the
  AKI against the issuer's SKI, resources within the issuer's) belong to
  chain validation (#112) and resource validation (M6).
  """

  alias Lumina.{Certificate, CRL, Crypto, DER, Extension, OID, Resources}

  @type kind :: :ta | :ca | :ee
  @type problem :: %{
          rule: atom(),
          rfc: String.t(),
          field: atom() | {:extension, tuple()},
          message: String.t(),
          severity: :error | :warning
        }

  @sha256_with_rsa {1, 2, 840, 113_549, 1, 1, 11}
  @null <<5, 0>>

  @common_name {2, 5, 4, 3}
  @serial_number {2, 5, 4, 5}
  @printable_string 0x13

  # RFC 6484 §1.2 (cited by RFC 6487 §4.8.9) and RFC 7318 §2.
  @rpki_policy {1, 3, 6, 1, 5, 5, 7, 14, 2}
  @rpki_policy_v2 {1, 3, 6, 1, 5, 5, 7, 14, 3}
  @cps_qualifier {1, 3, 6, 1, 5, 5, 7, 2, 1}

  # The extensions of the certificate profile (RFC 6487 §4.8).
  @profile_extensions [
    :basic_constraints,
    :subject_key_identifier,
    :authority_key_identifier,
    :key_usage,
    :extended_key_usage,
    :crl_distribution_points,
    :authority_info_access,
    :subject_info_access,
    :certificate_policies,
    :ip_resources,
    :as_resources
  ]

  @doc """
  The problems of `cert` as a certificate of `kind`: `basic_fields/2` at
  time `at`, then `extensions/2`.
  """
  @spec certificate(Certificate.t(), kind(), DateTime.t()) :: [problem()]
  def certificate(%Certificate{} = cert, kind, %DateTime{} = at),
    do: basic_fields(cert, at) ++ extensions(cert, kind)

  @doc """
  The problems of `cert`'s basic fields (RFC 6487 §4.1 to §4.7) at time
  `at`.
  """
  @spec basic_fields(Certificate.t(), DateTime.t()) :: [problem()]
  def basic_fields(%Certificate{} = cert, %DateTime{} = at) do
    Enum.concat([
      version(cert),
      serial(cert),
      signature_algorithm(cert),
      name(cert, :issuer, "6487#4.4"),
      name(cert, :subject, "6487#4.5"),
      validity(cert, at),
      unique_ids(cert),
      public_key(cert)
    ])
  end

  @doc """
  The problems of `cert`'s extensions (RFC 6487 §4.8, RFC 7318) as a
  certificate of `kind`.
  """
  @spec extensions(Certificate.t(), kind()) :: [problem()]
  def extensions(%Certificate{extensions: extensions} = cert, kind)
      when kind in [:ta, :ca, :ee] do
    by_name = Map.new(for %Extension{name: name} = e <- extensions, name != nil, do: {name, e})

    Enum.concat([
      duplicates(extensions),
      outside_profile(extensions),
      malformed(extensions),
      basic_constraints(by_name[:basic_constraints], kind),
      subject_key_identifier(by_name[:subject_key_identifier], cert),
      authority_key_identifier(by_name[:authority_key_identifier], cert, kind),
      key_usage(by_name[:key_usage], kind),
      extended_key_usage(by_name[:extended_key_usage]),
      crl_distribution_points(by_name[:crl_distribution_points], kind),
      authority_info_access(by_name[:authority_info_access], kind),
      subject_info_access(by_name[:subject_info_access], kind),
      certificate_policies(by_name[:certificate_policies]),
      resources(by_name[:ip_resources], by_name[:as_resources])
    ])
  end

  @doc """
  The problems of `crl`, issued by the CA certificate `issuer`, at time
  `at` (RFC 6487 §5, RFC 9829 §3.1).

  A CRL past its nextUpdate is still used, with a `:stale_crl` warning
  (D-016). Which CRL decides revocation (the CRLDP target, and in M5 the
  one on the issuer's manifest, D-015) is for the caller.
  """
  @spec crl(CRL.t(), Certificate.t(), DateTime.t()) :: [problem()]
  def crl(%CRL{} = crl, %Certificate{} = issuer, %DateTime{} = at) do
    Enum.concat([
      crl_version(crl),
      crl_signature_algorithm(crl),
      crl_issuer(crl, issuer),
      name(crl, :issuer, "6487#5"),
      crl_dates(crl, at),
      crl_extensions(crl, issuer),
      crl_entries(crl),
      crl_signature(crl, issuer)
    ])
  end

  @doc "Whether `problems` holds no `:error`."
  @spec passes?([problem()]) :: boolean()
  def passes?(problems), do: not Enum.any?(problems, &(&1.severity == :error))

  # §4.1, and F-015: earlier versions are rejected, not processed.
  defp version(%{version: 3}), do: []

  defp version(%{version: v}),
    do: [error(:version, "6487#4.1", :version, "version is #{v}; resource certificates are v3")]

  # §4.2 and RFC 5280 §4.1.2.2.
  defp serial(%{serial: serial}) when serial <= 0,
    do: [
      error(
        :serial_not_positive,
        "6487#4.2",
        :serial,
        "serial number is #{serial}; it must be positive"
      )
    ]

  defp serial(%{serial: serial}) do
    case integer_octets(serial) do
      octets when octets > 20 ->
        [
          error(
            :serial_too_long,
            "5280#4.1.2.2",
            :serial,
            "serial number is #{octets} octets; at most 20 are allowed"
          )
        ]

      _ ->
        []
    end
  end

  # The length of a positive INTEGER's DER contents: a leading zero octet
  # when the top bit is set.
  defp integer_octets(n), do: div(bit_length(n, 0), 8) + 1

  defp bit_length(0, count), do: count
  defp bit_length(n, count), do: bit_length(Bitwise.bsr(n, 1), count + 1)

  # §4.3 (via RFC 7935 §2), and RFC 5280 §4.1.1.2: the algorithm inside
  # tbsCertificate is the outer one.
  defp signature_algorithm(%{tbs_signature_algorithm: inner, signature_algorithm: outer}) do
    mismatch =
      if inner != outer,
        do: [
          error(
            :signature_algorithm_mismatch,
            "5280#4.1.1.2",
            :tbs_signature_algorithm,
            "the tbsCertificate signature algorithm (#{OID.format(inner.oid)}) " <>
              "is not the outer one (#{OID.format(outer.oid)})"
          )
        ],
        else: []

    unsupported =
      case Crypto.check_signature_algorithm(inner) do
        :ok -> []
        {:error, p} -> [error(p.rule, p.rfc, :tbs_signature_algorithm, p.message)]
      end

    mismatch ++ unsupported
  end

  # §4.4 and §4.5: one commonName, a PrintableString, and at most one
  # serialNumber; nothing else.
  defp name(cert, field, rfc) do
    attributes = attributes(Map.fetch!(cert, field), Map.fetch!(cert, :"#{field}_der"))
    types = Enum.map(attributes, &elem(&1, 0))
    common_names = Enum.filter(attributes, &(elem(&1, 0) == @common_name))

    others =
      for type <- Enum.uniq(types), type not in [@common_name, @serial_number] do
        error(
          :name_attribute,
          rfc,
          field,
          "the #{field} holds #{OID.format(type)}; only commonName and serialNumber are allowed"
        )
      end

    common_name =
      case common_names do
        [{_, @printable_string}] ->
          []

        [_] ->
          [
            error(
              :common_name_encoding,
              rfc,
              field,
              "the #{field} commonName is not a PrintableString"
            )
          ]

        list ->
          [
            error(
              :common_name_count,
              rfc,
              field,
              "the #{field} holds #{length(list)} commonNames; it needs exactly one"
            )
          ]
      end

    serial_numbers =
      case Enum.count(types, &(&1 == @serial_number)) do
        n when n > 1 ->
          [
            error(
              :serial_number_count,
              rfc,
              field,
              "the #{field} holds #{n} serialNumbers; at most one is allowed"
            )
          ]

        _ ->
          []
      end

    others ++ common_name ++ serial_numbers
  end

  # Each attribute of a name as {type, tag of its value}: the types from
  # the decoded name, the tags from its DER, in the same order. The name
  # was decoded with its certificate, so its structure is known to be valid.
  defp attributes(name, name_der) do
    {:ok, rdns} = DER.children(name_der)

    tags =
      for rdn <- rdns,
          {:ok, atvs} = DER.children(rdn),
          atv <- atvs,
          {:ok, [_type, <<tag, _::binary>>]} = DER.children(atv),
          do: tag

    Enum.zip(Enum.map(List.flatten(name), & &1.type), tags)
  end

  # §7.2 point 2: the validation time lies within notBefore..notAfter.
  defp validity(%{not_before: not_before, not_after: not_after}, at) do
    cond do
      DateTime.compare(at, not_before.at) == :lt ->
        [
          error(
            :not_yet_valid,
            "6487#7.2",
            :validity,
            "not yet valid: notBefore is #{DateTime.to_iso8601(not_before.at)}"
          )
        ]

      DateTime.compare(at, not_after.at) == :gt ->
        [
          error(
            :expired,
            "6487#7.2",
            :validity,
            "expired: notAfter is #{DateTime.to_iso8601(not_after.at)}"
          )
        ]

      true ->
        []
    end
  end

  # §4: fields the profile doesn't list MUST NOT appear.
  defp unique_ids(cert) do
    for field <- [:issuer_unique_id, :subject_unique_id], Map.fetch!(cert, field) != nil do
      error(
        :unique_id,
        "6487#4",
        field,
        "#{field} is present; the profile has no unique identifiers"
      )
    end
  end

  # §4.7 (via RFC 7935 §3 and §3.1) and D-018.
  defp public_key(%{public_key: key}) do
    warning =
      case key.algorithm do
        %{oid: @sha256_with_rsa, parameters: params} when params in [nil, @null] ->
          [
            warning(
              :key_algorithm_sha256_with_rsa,
              "7935#3.1",
              :public_key,
              "the key algorithm is sha256WithRSAEncryption; RPKI keys use rsaEncryption (F-027)"
            )
          ]

        _ ->
          []
      end

    case Crypto.check_rsa_key(key) do
      {:ok, _} -> warning
      {:error, p} -> [error(p.rule, p.rfc, :public_key, p.message)]
    end
  end

  # Extensions (RFC 6487 §4.8).

  # RFC 5280 §4.2: at most one instance of each extension.
  defp duplicates(extensions) do
    for {_oid, [ext, _ | _] = list} <- Enum.group_by(extensions, & &1.oid) do
      error(
        :duplicate_extension,
        "5280#4.2",
        field(ext),
        "#{label(ext)} appears #{length(list)} times; at most once is allowed"
      )
    end
  end

  # §4.8: an unrecognized critical extension rejects the certificate; a
  # non-critical one is accepted with a warning (D-013). Extensions Lumina
  # knows from CRLs, which have no meaning in a certificate, count as
  # unrecognized here.
  defp outside_profile(extensions) do
    for %Extension{name: name} = ext <- extensions, name not in @profile_extensions do
      if ext.critical do
        error(
          :unknown_critical_extension,
          "6487#4.8",
          field(ext),
          "#{label(ext)} is critical and not part of the RPKI profile"
        )
      else
        warning(
          :unknown_extension,
          "6487#4.8",
          field(ext),
          "#{label(ext)} is not part of the RPKI profile; ignored (D-013)"
        )
      end
    end
  end

  defp malformed(extensions) do
    for %Extension{name: name, value: {:malformed, reason}} = ext <- extensions,
        name in @profile_extensions do
      error(
        :malformed_extension,
        "5280#4.2",
        name,
        "#{label(ext)} doesn't decode: #{inspect(reason)}"
      )
    end
  end

  defp field(%Extension{name: nil, oid: oid}), do: {:extension, oid}
  defp field(%Extension{name: name}), do: name

  defp label(%Extension{name: nil, oid: oid}), do: "extension #{OID.dotted(oid)}"
  defp label(%Extension{name: name, oid: oid}), do: "#{name} (#{OID.dotted(oid)})"

  # The checks below see a malformed extension as present, but don't read
  # its value: malformed/1 reports it.
  defp decoded?(%Extension{value: {:malformed, _}}), do: false
  defp decoded?(%Extension{}), do: true

  defp criticality(%Extension{critical: critical} = ext, expected, rfc) do
    cond do
      critical == expected ->
        []

      expected ->
        [error(:not_critical, rfc, ext.name, "#{label(ext)} must be critical")]

      true ->
        [error(:critical, rfc, ext.name, "#{label(ext)} must not be critical")]
    end
  end

  defp missing(name, rfc, why),
    do: [error(:missing_extension, rfc, name, "#{name} is missing; #{why}")]

  defp present(%Extension{} = ext, rfc, why),
    do: [error(:extension_present, rfc, ext.name, "#{label(ext)} must not be present #{why}")]

  # §4.8.1.
  defp basic_constraints(nil, :ee), do: []

  defp basic_constraints(nil, _ca),
    do: missing(:basic_constraints, "6487#4.8.1", "a CA certificate needs it")

  defp basic_constraints(ext, :ee), do: present(ext, "6487#4.8.1", "in an EE certificate")

  defp basic_constraints(ext, _ca) do
    criticality(ext, true, "6487#4.8.1") ++
      if decoded?(ext) do
        [
          if(ext.value.ca != true,
            do: error(:not_ca, "6487#4.8.1", :basic_constraints, "cA is not set")
          ),
          if(ext.value.path_len != nil,
            do:
              error(
                :path_len_present,
                "6487#4.8.1",
                :basic_constraints,
                "pathLenConstraint must not be present"
              )
          )
        ]
        |> Enum.reject(&is_nil/1)
      else
        []
      end
  end

  # §4.8.2: present, non-critical, the SHA-1 of the subjectPublicKey bits.
  defp subject_key_identifier(nil, _cert),
    do: missing(:subject_key_identifier, "6487#4.8.2", "every resource certificate needs it")

  defp subject_key_identifier(ext, cert) do
    criticality(ext, false, "6487#4.8.2") ++
      if decoded?(ext) and is_binary(cert.public_key.key) and
           ext.value != :crypto.hash(:sha, cert.public_key.key) do
        [
          error(
            :ski_mismatch,
            "6487#4.8.2",
            :subject_key_identifier,
            "the key identifier is not the SHA-1 hash of the subject public key"
          )
        ]
      else
        []
      end
  end

  # §4.8.3: present except in a self-signed certificate, where it may be
  # present and equal to the SKI; key identifier only; non-critical.
  defp authority_key_identifier(nil, _cert, :ta), do: []

  defp authority_key_identifier(nil, _cert, _kind),
    do:
      missing(
        :authority_key_identifier,
        "6487#4.8.3",
        "only a self-signed certificate may omit it"
      )

  defp authority_key_identifier(ext, cert, kind) do
    criticality(ext, false, "6487#4.8.3") ++
      if decoded?(ext) do
        ski = Certificate.extension_value(cert, :subject_key_identifier)

        [
          if(ext.value.key_identifier == nil,
            do:
              error(
                :aki_key_identifier,
                "6487#4.8.3",
                :authority_key_identifier,
                "keyIdentifier is missing"
              )
          ),
          if(ext.value.issuer != nil or ext.value.serial != nil,
            do:
              error(
                :aki_issuer_fields,
                "6487#4.8.3",
                :authority_key_identifier,
                "authorityCertIssuer and authorityCertSerialNumber must not be present"
              )
          ),
          if(kind == :ta and ext.value.key_identifier != nil and ext.value.key_identifier != ski,
            do:
              error(
                :aki_mismatch,
                "6487#4.8.3",
                :authority_key_identifier,
                "in a self-signed certificate the AKI must equal the SKI"
              )
          )
        ]
        |> Enum.reject(&is_nil/1)
      else
        []
      end
  end

  # §4.8.4: critical; exactly keyCertSign and cRLSign for a CA, exactly
  # digitalSignature for an EE.
  defp key_usage(nil, _kind), do: missing(:key_usage, "6487#4.8.4", "it must be present")

  defp key_usage(ext, kind) do
    expected = if kind == :ee, do: [:digitalSignature], else: [:cRLSign, :keyCertSign]

    criticality(ext, true, "6487#4.8.4") ++
      if decoded?(ext) and Enum.sort(ext.value) != expected do
        [
          error(
            :key_usage_bits,
            "6487#4.8.4",
            :key_usage,
            "the bits set are #{inspect(ext.value)}; #{kind} certificates need exactly " <>
              inspect(expected)
          )
        ]
      else
        []
      end
  end

  # §4.8.5: never in a CA certificate, nor in an EE certificate of an RPKI
  # signed object (the only EE kind here; router certificates are not).
  defp extended_key_usage(nil), do: []

  defp extended_key_usage(ext),
    do: present(ext, "6487#4.8.5", "in CA certificates or EE certificates of RPKI objects")

  # §4.8.6: absent in a self-signed certificate; otherwise non-critical,
  # one DistributionPoint with a fullName of URIs, one of them rsync, no
  # reasons and no cRLIssuer.
  defp crl_distribution_points(nil, :ta), do: []

  defp crl_distribution_points(nil, _kind),
    do: missing(:crl_distribution_points, "6487#4.8.6", "only a self-signed certificate omits it")

  defp crl_distribution_points(ext, :ta),
    do: present(ext, "6487#4.8.6", "in a self-signed certificate")

  defp crl_distribution_points(ext, _kind) do
    criticality(ext, false, "6487#4.8.6") ++
      if decoded?(ext), do: distribution_point(ext.value), else: []
  end

  defp distribution_point([%{reasons: nil, crl_issuer: nil, full_name: names}])
       when is_list(names) do
    cond do
      not Enum.all?(names, &match?({:uri, _}, &1)) ->
        [crldp_error("the distributionPoint names must all be URIs")]

      not Enum.any?(names, &rsync?/1) ->
        [crldp_error("no rsync URI for the CRL")]

      true ->
        []
    end
  end

  defp distribution_point([%{reasons: nil, crl_issuer: nil}]),
    do: [crldp_error("the distributionPoint must be a fullName")]

  defp distribution_point([_point]),
    do: [crldp_error("reasons and cRLIssuer must be omitted")]

  defp distribution_point(points),
    do: [crldp_error("#{length(points)} DistributionPoints; exactly one is allowed")]

  defp crldp_error(message),
    do: error(:crl_distribution_point, "6487#4.8.6", :crl_distribution_points, message)

  # §4.8.7: absent in a self-signed certificate; otherwise non-critical,
  # with an rsync URI for id-ad-caIssuers.
  defp authority_info_access(nil, :ta), do: []

  defp authority_info_access(nil, _kind),
    do: missing(:authority_info_access, "6487#4.8.7", "only a self-signed certificate omits it")

  defp authority_info_access(ext, :ta),
    do: present(ext, "6487#4.8.7", "in a self-signed certificate")

  defp authority_info_access(ext, _kind) do
    criticality(ext, false, "6487#4.8.7") ++
      if decoded?(ext) and not Enum.any?(Extension.access_uris(ext.value, :ca_issuers), &rsync?/1) do
        [
          error(
            :access_method,
            "6487#4.8.7",
            :authority_info_access,
            "no id-ad-caIssuers rsync URI"
          )
        ]
      else
        []
      end
  end

  # §4.8.8: non-critical; a CA's names an rsync caRepository and an rsync
  # rpkiManifest, an EE's an rsync signedObject and nothing else.
  defp subject_info_access(nil, _kind),
    do: missing(:subject_info_access, "6487#4.8.8", "every resource certificate needs it")

  defp subject_info_access(ext, kind) do
    rfc = if kind == :ee, do: "6487#4.8.8.2", else: "6487#4.8.8.1"

    criticality(ext, false, rfc) ++
      if(decoded?(ext), do: sia_methods(ext.value, kind, rfc), else: [])
  end

  defp sia_methods(descriptions, :ee, rfc) do
    others = for %{method: m} <- descriptions, m != :signed_object, uniq: true, do: m

    Enum.concat([
      required_rsync(descriptions, :signed_object, rfc),
      for(
        m <- others,
        do:
          error(
            :access_method,
            rfc,
            :subject_info_access,
            "#{format_method(m)} must not appear in an EE certificate's SIA"
          )
      )
    ])
  end

  defp sia_methods(descriptions, _ca, rfc),
    do:
      required_rsync(descriptions, :ca_repository, rfc) ++
        required_rsync(descriptions, :rpki_manifest, rfc)

  defp required_rsync(descriptions, method, rfc) do
    if Enum.any?(Extension.access_uris(descriptions, method), &rsync?/1),
      do: [],
      else: [error(:access_method, rfc, :subject_info_access, "no #{method} rsync URI")]
  end

  defp format_method(m) when is_atom(m), do: to_string(m)
  defp format_method(oid), do: OID.dotted(oid)

  defp rsync?({:uri, uri}), do: rsync?(uri)
  defp rsync?("rsync://" <> _), do: true
  defp rsync?(_other), do: false

  # §4.8.9 as updated by RFC 7318 §2: critical, exactly one policy, the
  # RPKI CP, with at most one qualifier, a CPS pointer.
  defp certificate_policies(nil),
    do: missing(:certificate_policies, "6487#4.8.9", "every resource certificate needs it")

  defp certificate_policies(ext) do
    criticality(ext, true, "6487#4.8.9") ++ if(decoded?(ext), do: policy(ext.value), else: [])
  end

  defp policy([%{oid: @rpki_policy, qualifiers: qualifiers}]) do
    case qualifiers do
      [] ->
        []

      [%{policyQualifierId: @cps_qualifier}] ->
        []

      [%{policyQualifierId: oid}] ->
        [
          error(
            :policy_qualifier,
            "7318#2",
            :certificate_policies,
            "the policy qualifier is #{OID.format(oid)}; only id-qt-cps is allowed"
          )
        ]

      list ->
        [
          error(
            :policy_qualifier,
            "7318#2",
            :certificate_policies,
            "#{length(list)} policy qualifiers; at most one is allowed"
          )
        ]
    end
  end

  defp policy([%{oid: @rpki_policy_v2}]),
    do: [
      error(
        :policy,
        "6487#4.8.9",
        :certificate_policies,
        "the policy is id-cp-ipAddr-asNumber-v2 (RFC 8360), which Lumina doesn't support"
      )
    ]

  defp policy([%{oid: oid}]),
    do: [
      error(
        :policy,
        "6487#4.8.9",
        :certificate_policies,
        "the policy is #{OID.format(oid)}; the RPKI CP is id-cp-ipAddr-asNumber"
      )
    ]

  defp policy(policies),
    do: [
      error(
        :policy,
        "6487#4.8.9",
        :certificate_policies,
        "#{length(policies)} policies; exactly one is allowed"
      )
    ]

  # §4.8.10 and §4.8.11: at least one of the two, each critical, non-empty
  # or inherit, no SAFI and no RDI, in RFC 3779 canonical form.
  defp resources(nil, nil),
    do: [
      error(
        :no_resources,
        "6487#4.8.10",
        :ip_resources,
        "neither IP nor AS resources are present; at least one is required"
      )
    ]

  defp resources(ip, as), do: ip_resources(ip) ++ as_resources(as)

  defp ip_resources(nil), do: []

  defp ip_resources(ext) do
    criticality(ext, true, "6487#4.8.10") ++
      if decoded?(ext) do
        Enum.concat([
          if(ext.value == [] or Enum.any?(ext.value, &(&1.resources == [])),
            do: [
              error(
                :empty_resources,
                "6487#4.8.10",
                :ip_resources,
                "an empty set of IP resources"
              )
            ],
            else: []
          ),
          if(Enum.any?(ext.value, &(&1.safi != nil)),
            do: [error(:safi, "6487#4.8.10", :ip_resources, "SAFI must not be used")],
            else: []
          ),
          for(
            i <- Resources.ip_issues(ext.value),
            do: error(i.rule, i.rfc, :ip_resources, i.message)
          )
        ])
      else
        []
      end
  end

  defp as_resources(nil), do: []

  defp as_resources(ext) do
    criticality(ext, true, "6487#4.8.11") ++
      if decoded?(ext) do
        Enum.concat([
          if(ext.value.asnum in [nil, []],
            do: [
              error(:empty_resources, "6487#4.8.11", :as_resources, "an empty set of AS numbers")
            ],
            else: []
          ),
          if(ext.value.rdi != nil,
            do: [error(:rdi, "6487#4.8.11", :as_resources, "RDI values must not be used")],
            else: []
          ),
          for(
            i <- Resources.as_issues(ext.value),
            do: error(i.rule, i.rfc, :as_resources, i.message)
          )
        ])
      else
        []
      end
  end

  # CRLs (RFC 6487 §5, RFC 9829 §3.1).

  defp crl_version(%{version: 2}), do: []

  defp crl_version(%{version: v}),
    do: [error(:crl_version, "6487#5", :version, "the CRL is version #{v}; RPKI CRLs are v2")]

  # RFC 6487 §5 (via RFC 7935 §2), and RFC 5280 §5.1.1.2: the algorithm
  # inside tbsCertList is the outer one.
  defp crl_signature_algorithm(%{tbs_signature_algorithm: inner, signature_algorithm: outer}) do
    mismatch =
      if inner != outer,
        do: [
          error(
            :signature_algorithm_mismatch,
            "5280#5.1.1.2",
            :tbs_signature_algorithm,
            "the tbsCertList signature algorithm (#{OID.format(inner.oid)}) " <>
              "is not the outer one (#{OID.format(outer.oid)})"
          )
        ],
        else: []

    unsupported =
      case Crypto.check_signature_algorithm(inner) do
        :ok -> []
        {:error, p} -> [error(p.rule, p.rfc, :tbs_signature_algorithm, p.message)]
      end

    mismatch ++ unsupported
  end

  # §5: "The CRL issuer is the CA."
  defp crl_issuer(%{issuer_der: der}, %{subject_der: der}), do: []

  defp crl_issuer(_crl, _issuer),
    do: [error(:crl_issuer_mismatch, "6487#5", :issuer, "the CRL issuer is not the CA's subject")]

  # RFC 5280 §5.1.2.4 and §5.1.2.5: a CRL isn't in effect before its
  # thisUpdate, and RPKI CRLs carry a nextUpdate; past it, the CRL is
  # stale but still used (D-016).
  defp crl_dates(%{this_update: this_update, next_update: next_update}, at) do
    Enum.concat([
      if(DateTime.compare(at, this_update.at) == :lt,
        do: [
          error(
            :crl_not_yet_valid,
            "5280#5.1.2.4",
            :this_update,
            "thisUpdate is #{DateTime.to_iso8601(this_update.at)}, after the validation time"
          )
        ],
        else: []
      ),
      cond do
        next_update == nil ->
          [error(:next_update_missing, "5280#5.1.2.5", :next_update, "nextUpdate is missing")]

        DateTime.compare(at, next_update.at) == :gt ->
          [
            warning(
              :stale_crl,
              "5280#5.1.2.5",
              :next_update,
              "stale: nextUpdate was #{DateTime.to_iso8601(next_update.at)}; used anyway (D-016)"
            )
          ]

        true ->
          []
      end
    ])
  end

  # RFC 9829 §3.1: exactly an AKI and a CRL Number. The AKI is processed
  # (key identifier method, RFC 5280 §5.2.1, matching the issuer's SKI);
  # the CRL Number is only checked to be non-critical and in range.
  defp crl_extensions(%{extensions: extensions}, issuer) do
    by_name = Map.new(for %Extension{name: name} = e <- extensions, name != nil, do: {name, e})

    Enum.concat([
      duplicates(extensions),
      for(
        %Extension{name: name} = ext <- extensions,
        name not in [:authority_key_identifier, :crl_number],
        do:
          error(
            :crl_extension,
            "9829#3.1",
            field(ext),
            "#{label(ext)} is not allowed; a CRL has exactly AKI and CRL Number"
          )
      ),
      for(
        %Extension{name: name, value: {:malformed, reason}} = ext <- extensions,
        name in [:authority_key_identifier, :crl_number],
        not negative_crl_number?(ext),
        do:
          error(
            :malformed_extension,
            "5280#4.2",
            name,
            "#{label(ext)} doesn't decode: #{inspect(reason)}"
          )
      ),
      crl_aki(by_name[:authority_key_identifier], issuer),
      crl_number(by_name[:crl_number])
    ])
  end

  defp crl_aki(nil, _issuer),
    do: missing(:authority_key_identifier, "9829#3.1", "every CRL needs it")

  # The key identifier is the SHA-1 of the issuer's subjectPublicKey bits
  # (RFC 6487 §4.8.3), whether or not the issuer carries it as an SKI.
  defp crl_aki(ext, issuer) do
    criticality(ext, false, "6487#4.8.3") ++
      if decoded?(ext) do
        ski = :crypto.hash(:sha, issuer.public_key.key)

        cond do
          ext.value.key_identifier == nil ->
            [
              error(
                :aki_key_identifier,
                "5280#5.2.1",
                :authority_key_identifier,
                "keyIdentifier is missing"
              )
            ]

          ext.value.key_identifier != ski ->
            [
              error(
                :aki_mismatch,
                "9829#3.1",
                :authority_key_identifier,
                "the AKI is not the key identifier of the issuer's public key"
              )
            ]

          true ->
            []
        end
      else
        []
      end
  end

  defp crl_number(nil), do: missing(:crl_number, "9829#3.1", "every CRL needs it")

  # CRLNumber is INTEGER (0..MAX), so the decoder reports a negative value
  # as out of range; RFC 9829 §3.1 calls it a range violation.
  defp crl_number(%Extension{} = ext) when ext.value == {:malformed, {:asn1, :bad_range}} do
    criticality(ext, false, "9829#3.1") ++
      [
        error(
          :crl_number_range,
          "9829#3.1",
          :crl_number,
          "the CRL Number is negative; it must be between 0 and 2^159-1"
        )
      ]
  end

  defp crl_number(ext) do
    criticality(ext, false, "9829#3.1") ++
      if decoded?(ext) and (ext.value < 0 or ext.value > Integer.pow(2, 159) - 1) do
        [
          error(
            :crl_number_range,
            "9829#3.1",
            :crl_number,
            "the CRL Number is #{ext.value}; it must be between 0 and 2^159-1"
          )
        ]
      else
        []
      end
  end

  defp negative_crl_number?(%Extension{
         name: :crl_number,
         value: {:malformed, {:asn1, :bad_range}}
       }),
       do: true

  defp negative_crl_number?(_ext), do: false

  # §5: entries hold serial and revocation date only, no extensions.
  defp crl_entries(%{revoked: revoked}) do
    for %{serial: serial, extensions: [_ | _]} <- revoked do
      error(
        :entry_extensions,
        "6487#5",
        :revoked,
        "the entry for serial #{serial} has extensions; CRL entry extensions are not allowed"
      )
    end
  end

  defp crl_signature(crl, issuer) do
    case Crypto.verify(crl, issuer.public_key) do
      :ok -> []
      {:error, p} -> [error(p.rule, p.rfc, :signature, p.message)]
    end
  end

  defp warning(rule, rfc, field, message),
    do: %{rule: rule, rfc: rfc, field: field, message: message, severity: :warning}

  defp error(rule, rfc, field, message),
    do: %{rule: rule, rfc: rfc, field: field, message: message, severity: :error}
end
