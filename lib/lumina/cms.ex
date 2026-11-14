defmodule Lumina.CMS do
  @moduledoc """
  Checks the CMS envelope of an RPKI signed object (manifests, ROAs and
  the rest) against the signed object template: RFC 6488 §2.1 and §3
  item 1, as updated by RFC 9589 §4, with the algorithms of RFC 7935 §2.

    * `profile/1` (#129): the structure. Exactly one digest algorithm,
      certificate and SignerInfo; no CRLs and no unsigned attributes;
      versions 3; a sid that is the EE certificate's SKI; signed
      attributes content-type, message-digest and signing-time, each
      once with one value, and nothing else (so binary-signing-time is
      rejected, RFC 9589); content-type equal to the eContentType;
      SHA-256 digests and an RSA signature algorithm.
    * `verify/1` (#130): the message digest and the signature.
    * `check/1`: both.

  Problems have the same shape as `Lumina.Profile`'s: `rule`, `rfc`,
  `field`, `message` and `severity`. DER (item 1.l) and the SignedData
  content type (item 1.a) are already enforced by
  `Lumina.SignedObject.decode/1`, so a decoded object meets them.
  """

  alias Lumina.{Certificate, Crypto, SignedObject}

  @type problem :: Lumina.Profile.problem()

  @sha256 {2, 16, 840, 1, 101, 3, 4, 2, 1}
  @rsa_encryption {1, 2, 840, 113_549, 1, 1, 1}
  @sha256_with_rsa {1, 2, 840, 113_549, 1, 1, 11}
  @null <<5, 0>>

  @required [:content_type, :message_digest, :signing_time]

  @doc """
  Every problem of `object`'s envelope: `profile/1` and `verify/1`.
  """
  @spec check(SignedObject.t()) :: [problem()]
  def check(%SignedObject{} = object), do: profile(object) ++ verify(object)

  @doc """
  The problems of `object`'s CMS envelope (RFC 6488 §3 item 1, RFC 9589
  §4); `[]` when it follows the template.
  """
  @spec profile(SignedObject.t()) :: [problem()]
  def profile(%SignedObject{} = object) do
    ee = SignedObject.ee_certificate(object)

    signed_data(object) ++
      certificates(object.certificates) ++
      crls(object.crls) ++
      econtent(object) ++
      case object.signers do
        [signer] ->
          signer(signer, object, ee)

        signers ->
          [
            error(
              :signer_count,
              "6488#2.1",
              :signer_infos,
              "there are #{length(signers)} SignerInfos; exactly one is allowed"
            )
          ]
      end
  end

  @doc """
  The cryptographic problems of `object`'s envelope (RFC 6488 §3 item 2):
  the message-digest attribute must be the SHA-256 of the eContent (RFC
  5652 §5.4, §11.2), and the signature must verify over the DER of the
  signed attributes with the EE certificate's key (`Lumina.Crypto`).
  Parts that `profile/1` already reports missing (no single signer, no
  signed attributes, no EE certificate, no eContent) are skipped.
  """
  @spec verify(SignedObject.t()) :: [problem()]
  def verify(%SignedObject{signers: [signer]} = object) do
    message_digest(signer, object.econtent) ++
      signature(signer, SignedObject.ee_certificate(object))
  end

  def verify(%SignedObject{}), do: []

  # RFC 5652 §5.4: the digest covers the eContent's contents octets.
  defp message_digest(_signer, nil), do: []

  defp message_digest(%{signed_attrs: attrs}, econtent) when is_list(attrs) do
    case for(%{name: :message_digest, values: [digest]} <- attrs, do: digest) do
      [digest] when is_binary(digest) ->
        if digest == :crypto.hash(:sha256, econtent),
          do: [],
          else: [
            error(
              :message_digest_mismatch,
              "5652#5.4",
              :message_digest,
              "the message-digest attribute is not the SHA-256 of the eContent"
            )
          ]

      _ ->
        []
    end
  end

  defp message_digest(_signer, _econtent), do: []

  # A signature algorithm other than RSA is profile/1's to report.
  defp signature(
         %{signed_attrs_der: der, signature_algorithm: %{oid: oid}} = signer,
         %Certificate{} = ee
       )
       when is_binary(der) and oid in [@rsa_encryption, @sha256_with_rsa] do
    case Crypto.verify_cms(der, signer.signature_algorithm, signer.signature, ee.public_key) do
      :ok ->
        []

      {:error, %{rule: rule, rfc: rfc, message: message}} ->
        [error(rule, rfc, :signature, message)]
    end
  end

  defp signature(_signer, _ee), do: []

  # §2.1.1 (item 1.b) and §2.1.2 (item 1.j).
  defp signed_data(object) do
    version =
      if object.version == :v3,
        do: [],
        else: [
          error(
            :signed_data_version,
            "6488#2.1.1",
            :version,
            "the SignedData version is #{version(object.version)}; it must be 3"
          )
        ]

    digests =
      case object.digest_algorithms do
        [algorithm] ->
          digest(algorithm, "6488#2.1.2", :digest_algorithms, "SignedData")

        algorithms ->
          [
            error(
              :digest_algorithm_count,
              "6488#2.1.2",
              :digest_algorithms,
              "there are #{length(algorithms)} digest algorithms; exactly one is allowed"
            )
          ]
      end

    version ++ digests
  end

  # §2.1.4 (item 1.c): exactly one certificate, the EE certificate.
  defp certificates([%Certificate{}]), do: []

  defp certificates(certificates) do
    [
      error(
        :certificate_count,
        "6488#2.1.4",
        :certificates,
        "there are #{length(certificates)} certificates (#{Enum.count(certificates, &match?(%Certificate{}, &1))} " <>
          "X.509); exactly one EE certificate is required"
      )
    ]
  end

  # §2.1.5 (item 1.d).
  defp crls(nil), do: []

  defp crls(_crls),
    do: [
      error(:crls_present, "6488#2.1.5", :crls, "the crls field is present; it must be omitted")
    ]

  # §2.1.3.2: the eContent is the payload; RPKI objects never detach it.
  defp econtent(%SignedObject{econtent: nil}),
    do: [error(:no_econtent, "6488#2.1.3.2", :econtent, "the eContent is absent")]

  defp econtent(_object), do: []

  defp signer(signer, object, ee) do
    version =
      if signer.version == :v3,
        do: [],
        else: [
          error(
            :signer_version,
            "6488#2.1.6.1",
            :signer_version,
            "the SignerInfo version is #{version(signer.version)}; it must be 3"
          )
        ]

    version ++
      sid(signer.sid, ee) ++
      digest(signer.digest_algorithm, "6488#2.1.6.3", :digest_algorithm, "SignerInfo") ++
      signature_algorithm(signer.signature_algorithm) ++
      signed_attrs(signer.signed_attrs, object) ++
      unsigned_attrs(signer.unsigned_attrs)
  end

  # §2.1.6.2 (item 1.c).
  defp sid({:subject_key_identifier, ski}, ee) do
    case ee && Certificate.extension_value(ee, :subject_key_identifier) do
      ^ski ->
        []

      _ ->
        [
          error(
            :sid_mismatch,
            "6488#2.1.6.2",
            :sid,
            "the sid is not the EE certificate's Subject Key Identifier"
          )
        ]
    end
  end

  defp sid({:issuer_and_serial, _value}, _ee) do
    [
      error(
        :sid_not_ski,
        "6488#2.1.6.2",
        :sid,
        "the signer is identified by issuer and serial number; it must be the subjectKeyIdentifier"
      )
    ]
  end

  # RFC 7935 §2 with RFC 5754 §2: SHA-256, parameters absent or NULL.
  defp digest(%{oid: @sha256, parameters: parameters}, _rfc, _field, _where)
       when parameters in [nil, @null],
       do: []

  defp digest(%{oid: @sha256}, _rfc, field, where) do
    [
      error(
        :digest_algorithm_parameters,
        "7935#2",
        field,
        "the #{where} SHA-256 parameters must be absent or NULL (RFC 5754 section 2)"
      )
    ]
  end

  defp digest(%{oid: oid}, _rfc, field, where) do
    [
      error(
        :digest_algorithm,
        "7935#2",
        field,
        "the #{where} digest algorithm is #{Lumina.OID.format(oid)}; it must be SHA-256"
      )
    ]
  end

  # RFC 7935 §2: RPs accept rsaEncryption or sha256WithRSAEncryption.
  # sha256WithRSAEncryption: parameters NULL, or absent (RFC 4055 §5).
  # rsaEncryption: NULL (RFC 3370 §3.2, which RFC 7935 §2 cites); absent
  # only warns, since Barry writes it that way (F-031).
  defp signature_algorithm(%{oid: @sha256_with_rsa, parameters: parameters})
       when parameters in [nil, @null],
       do: []

  defp signature_algorithm(%{oid: @rsa_encryption, parameters: @null}), do: []

  defp signature_algorithm(%{oid: @rsa_encryption, parameters: nil}) do
    [
      %{
        rule: :signature_algorithm_parameters_absent,
        rfc: "3370#3.2",
        field: :signature_algorithm,
        message: "the rsaEncryption parameters are absent; they must be NULL",
        severity: :warning
      }
    ]
  end

  defp signature_algorithm(%{oid: oid}) when oid in [@rsa_encryption, @sha256_with_rsa] do
    [
      error(
        :signature_algorithm_parameters,
        "7935#2",
        :signature_algorithm,
        "the signature algorithm parameters must be NULL"
      )
    ]
  end

  defp signature_algorithm(%{oid: oid}) do
    [
      error(
        :signature_algorithm,
        "7935#2",
        :signature_algorithm,
        "the signature algorithm is #{Lumina.OID.format(oid)}; it must be rsaEncryption " <>
          "or sha256WithRSAEncryption"
      )
    ]
  end

  # §2.1.6.4 (items 1.f, 1.g, 1.h) as updated by RFC 9589 §4.
  defp signed_attrs(nil, _object) do
    [
      error(
        :no_signed_attrs,
        "6488#2.1.6.4",
        :signed_attrs,
        "the signed attributes are absent"
      )
    ]
  end

  defp signed_attrs(attrs, object) do
    names = Enum.map(attrs, & &1.name)

    missing =
      for name <- @required, name not in names do
        error(
          :missing_signed_attribute,
          if(name == :signing_time, do: "9589#4", else: "6488#2.1.6.4"),
          name,
          "the #{attribute(name)} attribute is missing"
        )
      end

    others =
      for %{name: name, oid: oid} <- attrs, name not in @required do
        error(
          :signed_attribute_not_allowed,
          if(name == :binary_signing_time, do: "9589#4", else: "6488#2.1.6.4"),
          name || {:attribute, oid},
          "the #{if name, do: attribute(name), else: Lumina.OID.format(oid)} attribute is not allowed"
        )
      end

    repeated =
      for {name, n} <- Enum.frequencies(names), n > 1, name in @required do
        error(
          :repeated_signed_attribute,
          "6488#2.1.6.4",
          name,
          "the #{attribute(name)} attribute appears #{n} times; once is allowed"
        )
      end

    values =
      for %{name: name, values: values} <- attrs, name in @required, length(values) != 1 do
        error(
          :signed_attribute_values,
          "6488#2.1.6.4",
          name,
          "the #{attribute(name)} attribute has #{length(values)} values; exactly one is allowed"
        )
      end

    malformed =
      for %{name: name, values: values} <- attrs,
          name in @required,
          Enum.any?(values, &match?({:malformed, _}, &1)) do
        error(
          :malformed_signed_attribute,
          "6488#2.1.6.4",
          name,
          "the #{attribute(name)} attribute value doesn't decode"
        )
      end

    missing ++ others ++ repeated ++ values ++ malformed ++ content_type(attrs, object)
  end

  # §2.1.6.4.1 (item 1.h).
  defp content_type(attrs, object) do
    case Enum.find(attrs, &(&1.name == :content_type)) do
      %{values: [oid]} when oid != object.econtent_type and is_tuple(oid) ->
        [
          error(
            :content_type_mismatch,
            "6488#2.1.6.4.1",
            :content_type,
            "the content-type attribute is #{Lumina.OID.format(oid)}, but the eContentType is " <>
              Lumina.OID.format(object.econtent_type)
          )
        ]

      _ ->
        []
    end
  end

  # §2.1.6.7 (item 1.i).
  defp unsigned_attrs(nil), do: []

  defp unsigned_attrs(_attrs) do
    [
      error(
        :unsigned_attrs_present,
        "6488#2.1.6.7",
        :unsigned_attrs,
        "unsigned attributes are present; they must be omitted"
      )
    ]
  end

  defp attribute(:content_type), do: "content-type"
  defp attribute(:message_digest), do: "message-digest"
  defp attribute(:signing_time), do: "signing-time"
  defp attribute(:binary_signing_time), do: "binary-signing-time"

  # CMSVersion decodes to :v0..:v5.
  defp version(version), do: version |> Atom.to_string() |> String.trim_leading("v")

  defp error(rule, rfc, field, message),
    do: %{rule: rule, rfc: rfc, field: field, message: message, severity: :error}
end
