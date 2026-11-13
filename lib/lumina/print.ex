defmodule Lumina.Print do
  @moduledoc """
  Renders decoded RPKI objects as human-readable text: one `field: value`
  per line, nested structures indented by two spaces. Used by
  `lumina print` (#34); `lumina print --brief` uses `render(object,
  brief: true)`.

  Conventions: OIDs as `name (dotted)` when the name is known, times in ISO
  8601 UTC, key identifiers and hashes in colon-separated hex, prefixes in
  the usual notation, and long binary values (signatures) by size only.

  Printing shows what is in the object. It doesn't validate: a
  certificate that breaks the RPKI profile prints like any other.
  """

  alias Lumina.{
    Certificate,
    CRL,
    Extension,
    Manifest,
    Name,
    Object,
    OID,
    Resources,
    ROA,
    SignedObject
  }

  @type node_ :: {String.t(), String.t() | [node_()]}

  @doc """
  Renders a decoded object.

  With `brief: true`, most cryptographic detail is left out (key
  identifiers, public keys, signature algorithms and values, digests,
  signer details, manifest hashes). Validity dates and the useful payload
  are kept: names, serials, resources, repository and CRL URIs, ROA
  prefixes, manifest file names, CRL revocations, unknown extensions.
  See D-001 in doc/decisions.md.
  """
  @spec render(Object.t(), keyword()) :: String.t()
  def render(%Object{} = object, opts \\ []) do
    tree = if Keyword.get(opts, :brief, false), do: brief(object), else: tree(object)
    tree |> lines(0) |> Enum.join("\n") |> Kernel.<>("\n")
  end

  @doc "Describes a decoding error from `Lumina.Object.decode/2`."
  @spec error(term(), String.t()) :: String.t()
  def error({:der, %{rule: rule, clause: clause, offset: offset, message: message}}, _name),
    do: "DER layer: #{message} (#{rule}, #{clause}, byte offset #{offset})"

  def error({:asn1, reason}, _name),
    do: "ASN.1 layer: not the expected structure (#{inspect(reason)})"

  def error({:invalid_time, raw}, _name), do: "ASN.1 layer: #{inspect(raw)} is not a valid time"
  def error({:envelope, reason}, _name), do: "envelope layer: #{inspect(reason)}"
  def error({:econtent, reason}, _name), do: "eContent layer: #{inspect(reason)}"

  def error({:content_type_mismatch, %{extension: ext, content_type: type}}, _name),
    do: "type: the file extension says #{ext}, but the eContent type is #{format_type(type)}"

  def error(:unknown_type, name),
    do: "type: #{inspect(Path.extname(name))} is not a registered RPKI file extension"

  def error(reason, _name) when is_atom(reason), do: "file: #{:file.format_error(reason)}"
  def error(reason, _name), do: inspect(reason)

  defp format_type({:unknown, oid}), do: OID.format(oid)
  defp format_type(type), do: to_string(type)

  # Tree building, per object type.

  defp tree(%Object{type: :certificate, value: cert}), do: certificate(cert)
  defp tree(%Object{type: :crl, value: crl}), do: crl(crl)

  defp tree(%Object{type: :roa, value: %ROA{} = roa}),
    do: signed_object("roa", roa.object) ++ [{"roa", roa(roa)}]

  defp tree(%Object{type: :manifest, value: %Manifest{} = mft}),
    do: signed_object("manifest", mft.object) ++ [{"manifest", manifest(mft)}]

  defp tree(%Object{type: type, value: %SignedObject{} = object}) do
    signed_object(to_string(type), object) ++
      [{"econtent", "#{byte_size(object.econtent || <<>>)} bytes, not decoded yet (M9)"}]
  end

  # Brief trees: validity and payload, without cryptographic detail.

  @brief_extensions [
    :crl_distribution_points,
    :authority_info_access,
    :subject_info_access,
    :ip_resources,
    :as_resources
  ]

  defp brief(%Object{type: :certificate, value: cert}), do: brief_certificate(cert)

  defp brief(%Object{type: :crl, value: crl}) do
    revoked =
      case crl.revoked do
        [] -> "none"
        entries -> Enum.map(entries, &{"serial #{&1.serial}", time(&1.revoked_at)})
      end

    [
      {"type", "crl"},
      {"issuer", Name.to_string(crl.issuer)},
      {"this update", time(crl.this_update)},
      {"next update", if(crl.next_update, do: time(crl.next_update), else: "absent")},
      {"crl number", crl |> CRL.number() |> inspect()},
      {"revoked", revoked}
    ]
  end

  defp brief(%Object{type: :roa, value: %ROA{} = roa}),
    do: brief_signed_object("roa", roa.object) ++ [{"roa", roa(roa)}]

  defp brief(%Object{type: :manifest, value: %Manifest{} = mft}) do
    files =
      case mft.files do
        [] -> "none"
        files -> Enum.map(files, &{"file", &1.name})
      end

    brief_signed_object("manifest", mft.object) ++
      [
        {"manifest",
         [
           {"manifest number", to_string(mft.number)},
           {"this update", time(mft.this_update)},
           {"next update", time(mft.next_update)},
           {"files", files}
         ]}
      ]
  end

  defp brief(%Object{type: type, value: %SignedObject{} = object}) do
    brief_signed_object(to_string(type), object) ++
      [{"econtent", "#{byte_size(object.econtent || <<>>)} bytes, not decoded yet (M9)"}]
  end

  defp brief_certificate(%Certificate{} = cert) do
    extensions =
      for %Extension{name: name, value: value} = ext <- cert.extensions,
          name in @brief_extensions or value == :unknown or match?({:malformed, _}, value) do
        case extension(ext) do
          {label, "unknown extension" <> _} -> {label, "unknown extension"}
          node -> node
        end
      end

    [
      {"type", "certificate (#{kind(cert)})"},
      {"version", to_string(cert.version)},
      {"serial", to_string(cert.serial)},
      {"issuer", Name.to_string(cert.issuer)},
      {"subject", Name.to_string(cert.subject)},
      {"validity", [{"not before", time(cert.not_before)}, {"not after", time(cert.not_after)}]},
      {"extensions", extensions}
    ]
  end

  defp brief_signed_object(type, %SignedObject{} = object) do
    signing_time =
      case SignedObject.signed_attribute(object, :signing_time) do
        %{at: _} = t -> time(t)
        _ -> "absent"
      end

    ee =
      case SignedObject.ee_certificate(object) do
        nil -> "none"
        cert -> [{"not before", time(cert.not_before)}, {"not after", time(cert.not_after)}]
      end

    [
      {"type", "#{type} (signed object)"},
      {"signing time", signing_time},
      {"ee certificate validity", ee}
    ]
  end

  defp certificate(%Certificate{} = cert) do
    [
      {"type", "certificate (#{kind(cert)})"},
      {"version", to_string(cert.version)},
      {"serial", to_string(cert.serial)},
      {"signature algorithm", OID.format(cert.signature_algorithm.oid)},
      {"issuer", Name.to_string(cert.issuer)},
      {"subject", Name.to_string(cert.subject)},
      {"validity", [{"not before", time(cert.not_before)}, {"not after", time(cert.not_after)}]},
      {"subject public key", public_key(cert.public_key)},
      {"extensions", Enum.map(cert.extensions, &extension/1)},
      {"signature", "#{div(bit_size(cert.signature), 8)} bytes"}
    ]
  end

  defp kind(cert) do
    case Certificate.extension_value(cert, :basic_constraints) do
      %{ca: true} -> if cert.issuer_der == cert.subject_der, do: "CA, self-issued", else: "CA"
      _ -> "EE"
    end
  end

  defp crl(%CRL{} = crl) do
    revoked =
      case crl.revoked do
        [] -> "none"
        entries -> Enum.map(entries, &{"serial #{&1.serial}", time(&1.revoked_at)})
      end

    [
      {"type", "crl"},
      {"version", to_string(crl.version)},
      {"issuer", Name.to_string(crl.issuer)},
      {"this update", time(crl.this_update)},
      {"next update", if(crl.next_update, do: time(crl.next_update), else: "absent")},
      {"revoked", revoked},
      {"extensions", Enum.map(crl.extensions, &extension/1)},
      {"signature algorithm", OID.format(crl.signature_algorithm.oid)},
      {"signature", "#{div(bit_size(crl.signature), 8)} bytes"}
    ]
  end

  defp signed_object(type, %SignedObject{} = object) do
    signer =
      case object.signers do
        [signer | _] ->
          [
            {"sid", sid(signer.sid)},
            {"digest algorithm", OID.format(signer.digest_algorithm.oid)},
            {"signature algorithm", OID.format(signer.signature_algorithm.oid)},
            {"signed attributes", Enum.map(signer.signed_attrs || [], &attribute/1)},
            {"signature", "#{byte_size(signer.signature)} bytes"}
          ]

        [] ->
          "none"
      end

    ee =
      case SignedObject.ee_certificate(object) do
        nil -> "none"
        cert -> certificate(cert)
      end

    [
      {"type", "#{type} (signed object)"},
      {"content type", OID.format(object.econtent_type)},
      {"signer", signer},
      {"ee certificate", ee}
    ]
  end

  defp sid({:subject_key_identifier, ski}), do: "subject key identifier #{hex(ski)}"
  defp sid({kind, _value}), do: to_string(kind)

  defp attribute(%{name: :signing_time, values: [%{at: _} = t | _]}),
    do: {"signing time", time(t)}

  defp attribute(%{name: :message_digest, values: [digest | _]}) when is_binary(digest),
    do: {"message digest", hex(digest)}

  defp attribute(%{name: :content_type, values: [oid | _]}) when is_tuple(oid),
    do: {"content type", OID.format(oid)}

  defp attribute(%{oid: oid, der: der}), do: {OID.format(oid), Enum.map_join(der, ", ", &hex/1)}

  defp roa(%ROA{} = roa) do
    prefixes =
      for vrp <- ROA.vrps(roa) do
        shown = Resources.format_ip({:prefix, vrp.address, vrp.length}, vrp.afi)

        {"prefix",
         if(vrp.max_length != vrp.length,
           do: "#{shown} max length #{vrp.max_length}",
           else: shown
         )}
      end

    [{"version", to_string(roa.version)}, {"as id", "AS#{roa.as_id}"}, {"prefixes", prefixes}]
  end

  defp manifest(%Manifest{} = mft) do
    files =
      case mft.files do
        [] -> "none"
        files -> Enum.map(files, &{&1.name, hex(&1.hash)})
      end

    [
      {"version", to_string(mft.version)},
      {"manifest number", to_string(mft.number)},
      {"this update", time(mft.this_update)},
      {"next update", time(mft.next_update)},
      {"file hash algorithm", OID.format(mft.file_hash_alg)},
      {"files", files}
    ]
  end

  # Extensions.

  defp extension(%Extension{oid: oid, name: name, critical: critical, der: der, value: value}) do
    label =
      if(name, do: name |> to_string() |> String.replace("_", " "), else: OID.dotted(oid)) <>
        if(critical, do: " (critical)", else: "")

    case value do
      :unknown -> {label, "unknown extension, #{byte_size(der)} bytes: #{hex(der)}"}
      {:malformed, reason} -> {label, "malformed: #{inspect(reason)}"}
      _ -> {label, extension_value(name, value)}
    end
  end

  defp extension_value(:basic_constraints, %{ca: ca, path_len: len}),
    do: "CA=#{ca}" <> if(len, do: ", path length #{len}", else: "")

  defp extension_value(:subject_key_identifier, ski), do: hex(ski)

  defp extension_value(:authority_key_identifier, aki) do
    case aki do
      %{key_identifier: kid, issuer: nil, serial: nil} ->
        hex(kid)

      _ ->
        [
          {"key identifier", hex(aki.key_identifier || <<>>)},
          {"issuer", inspect(aki.issuer)},
          {"serial", inspect(aki.serial)}
        ]
    end
  end

  defp extension_value(:key_usage, usages), do: Enum.map_join(usages, ", ", &to_string/1)
  defp extension_value(:extended_key_usage, oids), do: Enum.map_join(oids, ", ", &OID.format/1)

  defp extension_value(:crl_distribution_points, points) do
    for point <- points, name <- List.wrap(point.full_name), do: {"uri", general_name(name)}
  end

  defp extension_value(name, descriptions)
       when name in [:authority_info_access, :subject_info_access] do
    for %{method: method, location: location} <- descriptions do
      {if(is_atom(method),
         do: method |> to_string() |> String.replace("_", " "),
         else: OID.format(method)
       ), general_name(location)}
    end
  end

  defp extension_value(:certificate_policies, policies) do
    for policy <- policies,
        do:
          {"policy",
           OID.format(policy.oid) <>
             if(policy.qualifiers == [], do: "", else: " (with qualifiers)")}
  end

  defp extension_value(:ip_resources, families) do
    for family <- families do
      label = family_label(family)

      case family.resources do
        :inherit -> {label, "inherit"}
        resources -> {label, Enum.map_join(resources, ", ", &ip_resource(&1, family.afi))}
      end
    end
  end

  defp extension_value(:as_resources, ids) do
    for {label, value} <- [{"asnum", ids.asnum}, {"rdi", ids.rdi}], value != nil do
      {label,
       if(value == :inherit,
         do: "inherit",
         else: Enum.map_join(value, ", ", &Resources.format_as/1)
       )}
    end
  end

  defp extension_value(_name, value) when is_integer(value) or is_atom(value),
    do: to_string(value)

  defp extension_value(_name, value), do: inspect(value)

  defp family_label(%{afi: afi, safi: safi}) do
    base = %{ipv4: "IPv4", ipv6: "IPv6"}[afi] || "AFI #{inspect(afi)}"
    if safi, do: "#{base} (SAFI #{safi})", else: base
  end

  defp ip_resource({kind, _, _} = resource, afi)
       when kind in [:prefix, :range] and afi in [:ipv4, :ipv6],
       do: Resources.format_ip(resource, afi)

  defp ip_resource(resource, _afi), do: inspect(resource)

  defp general_name({:uri, uri}), do: uri
  defp general_name({:directory_name, name}), do: Name.to_string(name)
  defp general_name(other), do: inspect(other)

  # Values.

  defp public_key(%{algorithm: %{oid: oid}, key: key}) do
    OID.format(oid) <>
      case rsa_bits(key) do
        nil -> ""
        bits -> ", #{bits}-bit modulus"
      end
  end

  # An RSA public key is SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
  defp rsa_bits(key) when is_binary(key) do
    with {:ok, [<<0x02, rest::binary>>, _exponent]} <- Lumina.DER.children(key),
         {:ok, modulus} <- integer_contents(rest) do
      modulus |> :binary.decode_unsigned() |> Integer.digits(2) |> length()
    else
      _ -> nil
    end
  end

  defp rsa_bits(_key), do: nil

  defp integer_contents(<<n, contents::binary-size(n)>>) when n < 128, do: {:ok, contents}
  defp integer_contents(<<0x81, n, contents::binary-size(n)>>), do: {:ok, contents}
  defp integer_contents(<<0x82, n::16, contents::binary-size(n)>>), do: {:ok, contents}
  defp integer_contents(_), do: :error

  defp time(%{at: at}), do: DateTime.to_iso8601(at)

  defp hex(bits) when is_bitstring(bits) and rem(bit_size(bits), 8) != 0, do: inspect(bits)

  defp hex(bytes) when is_binary(bytes),
    do:
      bytes
      |> Base.encode16(case: :lower)
      |> String.graphemes()
      |> Enum.chunk_every(2)
      |> Enum.map_join(":", &Enum.join/1)

  # Layout.

  defp lines(nodes, depth) do
    pad = String.duplicate("  ", depth)

    Enum.flat_map(nodes, fn
      {label, value} when is_binary(value) -> ["#{pad}#{label}: #{value}"]
      {label, []} -> ["#{pad}#{label}: none"]
      {label, children} when is_list(children) -> ["#{pad}#{label}:" | lines(children, depth + 1)]
    end)
  end
end
