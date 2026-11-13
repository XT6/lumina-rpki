defmodule Lumina.Profile do
  @moduledoc """
  Checks resource certificates against the RPKI profile (RFC 6487).

  `certificate/2` checks the basic fields, RFC 6487 §4.1 to §4.7 (#109):
  version, serial number, signature algorithm, issuer and subject names,
  validity at a given time, unique identifiers, and the public key. These
  rules are the same for TA, CA and EE certificates; the extensions,
  where they differ, are #110.

  The result is a list of problems, each with a `rule`, the `rfc` section,
  the `field` it concerns, a `message` and a `severity`. A certificate
  passes when no problem has severity `:error`; `:warning`s are reported
  but don't reject it (D-018).

  The validation time is always an argument, never "now", so fixtures
  validate at a fixed time.
  """

  alias Lumina.{Certificate, Crypto, DER, OID}

  @type problem :: %{
          rule: atom(),
          rfc: String.t(),
          field: atom(),
          message: String.t(),
          severity: :error | :warning
        }

  @sha256_with_rsa {1, 2, 840, 113_549, 1, 1, 11}
  @null <<5, 0>>

  @common_name {2, 5, 4, 3}
  @serial_number {2, 5, 4, 5}
  @printable_string 0x13

  @doc """
  The problems of `cert`'s basic fields (RFC 6487 §4.1 to §4.7) at time
  `at`.
  """
  @spec certificate(Certificate.t(), DateTime.t()) :: [problem()]
  def certificate(%Certificate{} = cert, %DateTime{} = at) do
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
            %{
              rule: :key_algorithm_sha256_with_rsa,
              rfc: "7935#3.1",
              field: :public_key,
              message:
                "the key algorithm is sha256WithRSAEncryption; RPKI keys use rsaEncryption (F-027)",
              severity: :warning
            }
          ]

        _ ->
          []
      end

    case Crypto.check_rsa_key(key) do
      {:ok, _} -> warning
      {:error, p} -> [error(p.rule, p.rfc, :public_key, p.message)]
    end
  end

  defp error(rule, rfc, field, message),
    do: %{rule: rule, rfc: rfc, field: field, message: message, severity: :error}
end
