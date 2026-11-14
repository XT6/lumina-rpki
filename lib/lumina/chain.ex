defmodule Lumina.Chain do
  @moduledoc """
  Validates certificates in the context of their issuer (#112): RFC 6487
  §7.2 points 1 to 5 and 7, as RFC 9829 §3.2 updates point 5. Resource
  inclusion (point 6) is M6.

    * `ta/3`: a TA certificate against its TAL (`Lumina.TAL.check_ta/2`),
      its self-signature and the profile (`Lumina.Profile.certificate/3`).
    * `crl/3`: the CRL of a CA, once per CA, so its children can share the
      result (`Lumina.Profile.crl/3`, signature included).
    * `child/5`: a CA or EE certificate against its issuer: names, AKI,
      signature, profile, and revocation by the issuer's CRL.

  Each returns `%{valid: boolean, problems: [problem]}`, problems as in
  `Lumina.Profile` (rule, RFC section, field, message, severity). A result
  is valid when no problem is an `:error`; warnings are kept (D-013,
  D-016, D-018). The validation time is always an argument.

  Finding the CRL is the caller's job: the one at the URI of the child's
  CRL Distribution Point (`crl_uri/1`), in the issuer's publication point
  (D-015). From M5, it must also be the CRL on the issuer's current
  manifest (RFC 9829, #116). The caller also validates top-down: an issuer
  is passed here only once it is valid itself.
  """

  alias Lumina.{Certificate, CRL, Crypto, Profile, TAL}

  @type result :: %{valid: boolean(), problems: [Profile.problem()]}
  @type crl_result :: %{crl: CRL.t() | nil, valid: boolean(), problems: [Profile.problem()]}

  @doc """
  Validates a TA certificate at time `at`: the TAL checks (RFC 8630 §2.3,
  §3), its self-signature with its own key (RFC 6487 §7.2 point 1) and
  the profile, validity dates included.
  """
  @spec ta(Certificate.t(), TAL.t(), DateTime.t()) :: result()
  def ta(%Certificate{} = cert, %TAL{} = tal, %DateTime{} = at) do
    profile = Profile.certificate(cert, :ta, at)

    # The TAL checks overlap the profile (cA, AKI, resources); a rule the
    # profile already reports isn't repeated.
    tal_problems =
      case TAL.check_ta(tal, cert) do
        :ok -> []
        {:error, problems} -> problems
      end

    profile_rules = MapSet.new(profile, & &1.rule)

    tal_only =
      for p <- tal_problems,
          not MapSet.member?(profile_rules, p.rule),
          do: Map.merge(p, %{field: :tal, severity: :error})

    result(tal_only ++ signature(cert, cert, "the self-signature doesn't verify") ++ profile)
  end

  @doc """
  Validates `crl` (or `nil` when it couldn't be found or decoded) as the
  CRL of the CA certificate `issuer` at time `at`.
  """
  @spec crl(CRL.t() | nil, Certificate.t(), DateTime.t()) :: crl_result()
  def crl(nil, %Certificate{}, %DateTime{}), do: %{crl: nil, valid: false, problems: []}

  def crl(%CRL{} = crl, %Certificate{} = issuer, %DateTime{} = at) do
    problems = Profile.crl(crl, issuer, at)
    %{crl: crl, valid: Profile.passes?(problems), problems: problems}
  end

  @doc """
  Validates `cert`, a certificate of `kind` (`:ca` or `:ee`) issued by
  the valid CA certificate `issuer`, at time `at`, with `crl_result`
  (`crl/3`) for the CRL its CRL Distribution Point names.

  A missing or invalid CRL makes the certificate invalid: revocation
  can't be decided without it (RFC 6487 §7.2 point 5). The CRL's own
  warnings (a stale CRL, D-016) are passed on.
  """
  @spec child(Certificate.t(), :ca | :ee, Certificate.t(), crl_result(), DateTime.t()) ::
          result()
  def child(%Certificate{} = cert, kind, %Certificate{} = issuer, crl_result, %DateTime{} = at)
      when kind in [:ca, :ee] do
    result(
      Enum.concat([
        issuer_name(cert, issuer),
        aki(cert, issuer),
        signature(cert, issuer, "the signature doesn't verify with the issuer's key"),
        Profile.certificate(cert, kind, at),
        revocation(cert, crl_result)
      ])
    )
  end

  @doc """
  The rsync URI of the CRL that `cert`'s CRL Distribution Point names, or
  `nil` (RFC 6487 §4.8.6).
  """
  @spec crl_uri(Certificate.t()) :: String.t() | nil
  def crl_uri(%Certificate{} = cert) do
    case Certificate.extension_value(cert, :crl_distribution_points) do
      [%{full_name: names}] when is_list(names) ->
        Enum.find_value(names, fn
          {:uri, "rsync://" <> _ = uri} -> uri
          _ -> nil
        end)

      _ ->
        nil
    end
  end

  # Point 1 and 7: the subject of the issuer is the issuer of the child.
  defp issuer_name(%{issuer_der: der}, %{subject_der: der}), do: []

  defp issuer_name(_cert, _issuer),
    do: [
      error(:issuer_mismatch, "6487#7.2", :issuer, "the issuer is not the parent's subject")
    ]

  # The AKI is the SHA-1 of the issuer's public key (RFC 6487 §4.8.3). A
  # missing AKI is a profile problem.
  defp aki(cert, issuer) do
    case Certificate.extension_value(cert, :authority_key_identifier) do
      %{key_identifier: kid} when is_binary(kid) ->
        if kid == :crypto.hash(:sha, issuer.public_key.key),
          do: [],
          else: [
            error(
              :aki_mismatch,
              "6487#4.8.3",
              :authority_key_identifier,
              "the AKI is not the parent's key identifier"
            )
          ]

      _ ->
        []
    end
  end

  # Point 1: the certificate verifies with the issuer's key.
  defp signature(cert, issuer, message) do
    case Crypto.verify(cert, issuer.public_key) do
      :ok -> []
      {:error, p} -> [error(p.rule, p.rfc, :signature, "#{message}: #{p.message}")]
    end
  end

  # Point 5, as RFC 9829 §3.2 updates it.
  defp revocation(_cert, %{crl: nil}),
    do: [
      error(
        :crl_missing,
        "6487#7.2",
        :crl_distribution_points,
        "the CRL named by the CRLDP is missing"
      )
    ]

  defp revocation(_cert, %{valid: false, problems: problems}) do
    rules = problems |> Enum.filter(&(&1.severity == :error)) |> Enum.map_join(", ", & &1.rule)

    [
      error(
        :crl_invalid,
        "6487#7.2",
        :crl_distribution_points,
        "the CRL named by the CRLDP is invalid (#{rules})"
      )
    ]
  end

  defp revocation(cert, %{crl: crl, problems: problems}) do
    warnings = Enum.filter(problems, &(&1.severity == :warning))

    if CRL.revoked?(crl, cert.serial),
      do: [error(:revoked, "6487#7.2", :serial, "revoked by the issuer's CRL") | warnings],
      else: warnings
  end

  defp result(problems), do: %{valid: Profile.passes?(problems), problems: problems}

  defp error(rule, rfc, field, message),
    do: %{rule: rule, rfc: rfc, field: field, message: message, severity: :error}
end
