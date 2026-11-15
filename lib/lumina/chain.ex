defmodule Lumina.Chain do
  @moduledoc """
  Validates certificates in the context of their issuer (#112): RFC 6487
  §7.2 points 1 to 7, as RFC 9829 §3.2 updates point 5. Each result
  carries the certificate's effective resources, `inherit` resolved
  (`Lumina.Resources.effective/2`, #153), and a child's must be
  encompassed by its issuer's (point 6, #154).

    * `ta/3`: a TA certificate against its TAL (`Lumina.TAL.check_ta/2`),
      its self-signature and the profile (`Lumina.Profile.certificate/3`).
    * `crl/3`: the CRL of a CA, once per CA, so its children can share the
      result (`Lumina.Profile.crl/3`, signature included).
    * `child/6`: a CA or EE certificate against its issuer: names, AKI,
      signature, profile, revocation by the issuer's CRL, and resource
      inclusion.

  Each returns `%{valid: boolean, problems: [problem]}` (`ta/3` and
  `child/6` add `resources`), problems as in
  `Lumina.Profile` (rule, RFC section, field, message, severity). A result
  is valid when no problem is an `:error`; warnings are kept (D-013,
  D-016, D-018). The validation time is always an argument.

  Finding the CRL is the caller's job: the one at the URI of the child's
  CRL Distribution Point (`crl_uri/1`), in the issuer's publication point
  (D-015). From M5, it must also be the CRL on the issuer's current
  manifest (RFC 9829, #116). The caller also validates top-down: an issuer
  is passed here only once it is valid itself.
  """

  alias Lumina.{Certificate, CRL, Crypto, Profile, Resources, TAL}

  @type result :: %{
          valid: boolean(),
          problems: [Profile.problem()],
          resources: Resources.effective()
        }
  @type crl_result :: %{crl: CRL.t() | nil, valid: boolean(), problems: [Profile.problem()]}

  @not_held " not held by the issuer"

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

    result(
      tal_only ++ signature(cert, cert, "the self-signature doesn't verify") ++ profile,
      Resources.effective(cert, nil)
    )
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

  The result's `resources` are the certificate's effective resources,
  `inherit` resolved from the issuer's (`Lumina.Resources.effective/2`).
  Option
  `:resources` gives the issuer's effective resources, which the walk
  carries down from the TA; without it, the issuer's own are used, as if
  it were at the top. `:held` may give the same resources already merged
  (`Lumina.Resources.held/1`), so a caller validating many children of
  one issuer merges them once.

  The effective resources must be encompassed by the issuer's (RFC 6487
  §7.2 point 6; RFC 3779 §2.3, §3.3: "Validation MUST fail when this is
  not the case"), compared as sets (`Lumina.Resources.encompasses?/2`,
  D-027). Otherwise the certificate is invalid as a whole, with
  `resources_not_encompassed` naming what lies outside (RFC 8360 isn't
  applied, #121).
  """
  @spec child(
          Certificate.t(),
          :ca | :ee,
          Certificate.t(),
          crl_result(),
          DateTime.t(),
          keyword()
        ) :: result()
  def child(
        %Certificate{} = cert,
        kind,
        %Certificate{} = issuer,
        crl_result,
        %DateTime{} = at,
        opts \\ []
      )
      when kind in [:ca, :ee] do
    held = Keyword.get_lazy(opts, :resources, fn -> Resources.effective(issuer, nil) end)
    resources = Resources.effective(cert, held)

    result(
      Enum.concat([
        issuer_name(cert, issuer),
        aki(cert, issuer),
        signature(cert, issuer, "the signature doesn't verify with the issuer's key"),
        Profile.certificate(cert, kind, at),
        revocation(cert, crl_result),
        encompassed(resources, Keyword.get_lazy(opts, :held, fn -> Resources.held(held) end))
      ]),
      resources
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

  @doc """
  A problem's rule as text for a one-line report: the rule, and for
  `resources_not_encompassed` the resources outside the issuer's too
  (#155).

  ## Examples

      iex> Lumina.Chain.rule_text(%{rule: :revoked, message: "revoked by the issuer's CRL"})
      "revoked"

      iex> Lumina.Chain.rule_text(%{
      ...>   rule: :resources_not_encompassed,
      ...>   message: "10.0.0.0/8, AS64500 not held by the issuer"
      ...> })
      "resources_not_encompassed: 10.0.0.0/8, AS64500"

  """
  @spec rule_text(%{rule: atom(), message: String.t()}) :: String.t()
  def rule_text(%{rule: :resources_not_encompassed, message: message}),
    do: "resources_not_encompassed: " <> String.replace_suffix(message, @not_held, "")

  def rule_text(%{rule: rule}), do: to_string(rule)

  @doc "Whether `problems` include an overclaim (`resources_not_encompassed`)."
  @spec overclaim?([%{rule: atom()}]) :: boolean()
  def overclaim?(problems), do: Enum.any?(problems, &(&1.rule == :resources_not_encompassed))

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

  # Point 5, as RFC 9829 §3.2 updates it. A CRL the caller rejected before
  # validating it (not on the manifest, #116) comes with its reason.
  defp revocation(_cert, %{crl: nil, problems: [_ | _] = problems}),
    do: Enum.filter(problems, &(&1.severity == :error))

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

  # Point 6. Inherited kinds are the issuer's own, so only explicit ones
  # can lie outside.
  defp encompassed(resources, held) do
    outside = Resources.outside(resources, held)

    case for kind <- [:ipv4, :ipv6, :as], r <- outside[kind], do: Resources.format(r, kind) do
      [] ->
        []

      shown ->
        [
          error(
            :resources_not_encompassed,
            "6487#7.2",
            :resources,
            Enum.join(shown, ", ") <> @not_held
          )
        ]
    end
  end

  defp result(problems, resources),
    do: %{valid: Profile.passes?(problems), problems: problems, resources: resources}

  defp error(rule, rfc, field, message),
    do: %{rule: rule, rfc: rfc, field: field, message: message, severity: :error}
end
