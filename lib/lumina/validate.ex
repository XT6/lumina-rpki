defmodule Lumina.Validate do
  @moduledoc """
  Validates the certificates of the trees in the cache (D-014): the code
  the repository walk (`Lumina.Walk`) and `lumina validate` (#114) share.

    * `point/5`: one publication point of a valid CA: accepted or failed
      (`Lumina.PublicationPoint`), and the certificates its manifest
      lists, each validated against the CA (`Lumina.Chain.child/6`) with
      the CRL its CRL Distribution Point names in that publication point
      (D-015). The walk asks only for CA certificates; `lumina validate`
      also asks for signed objects, each valid when its CMS envelope is
      (`Lumina.CMS.check/1`) and its EE certificate validates (RFC 6488
      §3, #131).
    * `run/3`: offline validation of one TAL's tree, from the TA stored in
      the cache (`Lumina.TA.stored/2`), at a given time, without fetching:
      the same top-down walk through valid CAs that `Lumina.Walk` makes,
      over the publication points already in the cache.

  What a CA published is what its current manifest lists (RFC 9286 §6,
  #134): a publication point that fails (`Lumina.PublicationPoint`) gives
  nothing, and files not on the manifest are ignored. A listed `.cer`
  file is a CA certificate when its Basic Constraints say cA or its Key
  Usage has keyCertSign; other `.cer` files (router certificates, D-020)
  are skipped.

  The manifest is checked as part of its point (CMS, EE certificate and
  content); the other types' eContent isn't judged yet (ROAs in M7, the
  rest in M9).
  """

  alias Lumina.{
    Cache,
    Certificate,
    Chain,
    CMS,
    Object,
    LastValid,
    ManifestState,
    Profile,
    PublicationPoint,
    SignedObject,
    TA,
    TAL,
    Walk
  }

  @default_max_depth 32

  @type entry ::
          %{
            uri: String.t(),
            kind: :ca,
            certificate: Certificate.t(),
            valid: boolean(),
            problems: [map()],
            resources: Lumina.Resources.effective()
          }
          | %{
              uri: String.t(),
              kind: :object,
              type: Object.type(),
              certificate: Certificate.t(),
              valid: boolean(),
              problems: [map()]
            }
          | %{uri: String.t(), kind: :decode_failed, reason: term()}

  @type result :: %{
          ta: %{uri: String.t(), path: Path.t(), valid: boolean(), problems: [map()]} | nil,
          objects: [entry()],
          unlisted: non_neg_integer(),
          fallback: non_neg_integer(),
          issues: [Walk.issue()]
        }

  # Signed objects validated in a point; its manifest is the point's own
  # entry, and another manifest listed there isn't this CA's.
  @signed [".roa", ".gbr", ".sig", ".tak"]

  # Summary lines for signed objects, in this order.
  @labels [
    manifest: "manifests",
    roa: "ROAs",
    ghostbusters: "Ghostbusters records",
    rsc: "RSCs",
    tak: "TAKs"
  ]

  @doc """
  Validates the publication point `key` of the valid CA certificate `ca`,
  held at `path`, at time `now` (RFC 9286 §6, #134).

  The point is processed first (`Lumina.PublicationPoint.process/5`).
  Only when it is accepted are the files its manifest lists validated:
  one entry per CA certificate or signed object (or file that doesn't
  decode), in file name order. Files not on the manifest are never
  looked at (§6: they "MUST NOT be used").

  Returns `%{point: publication point result, entries: [entry]}`; with
  `objects: true`, the first entry is the manifest's, standing for the
  point: valid when the point is accepted, with every problem of the
  point.

  Options: `objects: true` also validates signed objects (`.roa .gbr .sig
  .tak .asa`): the EE certificate against the CA, and the CMS envelope
  (`Lumina.CMS.check/1`), whose problems are added to the entry's. By
  default only CA certificates are validated. `resources:` the CA's
  effective resources (`Lumina.Resources.effective/2`), which its
  children's `inherit` resolves from; a CA certificate's entry carries
  its own, for the next level (#153). Without it, the CA's own resources
  are used, as for a TA.
  """
  @spec point(Certificate.t(), Path.t(), String.t(), DateTime.t(), keyword()) :: %{
          point: PublicationPoint.t(),
          entries: [entry()]
        }
  def point(%Certificate{} = ca, path, key, %DateTime{} = now, opts \\ []) do
    objects? = Keyword.get(opts, :objects, false)
    {point, dir} = processed(ca, path, key, now, opts)

    {entries, _crls} =
      point.files
      |> Enum.sort()
      |> Enum.flat_map_reduce(%{}, fn {file, full}, crls ->
        name = key <> "/" <> file

        case candidate(full, objects?) do
          :skip ->
            {[], crls}

          {:error, reason} ->
            {[%{uri: name, kind: :decode_failed, reason: reason}], crls}

          {kind, cert, object} ->
            {crl, crls} = crl(cert, ca, point, dir, key, crls, now)
            result = Chain.child(cert, chain_kind(kind), ca, crl, now, resources_opt(opts))
            {[entry(name, kind, cert, object, result)], crls}
        end
      end)

    if objects?,
      do: %{point: point, entries: [manifest_entry(point, key) | entries]},
      else: %{point: point, entries: entries}
  end

  # The point and the directory its files are read from: the live copy, or
  # when that fails, the last valid copy if it is still usable (D-023).
  # `:save` keeps an accepted live copy as the last valid one.
  defp processed(ca, path, key, now, opts) do
    root = Keyword.get(opts, :last_valid)
    point = PublicationPoint.process(ca, path, key, now, resources_opt(opts))
    point = if root, do: replay(root, ca, point), else: point

    cond do
      root == nil ->
        {point, path}

      point.status == :accepted ->
        # A copy or record that can't be saved only weakens the next run.
        _ =
          if Keyword.get(opts, :save, false) do
            _ = LastValid.save(root, point, path)
            ManifestState.record(root, ca, point)
          end

        {point, path}

      stored = point.manifest && LastValid.load(root, point.manifest) ->
        fallback(
          point,
          PublicationPoint.process(ca, stored, key, now, resources_opt(opts)),
          stored,
          path
        )

      true ->
        {point, path}
    end
  end

  # RFC 9286 §4.2.1, RFC 9981 (D-024): a new manifest that doesn't move
  # forward is a failed fetch, so the last valid copy can stand in.
  defp replay(root, ca, %{status: :accepted} = point) do
    problems = point.problems ++ ManifestState.check(root, ca, point)

    if Profile.passes?(problems),
      do: %{point | problems: problems},
      else: %{point | status: :failed, problems: problems, files: %{}, unlisted: []}
  end

  defp replay(_root, _ca, point), do: point

  defp fallback(live, stored, dir, path) do
    if stored.status == :accepted do
      note =
        warning(
          :last_valid_copy,
          "the publication point failed (#{rules(live.problems)}); its last valid copy is used"
        )

      {Map.merge(stored, %{
         status: :fallback,
         problems: [note | stored.problems],
         failed: errors(live.problems)
       }), dir}
    else
      note =
        warning(
          :last_valid_copy_unusable,
          "the last valid copy can't be used either (#{rules(stored.problems)})"
        )

      {%{live | problems: live.problems ++ [note]}, path}
    end
  end

  defp warning(rule, message),
    do: %{rule: rule, rfc: "9286#6.6", field: :manifest, message: message, severity: :warning}

  defp rules(problems), do: problems |> errors() |> Enum.map_join(", ", & &1.rule)

  defp errors(problems), do: Enum.filter(problems, &(&1.severity == :error))

  defp manifest_entry(point, key) do
    %{
      uri: point.manifest || key,
      kind: :object,
      type: :manifest,
      certificate: nil,
      valid: point.status in [:accepted, :fallback],
      problems: point.problems
    }
  end

  defp entry(name, :ca, cert, nil, result),
    do: %{
      uri: name,
      kind: :ca,
      certificate: cert,
      valid: result.valid,
      problems: result.problems,
      resources: result.resources
    }

  # RFC 6488 §3: the envelope (items 1, 2) and the EE certificate (item 3).
  defp entry(name, {:object, type}, ee, value, result) do
    own = CMS.check(signed_object(value))

    %{
      uri: name,
      kind: :object,
      type: type,
      certificate: ee,
      valid: result.valid and Profile.passes?(own),
      problems: result.problems ++ own
    }
  end

  defp resources_opt(opts),
    do: if(held = opts[:resources], do: [resources: held], else: [])

  defp chain_kind(:ca), do: :ca
  defp chain_kind({:object, _type}), do: :ee

  # What a file holds for validation: a CA certificate, a signed object
  # with its EE certificate (with `objects?`), a decode error, or nothing
  # to check.
  defp candidate(file, objects?) do
    ext = Path.extname(file)

    cond do
      ext == ".cer" ->
        case Object.decode_file(file) do
          {:ok, %Object{value: %Certificate{} = cert}} ->
            if ca?(cert), do: {:ca, cert, nil}, else: :skip

          {:error, reason} ->
            {:error, reason}
        end

      objects? and ext in @signed ->
        case Object.decode_file(file) do
          {:ok, %Object{type: type, value: value}} ->
            case SignedObject.ee_certificate(signed_object(value)) do
              %Certificate{} = cert -> {{:object, type}, cert, value}
              nil -> {:error, {:envelope, :no_ee_certificate}}
            end

          {:error, reason} ->
            {:error, reason}
        end

      true ->
        :skip
    end
  end

  defp signed_object(%SignedObject{} = object), do: object
  defp signed_object(%{object: %SignedObject{} = object}), do: object

  # A CA certificate says so with Basic Constraints (RFC 6487 §4.8.1) or
  # keyCertSign (§4.8.4); one with only the latter is checked as a CA, so
  # the missing Basic Constraints is reported rather than skipped.
  defp ca?(cert) do
    match?(%{ca: true}, Certificate.extension_value(cert, :basic_constraints)) or
      case Certificate.extension_value(cert, :key_usage) do
        bits when is_list(bits) -> :keyCertSign in bits
        _ -> false
      end
  end

  # The CA's CRL result for the CRL `cert`'s CRLDP names: one on the
  # point's manifest (RFC 9829 §3.2, #116), validated once per URI.
  defp crl(cert, ca, point, path, key, crls, now) do
    uri = Chain.crl_uri(cert)

    case Map.fetch(crls, uri) do
      {:ok, result} ->
        {result, crls}

      :error ->
        result = PublicationPoint.crl(point, uri, path, key, ca, now)
        {result, Map.put(crls, uri, result)}
    end
  end

  @doc """
  Validates the tree of `tal` in the cache at `root`, offline.

  Starts from the TA stored by the last sync that accepted one, validates
  it at `:now` (`Lumina.Chain.ta/3`), then each publication point of a
  valid CA that is in the cache, CA certificates and signed objects
  (`point/5`),
  breadth first. Returns `{:error, :no_ta}` if no TA is stored.

  `:issues` are those of the walk (`Lumina.Walk`): `:missing` (a valid
  CA's publication point isn't in the cache), `:loop`, `:duplicate`,
  `:depth_exceeded`, `:no_repository` and `:bad_uri`.

  Options: `:now` (default the current time) and `:max_depth` (32).
  """
  @spec run(TAL.t(), Path.t(), keyword()) :: {:ok, result()} | {:error, :no_ta}
  def run(%TAL{} = tal, root, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)
    max_depth = Keyword.get(opts, :max_depth, @default_max_depth)

    case TA.stored(root, tal) do
      nil ->
        {:error, :no_ta}

      %{certificate: cert, uri: uri, path: path} ->
        result = Chain.ta(cert, tal, now)
        ta = %{uri: uri, path: path, valid: result.valid, problems: result.problems}

        state = %{
          root: root,
          now: now,
          max_depth: max_depth,
          visited: MapSet.new(),
          objects: [],
          unlisted: 0,
          fallback: 0,
          issues: []
        }

        state =
          if result.valid,
            do: walk([{cert, uri, 0, [], result.resources}], state),
            else: state

        {:ok,
         %{
           ta: ta,
           objects: Enum.reverse(state.objects),
           unlisted: state.unlisted,
           fallback: state.fallback,
           issues: Enum.reverse(state.issues)
         }}
    end
  end

  # One breadth-first level at a time, as the walk goes. Each entry is
  # {valid CA certificate, its name, depth, ancestor publication points,
  # its effective resources}.
  defp walk([], state), do: state

  defp walk(level, state) do
    {next, state} = Enum.flat_map_reduce(level, state, &visit/2)
    walk(next, state)
  end

  defp visit({cert, name, depth, ancestors, resources}, state) do
    case Walk.repository(cert) do
      :not_ca ->
        {[], state}

      {:error, kind, detail} ->
        {[], issue(state, kind, name, detail)}

      {:ok, pp} ->
        key = to_string(pp)
        path = Cache.path(state.root, pp)

        cond do
          depth > state.max_depth ->
            {[], issue(state, :depth_exceeded, key, %{certificate: name, depth: depth})}

          key in ancestors ->
            {[], issue(state, :loop, key, %{certificate: name})}

          MapSet.member?(state.visited, key) ->
            {[], issue(state, :duplicate, key, %{certificate: name})}

          not File.dir?(path) ->
            {[], issue(%{state | visited: MapSet.put(state.visited, key)}, :missing, key, nil)}

          true ->
            state = %{state | visited: MapSet.put(state.visited, key)}

            %{point: point, entries: entries} =
              point(cert, path, key, state.now,
                objects: true,
                last_valid: state.root,
                resources: resources
              )

            state = %{
              state
              | objects: Enum.reverse(entries, state.objects),
                unlisted: state.unlisted + length(point.unlisted),
                fallback: state.fallback + if(point.status == :fallback, do: 1, else: 0)
            }

            next =
              for %{kind: :ca, valid: true} = entry <- entries,
                  do:
                    {entry.certificate, entry.uri, depth + 1, [key | ancestors], entry.resources}

            {next, state}
        end
    end
  end

  @doc """
  Whether a report of `run/3` (or `{:error, :no_ta}`) should fail
  `lumina validate` (D-022): no TA, an invalid TA, or more than
  `max_invalid` percent of the CA certificates and signed objects below
  it invalid or not decoding. Warnings and missing publication points
  don't count.
  """
  @spec failed?({:ok, result()} | {:error, :no_ta}, number()) :: boolean()
  def failed?(report, max_invalid \\ 10)
  def failed?({:error, :no_ta}, _max_invalid), do: true

  def failed?({:ok, result}, max_invalid) do
    invalid = Enum.count(result.objects, &(&1[:valid] != true))
    not result.ta.valid or invalid * 100 > max_invalid * length(result.objects)
  end

  @doc """
  A text summary of `lumina validate`: `reports` is `[{tal_path,
  run_result}]`, validated at `now`.
  """
  @spec summary([{Path.t(), {:ok, result()} | {:error, :no_ta}}], DateTime.t()) :: String.t()
  def summary(reports, %DateTime{} = now) do
    objects = for {_path, {:ok, r}} <- reports, o <- r.objects, do: o
    valid = Enum.count(objects, &(&1[:valid] == true))

    blocks = Enum.map(reports, fn {path, report} -> [path, "\n", tal_lines(report)] end)

    IO.iodata_to_binary([
      Enum.intersperse(blocks, "\n"),
      "\n#{length(reports)} TAL(s), #{valid} object(s) valid, " <>
        "#{length(objects) - valid} invalid, at #{DateTime.to_iso8601(now)}\n"
    ])
  end

  defp tal_lines({:error, :no_ta}),
    do: "  ta: none in the cache; run lumina sync first\n"

  defp tal_lines({:ok, %{ta: ta} = result}) do
    accepted = "  ta: #{ta.uri}"

    if ta.valid do
      [
        accepted <> ": valid\n",
        warning_line(ta.uri, ta.problems),
        counts("CA certificates", Enum.filter(result.objects, &(&1.kind == :ca))),
        type_counts(result.objects),
        overclaims_line(Enum.count(result.objects, &Chain.overclaim?(&1[:problems] || []))),
        if(result.fallback > 0,
          do:
            "  publication points from the last valid copy: #{result.fallback} " <>
              "(the current copy failed, RFC 9286 section 6.6)\n",
          else: []
        ),
        if(result.unlisted > 0,
          do: "  files not on a manifest: #{result.unlisted} (not used, RFC 9286 section 6)\n",
          else: []
        ),
        Enum.map(result.objects, &object_line/1),
        Enum.map(result.issues, &issue_line/1)
      ]
    else
      [accepted <> ": INVALID (#{rules(ta.problems, :error)}); nothing below it validated\n"]
    end
  end

  defp type_counts(objects) do
    for {type, label} <- @labels,
        of_type = Enum.filter(objects, &(&1[:type] == type)),
        of_type != [],
        do: counts(label, of_type)
  end

  # Certificates (CA or EE) holding resources outside their issuer's
  # (RFC 6487 §7.2 point 6, #155); only when there are any.
  defp overclaims_line(0), do: []

  defp overclaims_line(n),
    do: "  overclaims: #{n} (resources outside the issuer's, RFC 6487 section 7.2)\n"

  defp counts(label, entries) do
    valid = Enum.count(entries, & &1.valid)
    "  #{label}: #{valid} valid, #{length(entries) - valid} invalid\n"
  end

  defp object_line(%{kind: :decode_failed, uri: uri, reason: reason}),
    do: "    decode_failed: #{uri} (#{Lumina.Print.error(reason, uri)})\n"

  defp object_line(%{valid: false, uri: uri, problems: problems}),
    do: "    invalid: #{uri} (#{rules(problems, :error)})\n"

  defp object_line(%{uri: uri, problems: problems}), do: warning_line(uri, problems)

  defp warning_line(_uri, []), do: []
  defp warning_line(uri, problems), do: "    warning: #{uri} (#{rules(problems, :warning)})\n"

  defp issue_line(%{kind: kind, uri: uri, detail: detail}) do
    reason =
      case detail do
        nil -> ""
        %{certificate: name} -> " (from #{name})"
        other -> " (#{inspect(other)})"
      end

    "    #{kind}: #{uri}#{reason}\n"
  end

  defp rules(problems, severity),
    do:
      problems
      |> Enum.filter(&(&1.severity == severity))
      |> Enum.map_join(", ", &Chain.rule_text/1)

  defp issue(state, kind, uri, detail),
    do: %{state | issues: [%{kind: kind, uri: uri, detail: detail} | state.issues]}
end
