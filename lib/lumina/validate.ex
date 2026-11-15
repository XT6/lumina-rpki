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
  content), and a ROA's content with `Lumina.ROA.check/2` (RFC 9582 §4,
  §5, #171); the other types' eContent isn't judged yet (M9).
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
    Progress,
    PublicationPoint,
    ROA,
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

  @type vrp :: %{
          asn: non_neg_integer(),
          afi: :ipv4 | :ipv6,
          address: non_neg_integer(),
          length: non_neg_integer(),
          max_length: non_neg_integer(),
          ta: String.t() | nil,
          uri: String.t()
        }
  @type result :: %{
          ta: %{uri: String.t(), path: Path.t(), valid: boolean(), problems: [map()]} | nil,
          objects: [entry()],
          vrps: [vrp()],
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
    # The CA's resources, merged once for all its children.
    held = Keyword.get_lazy(opts, :resources, fn -> Lumina.Resources.effective(ca, nil) end)
    child_opts = [resources: held, held: Lumina.Resources.held(held)]

    # Files are decoded and children validated in parallel, in file order;
    # each CRL is read once, in between.
    {checks, _crls} =
      point.files
      |> Enum.sort()
      |> parallel(fn {file, full} -> {key <> "/" <> file, candidate(full, objects?)} end)
      |> Enum.flat_map_reduce(%{}, fn
        {_name, :skip}, crls ->
          {[], crls}

        {name, {:error, reason}}, crls ->
          {[{:done, %{uri: name, kind: :decode_failed, reason: reason}}], crls}

        {name, {kind, cert, object}}, crls ->
          {crl, crls} = crl(cert, ca, point, dir, key, crls, now)
          {[{:check, name, kind, cert, object, crl}], crls}
      end)

    entries =
      parallel(checks, fn
        {:done, entry} ->
          entry

        {:check, name, kind, cert, object, crl} ->
          result = Chain.child(cert, chain_kind(kind), ca, crl, now, child_opts)
          entry(name, kind, cert, object, result)
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

  # RFC 6488 §3: the envelope (items 1, 2) and the EE certificate (item 3);
  # for a ROA, its content too (RFC 9582 §4, §5, #171).
  defp entry(name, {:object, type}, ee, value, result) do
    own = CMS.check(signed_object(value)) ++ content(value, ee)

    entry = %{
      uri: name,
      kind: :object,
      type: type,
      certificate: ee,
      valid: result.valid and Profile.passes?(own),
      problems: result.problems ++ own
    }

    # What a ROA asserts, used only when it is valid (`run/3`).
    with %ROA{} <- value, do: Map.put(entry, :vrps, ROA.vrps(value)), else: (_ -> entry)
  end

  defp content(%ROA{} = roa, ee), do: ROA.check(roa, ee)
  defp content(_value, _ee), do: []

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
  # `fun` over `list` on every scheduler, results in the order of `list`.
  defp parallel(list, fun) do
    list
    |> Task.async_stream(fun, timeout: :infinity, max_concurrency: System.schedulers_online())
    |> Enum.map(fn {:ok, result} -> result end)
  end

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

  `:vrps` are the VRPs of the valid ROAs (#164): each `ROA.vrps/1` entry
  (maxLength the prefix length when absent, RFC 9582 §4.3.2.2) with the
  trust anchor's name (`:name`) and the URI of the ROA it comes from. A
  ROA served from its point's last valid copy (D-023) is valid and
  counts. Two ROAs stating the same VRP give two entries (`--wide`,
  D-033, lists both); they are sorted IPv4 first, then by address,
  prefix length, maxLength, AS, trust anchor and URI.

  Options: `:now` (default the current time), `:max_depth` (32),
  `:name`, the trust anchor's name for VRPs (`ta_name/1` of the TAL's
  path, D-032), and `:progress`, a `Lumina.Progress` listener: levels
  and each publication point validated are reported (#180, D-036).
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
          progress: Keyword.take(opts, [:progress]),
          objects: [],
          unlisted: 0,
          fallback: 0,
          issues: []
        }

        state =
          if result.valid,
            do: walk([{cert, uri, 0, [], result.resources}], state),
            else: state

        objects = Enum.reverse(state.objects)

        {:ok,
         %{
           ta: ta,
           objects: objects,
           vrps: vrps(objects, Keyword.get(opts, :name)),
           unlisted: state.unlisted,
           fallback: state.fallback,
           issues: Enum.reverse(state.issues)
         }}
    end
  end

  @doc """
  The name of the trust anchor a TAL file stands for, as VRPs show it:
  the file name without `.tal` (D-032).

  ## Examples

      iex> Lumina.Validate.ta_name("tals/ripe-ncc.tal")
      "ripe-ncc"

  """
  @spec ta_name(Path.t()) :: String.t()
  def ta_name(path), do: Path.basename(path, ".tal")

  defp vrps(objects, name) do
    Lumina.VRP.sort(
      for %{type: :roa, valid: true, vrps: vrps, uri: uri} <- objects,
          vrp <- vrps,
          do: Map.merge(vrp, %{ta: name, uri: uri})
    )
  end

  # One breadth-first level at a time, as the walk goes. Each entry is
  # {valid CA certificate, its name, depth, ancestor publication points,
  # its effective resources}. A level is planned in order, its points are
  # validated in parallel, and the results are folded in order, so the
  # outcome is the same as visiting the entries one by one.
  defp walk([], state), do: state

  defp walk(level, state) do
    {plans, state} = Enum.map_reduce(level, state, &plan/2)
    # Only these go to the tasks: `state` holds every entry so far.
    %{now: now, root: root, progress: progress} = state
    depth = level |> hd() |> elem(2)
    points = Enum.count(plans, &match?({:point, _, _, _, _, _, _}, &1))
    Progress.emit(progress, {:validation_level_started, depth, %{points: points}})

    {next, state} =
      plans
      |> parallel(fn
        {:point, cert, path, key, depth, ancestors, resources} ->
          validated =
            point(cert, path, key, now, objects: true, last_valid: root, resources: resources)

          Progress.emit(
            progress,
            {:point_validated,
             %{
               objects: length(validated.entries),
               invalid: Enum.count(validated.entries, &(&1[:valid] != true))
             }}
          )

          {:point, validated, key, depth, ancestors}

        other ->
          other
      end)
      |> Enum.flat_map_reduce(state, &visit/2)

    Progress.emit(progress, {:validation_level_finished, depth, %{points: points}})
    walk(next, state)
  end

  # What an entry needs: nothing, an issue, or its publication point
  # validated.
  defp plan({cert, name, depth, ancestors, resources}, state) do
    case Walk.repository(cert) do
      :not_ca ->
        {:skip, state}

      {:error, kind, detail} ->
        {{:issue, kind, name, detail}, state}

      {:ok, pp} ->
        key = to_string(pp)
        path = Cache.path(state.root, pp)

        cond do
          depth > state.max_depth ->
            {{:issue, :depth_exceeded, key, %{certificate: name, depth: depth}}, state}

          key in ancestors ->
            {{:issue, :loop, key, %{certificate: name}}, state}

          MapSet.member?(state.visited, key) ->
            {{:issue, :duplicate, key, %{certificate: name}}, state}

          not File.dir?(path) ->
            {{:issue, :missing, key, nil}, %{state | visited: MapSet.put(state.visited, key)}}

          true ->
            {{:point, cert, path, key, depth, ancestors, resources},
             %{state | visited: MapSet.put(state.visited, key)}}
        end
    end
  end

  defp visit(:skip, state), do: {[], state}
  defp visit({:issue, kind, uri, detail}, state), do: {[], issue(state, kind, uri, detail)}

  defp visit({:point, %{point: point, entries: entries}, key, depth, ancestors}, state) do
    state = %{
      state
      | objects: Enum.reverse(entries, state.objects),
        unlisted: state.unlisted + length(point.unlisted),
        fallback: state.fallback + if(point.status == :fallback, do: 1, else: 0)
    }

    next =
      for %{kind: :ca, valid: true} = entry <- entries,
          do: {entry.certificate, entry.uri, depth + 1, [key | ancestors], entry.resources}

    {next, state}
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
