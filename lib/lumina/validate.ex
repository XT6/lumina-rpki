defmodule Lumina.Validate do
  @moduledoc """
  Validates the certificates of the trees in the cache (D-014): the code
  the repository walk (`Lumina.Walk`) and `lumina validate` (#114) share.

    * `point/5`: the certificates in one publication point of a valid CA,
      each validated against it (`Lumina.Chain.child/5`) with the CRL its
      CRL Distribution Point names in that publication point (D-015). The
      walk asks only for CA certificates; `lumina validate` also asks for
      signed objects, each valid when its CMS envelope is
      (`Lumina.CMS.check/1`) and its EE certificate validates (RFC 6488
      §3, #131).
    * `run/3`: offline validation of one TAL's tree, from the TA stored in
      the cache (`Lumina.TA.stored/2`), at a given time, without fetching:
      the same top-down walk through valid CAs that `Lumina.Walk` makes,
      over the publication points already in the cache.

  A `.cer` file is a CA certificate when its Basic Constraints say cA or
  its Key Usage has keyCertSign; other `.cer` files (router certificates,
  D-020) are skipped. What a CA published is decided by the directory
  until manifests list it (M5). Two kinds of certificate there aren't the CA's products and are
  skipped without a result: one with the CA's own key (a TA published in
  its own publication point, #103), and one whose issuer name and AKI both
  name another CA (a CA sharing the directory). One mismatch alone is a
  fault, left to validation to report.

  A manifest's content is checked too (`Lumina.Manifest.check/1`, #132);
  the other types' eContent isn't judged yet (ROAs in M7, the rest in M9).
  """

  alias Lumina.{
    Cache,
    Certificate,
    Chain,
    CMS,
    Manifest,
    Object,
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
            problems: [map()]
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
          issues: [Walk.issue()]
        }

  @signed [".mft", ".roa", ".gbr", ".sig", ".tak"]

  # Summary lines for signed objects, in this order.
  @labels [
    manifest: "manifests",
    roa: "ROAs",
    ghostbusters: "Ghostbusters records",
    rsc: "RSCs",
    tak: "TAKs"
  ]

  @doc """
  Validates the certificates in the publication point `key` of the valid
  CA certificate `ca`, held at `path`, at time `now`. Returns one entry
  per CA certificate or signed object (or file that doesn't decode), in
  file name order.

  Options: `objects: true` also validates signed objects (`.mft .roa .gbr
  .sig .tak`): the EE certificate against the CA, and the CMS envelope
  (`Lumina.CMS.check/1`), whose problems are added to the entry's. By
  default only CA certificates are validated.
  """
  @spec point(Certificate.t(), Path.t(), String.t(), DateTime.t(), keyword()) :: [entry()]
  def point(%Certificate{} = ca, path, key, %DateTime{} = now, opts \\ []) do
    objects? = Keyword.get(opts, :objects, false)

    {entries, _crls} =
      path
      |> File.ls!()
      |> Enum.sort()
      |> Enum.filter(&File.regular?(Path.join(path, &1)))
      |> Enum.flat_map_reduce(%{}, fn file, crls ->
        name = key <> "/" <> file

        case candidate(Path.join(path, file), objects?) do
          :skip ->
            {[], crls}

          {:error, reason} ->
            {[%{uri: name, kind: :decode_failed, reason: reason}], crls}

          {kind, cert, object} ->
            if ours?(cert, ca) do
              {crl, crls} = crl(cert, ca, path, key, crls, now)

              {[
                 entry(
                   name,
                   kind,
                   cert,
                   object,
                   Chain.child(cert, chain_kind(kind), ca, crl, now)
                 )
               ], crls}
            else
              {[], crls}
            end
        end
      end)

    entries
  end

  defp entry(name, :ca, cert, nil, result),
    do: %{uri: name, kind: :ca, certificate: cert, valid: result.valid, problems: result.problems}

  # RFC 6488 §3: the envelope (items 1, 2) and the EE certificate (item 3);
  # for a manifest, its content too (RFC 9286 §4.4, #132).
  defp entry(name, {:object, type}, ee, value, result) do
    own = CMS.check(signed_object(value)) ++ content(value)

    %{
      uri: name,
      kind: :object,
      type: type,
      certificate: ee,
      valid: result.valid and Profile.passes?(own),
      problems: result.problems ++ own
    }
  end

  defp content(%Manifest{} = manifest), do: Manifest.check(manifest)
  defp content(_value), do: []

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

  defp ours?(cert, ca),
    do: cert.public_key.key != ca.public_key.key and not other_issuer?(cert, ca)

  defp other_issuer?(cert, ca) do
    aki = Certificate.extension_value(cert, :authority_key_identifier)

    cert.issuer_der != ca.subject_der and
      match?(%{key_identifier: kid} when is_binary(kid), aki) and
      aki.key_identifier != :crypto.hash(:sha, ca.public_key.key)
  end

  # The CA's CRL result for the CRL `cert`'s CRLDP names, read only from
  # the CA's publication point (D-015) and validated once per URI.
  defp crl(cert, ca, path, key, crls, now) do
    uri = Chain.crl_uri(cert)

    case Map.fetch(crls, uri) do
      {:ok, result} ->
        {result, crls}

      :error ->
        result = Chain.crl(PublicationPoint.read_crl(uri, path, key), ca, now)
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
          issues: []
        }

        state =
          if result.valid,
            do: walk([{cert, uri, 0, []}], state),
            else: state

        {:ok,
         %{
           ta: ta,
           objects: Enum.reverse(state.objects),
           issues: Enum.reverse(state.issues)
         }}
    end
  end

  # One breadth-first level at a time, as the walk goes. Each entry is
  # {valid CA certificate, its name, depth, ancestor publication points}.
  defp walk([], state), do: state

  defp walk(level, state) do
    {next, state} = Enum.flat_map_reduce(level, state, &visit/2)
    walk(next, state)
  end

  defp visit({cert, name, depth, ancestors}, state) do
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
            entries = point(cert, path, key, state.now, objects: true)
            state = %{state | objects: Enum.reverse(entries, state.objects)}

            next =
              for %{kind: :ca, valid: true} = entry <- entries,
                  do: {entry.certificate, entry.uri, depth + 1, [key | ancestors]}

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
    do: problems |> Enum.filter(&(&1.severity == severity)) |> Enum.map_join(", ", & &1.rule)

  defp issue(state, kind, uri, detail),
    do: %{state | issues: [%{kind: kind, uri: uri, detail: detail} | state.issues]}
end
