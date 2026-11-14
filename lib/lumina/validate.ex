defmodule Lumina.Validate do
  @moduledoc """
  Validates the certificates of the trees in the cache (D-014): the code
  the repository walk (`Lumina.Walk`) and `lumina validate` (#114) share.

    * `point/5`: the certificates in one publication point of a valid CA,
      each validated against it (`Lumina.Chain.child/5`) with the CRL its
      CRL Distribution Point names in that publication point (D-015). The
      walk asks only for CA certificates; `lumina validate` also asks for
      the EE certificates of signed objects.
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

  An EE certificate is checked as a certificate only. The CMS signature
  of its signed object and the object's content are M5.
  """

  alias Lumina.{Cache, Certificate, Chain, CRL, Object, SignedObject, TA, TAL, URI, Walk}

  @default_max_depth 32

  @type entry ::
          %{
            uri: String.t(),
            kind: :ca | :ee,
            certificate: Certificate.t(),
            valid: boolean(),
            problems: [map()]
          }
          | %{uri: String.t(), kind: :decode_failed, reason: term()}

  @type result :: %{
          ta: %{uri: String.t(), path: Path.t(), valid: boolean(), problems: [map()]} | nil,
          certificates: [entry()],
          issues: [Walk.issue()]
        }

  @signed [".mft", ".roa", ".gbr", ".sig", ".tak"]

  @doc """
  Validates the certificates in the publication point `key` of the valid
  CA certificate `ca`, held at `path`, at time `now`. Returns one entry
  per certificate (or file that doesn't decode), in file name order.

  Options: `ee: true` also validates the EE certificates of signed objects
  (`.mft .roa .gbr .sig .tak`); by default only CA certificates (`.cer`
  files with cA true) are.
  """
  @spec point(Certificate.t(), Path.t(), String.t(), DateTime.t(), keyword()) :: [entry()]
  def point(%Certificate{} = ca, path, key, %DateTime{} = now, opts \\ []) do
    ee? = Keyword.get(opts, :ee, false)

    {entries, _crls} =
      path
      |> File.ls!()
      |> Enum.sort()
      |> Enum.filter(&File.regular?(Path.join(path, &1)))
      |> Enum.flat_map_reduce(%{}, fn file, crls ->
        name = key <> "/" <> file

        case candidate(Path.join(path, file), ee?) do
          :skip ->
            {[], crls}

          {:error, reason} ->
            {[%{uri: name, kind: :decode_failed, reason: reason}], crls}

          {kind, cert} ->
            if ours?(cert, ca) do
              {crl, crls} = crl(cert, ca, path, key, crls, now)
              result = Chain.child(cert, kind, ca, crl, now)

              {[
                 %{
                   uri: name,
                   kind: kind,
                   certificate: cert,
                   valid: result.valid,
                   problems: result.problems
                 }
               ], crls}
            else
              {[], crls}
            end
        end
      end)

    entries
  end

  # What a file holds for validation: a CA certificate, the EE certificate
  # of a signed object (with `ee?`), a decode error, or nothing to check.
  defp candidate(file, ee?) do
    ext = Path.extname(file)

    cond do
      ext == ".cer" ->
        case Object.decode_file(file) do
          {:ok, %Object{value: %Certificate{} = cert}} ->
            if ca?(cert), do: {:ca, cert}, else: :skip

          {:error, reason} ->
            {:error, reason}
        end

      ee? and ext in @signed ->
        case Object.decode_file(file) do
          {:ok, %Object{value: value}} ->
            case ee(value) do
              %Certificate{} = cert -> {:ee, cert}
              nil -> {:error, {:envelope, :no_ee_certificate}}
            end

          {:error, reason} ->
            {:error, reason}
        end

      true ->
        :skip
    end
  end

  defp ee(%SignedObject{} = object), do: SignedObject.ee_certificate(object)
  defp ee(%{object: %SignedObject{} = object}), do: SignedObject.ee_certificate(object)

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
        result = Chain.crl(read_crl(uri, path, key), ca, now)
        {result, Map.put(crls, uri, result)}
    end
  end

  defp read_crl(uri, path, key) do
    with true <- is_binary(uri),
         {:ok, parsed} <- URI.parse(uri),
         prefix = key <> "/",
         true <- String.starts_with?(to_string(parsed), prefix),
         file = String.replace_prefix(to_string(parsed), prefix, ""),
         false <- String.contains?(file, "/"),
         {:ok, %Object{value: %CRL{} = crl}} <- Object.decode_file(Path.join(path, file)) do
      crl
    else
      _ -> nil
    end
  end

  @doc """
  Validates the tree of `tal` in the cache at `root`, offline.

  Starts from the TA stored by the last sync that accepted one, validates
  it at `:now` (`Lumina.Chain.ta/3`), then each publication point of a
  valid CA that is in the cache, CA and EE certificates (`point/5`),
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
          certificates: [],
          issues: []
        }

        state =
          if result.valid,
            do: walk([{cert, uri, 0, []}], state),
            else: state

        {:ok,
         %{
           ta: ta,
           certificates: Enum.reverse(state.certificates),
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
            entries = point(cert, path, key, state.now, ee: true)
            state = %{state | certificates: Enum.reverse(entries, state.certificates)}

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
  `max_invalid` percent of the certificates below it invalid or not
  decoding. Warnings and missing publication points don't count.
  """
  @spec failed?({:ok, result()} | {:error, :no_ta}, number()) :: boolean()
  def failed?(report, max_invalid \\ 10)
  def failed?({:error, :no_ta}, _max_invalid), do: true

  def failed?({:ok, result}, max_invalid) do
    invalid = Enum.count(result.certificates, &(&1[:valid] != true))
    not result.ta.valid or invalid * 100 > max_invalid * length(result.certificates)
  end

  @doc """
  A text summary of `lumina validate`: `reports` is `[{tal_path,
  run_result}]`, validated at `now`.
  """
  @spec summary([{Path.t(), {:ok, result()} | {:error, :no_ta}}], DateTime.t()) :: String.t()
  def summary(reports, %DateTime{} = now) do
    certificates = for {_path, {:ok, r}} <- reports, c <- r.certificates, do: c
    valid = Enum.count(certificates, &(&1[:valid] == true))

    blocks = Enum.map(reports, fn {path, report} -> [path, "\n", tal_lines(report)] end)

    IO.iodata_to_binary([
      Enum.intersperse(blocks, "\n"),
      "\n#{length(reports)} TAL(s), #{valid} certificate(s) valid, " <>
        "#{length(certificates) - valid} invalid, at #{DateTime.to_iso8601(now)}\n"
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
        counts("CA", result.certificates, :ca),
        counts("EE", result.certificates, :ee),
        Enum.map(result.certificates, &certificate_line/1),
        Enum.map(result.issues, &issue_line/1)
      ]
    else
      [accepted <> ": INVALID (#{rules(ta.problems, :error)}); nothing below it validated\n"]
    end
  end

  defp counts(label, certificates, kind) do
    of_kind = Enum.filter(certificates, &(&1.kind == kind))
    valid = Enum.count(of_kind, & &1.valid)
    "  #{label} certificates: #{valid} valid, #{length(of_kind) - valid} invalid\n"
  end

  defp certificate_line(%{kind: :decode_failed, uri: uri, reason: reason}),
    do: "    decode_failed: #{uri} (#{Lumina.Print.error(reason, uri)})\n"

  defp certificate_line(%{valid: false, uri: uri, problems: problems}),
    do: "    invalid: #{uri} (#{rules(problems, :error)})\n"

  defp certificate_line(%{uri: uri, problems: problems}), do: warning_line(uri, problems)

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
