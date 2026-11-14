defmodule Lumina.Walk do
  @moduledoc """
  Walks a repository from an accepted TA certificate and mirrors every
  publication point it reaches into the cache (RFC 6481 §5, #75).

  Starting with the TA, each CA certificate's SIA `caRepository` is a
  publication point. The rsync module holding it is fetched recursively
  with `Lumina.Rsync.fetch_dir/3` (D-012), the CA certificates directly in
  the publication point are found, and their publication points are walked
  the same way, breadth first.

  **Which certificates are followed** (D-005, D-014): a CA certificate
  in the publication point of a CA already walked, that validates against
  that CA at `:now` (`Lumina.Validate.point/5`, shared with `lumina
  validate`) and has an rsync `caRepository` (`repository/1`). The TA was
  validated when it was accepted (`Lumina.TA`). An invalid CA is reported
  with its reasons and nothing below it is walked; a valid one's warnings
  are reported too. Certificates that aren't the CA's products (its own,
  another CA's) are skipped without an issue, as `Lumina.Validate`
  describes.

  **Fetching once:** a publication point in a module already fetched in
  this run (same host and port, same module) isn't fetched again; it's
  read from the copy that fetch brought (D-012). Each
  fetch is staged and committed with `Lumina.Cache`, so a failed fetch
  keeps the last good copy (RFC 8897 §7); the walk then continues from that
  copy, marked stale, and the failure is reported. A failed fetch also
  covers the rest of its module for the rest of the run, so it isn't
  retried for each publication point.

  **In parallel (D-011):** the walk goes one level at a time. A level's
  new modules are fetched concurrently, at most `:per_host`
  (default 8) rsync runs at once on each host, and the results are
  reported in walk order, as a sequential walk would give them.

  **Limits (D-008):** a certificate deeper than `:max_depth` (the TA is
  depth 0) isn't followed, and a publication point already visited isn't
  walked again: a loop if it is the publication point of an ancestor,
  otherwise a duplicate. Both are reported, and neither stops the rest of
  the walk.

  The result:

    * `:points`: each publication point walked, with its depth, its cache
      path, the fetch that covered it and whether the copy is `stale`;
    * `:fetches`: each rsync run, by module URI, with its outcome (their number is the
      number of rsync runs);
    * `:issues`: everything reported, as `%{kind, uri, detail}`, `kind` one
      of `:fetch_failed`, `:loop`, `:duplicate`, `:depth_exceeded`,
      `:decode_failed`, `:invalid` (a CA that doesn't validate; the detail
      lists its errors), `:warning` (a valid CA's warnings), `:no_repository`,
      `:bad_uri`, `:oversize`,
      `:removed` (symlinks or special files dropped by `Cache.commit/3`)
      and `:missing` (a publication point that was never fetched and has
      no copy).
  """

  alias Lumina.{Cache, Certificate, Progress, Rsync, URI, Validate}

  @default_max_depth 32
  @default_per_host 8

  @type issue :: %{kind: atom(), uri: String.t(), detail: term()}
  @type point :: %{
          uri: String.t(),
          depth: non_neg_integer(),
          path: Path.t(),
          covered_by: String.t(),
          stale: boolean()
        }
  @type fetch :: %{uri: String.t(), outcome: :ok | :error, detail: term()}
  @type result :: %{points: [point()], fetches: [fetch()], issues: [issue()]}

  @doc """
  Walks from `ta` (an accepted TA certificate) into the cache at `root`.

  Options: `:max_depth` (default 32), `:per_host` (rsync runs at once per
  host, default 8), `:now` (the validation time, also recorded for each
  fetch; default now),
  `:progress` (a `Lumina.Progress` listener, sent level and fetch events),
  `:rsync` (options for `Lumina.Rsync.fetch_dir/3`), and `:remap`,
  for tests: a map from `"host:port"` in repository URIs to the
  `"host:port"` actually connected to. Remapping changes only where rsync
  connects; cache paths and reports keep the URIs from the certificates.
  """
  @spec run(Certificate.t(), Path.t(), keyword()) :: result()
  def run(%Certificate{} = ta, root, opts \\ []) do
    state = %{
      root: root,
      opts: opts,
      max_depth: Keyword.get(opts, :max_depth, @default_max_depth),
      per_host: Keyword.get(opts, :per_host, @default_per_host),
      now: Keyword.get_lazy(opts, :now, &DateTime.utc_now/0),
      # Directories fetched (or attempted) this run: URI => :ok | :error
      # (:planned while a level is being planned).
      fetched: %{},
      visited: MapSet.new(),
      points: [],
      fetches: [],
      issues: []
    }

    state = walk([{ta, "TA", 0, []}], state)

    %{
      points: Enum.reverse(state.points),
      fetches: Enum.reverse(state.fetches),
      issues: Enum.reverse(state.issues)
    }
  end

  @doc """
  The publication point to follow for the valid certificate `cert`, or
  why it isn't followed: a CA with cA true and an rsync `caRepository`
  (D-005). Validation comes first (D-014).
  """
  @spec repository(Certificate.t()) :: {:ok, URI.t()} | :not_ca | {:error, atom(), term()}
  def repository(%Certificate{} = cert) do
    if match?(%{ca: true}, Certificate.extension_value(cert, :basic_constraints)) do
      case Enum.filter(Certificate.sia_uris(cert, :ca_repository), &rsync?/1) do
        [] ->
          {:error, :no_repository, Certificate.sia_uris(cert, :ca_repository)}

        [first | _] ->
          case URI.parse(first) do
            {:ok, uri} -> {:ok, uri}
            {:error, error} -> {:error, :bad_uri, error}
          end
      end
    else
      :not_ca
    end
  end

  defp rsync?(uri), do: String.starts_with?(String.downcase(uri), "rsync://")

  # The walk goes one breadth-first level at a time. Each entry is
  # {certificate, its name for reports, depth, ancestor publication
  # points}. A level is planned in order, its fetches run concurrently, and
  # its results are reported in order, so the outcome is the same as
  # visiting the entries one by one.
  defp walk([], state), do: state

  defp walk(level, state) do
    {plans, state} = Enum.map_reduce(level, state, &plan/2)
    to_fetch = for {:point, _entry, _pp, {:fetch, module}} <- plans, do: module
    depth = level |> hd() |> elem(2)
    points = Enum.count(plans, &match?({:point, _, _, _}, &1))

    Progress.emit(
      state.opts,
      {:level_started, depth, %{points: points, fetches: length(to_fetch)}}
    )

    results = fetch_all(to_fetch, state)

    state = %{
      state
      | fetched:
          Enum.reduce(results, state.fetched, fn {pp, r}, acc -> Map.put(acc, pp, r.outcome) end)
    }

    {next, state} = Enum.flat_map_reduce(plans, state, &report(&1, &2, results))

    Progress.emit(
      state.opts,
      {:level_finished, depth, %{points: length(state.points), issues: length(state.issues)}}
    )

    walk(next, state)
  end

  # Decides what an entry needs: nothing, an issue, or a publication point
  # read from a fetch (`:fetch` if it is fetched for itself, or the URI of
  # the fetch that covers it).
  defp plan({cert, name, depth, ancestors} = entry, state) do
    case repository(cert) do
      :not_ca ->
        {:skip, state}

      {:error, kind, detail} ->
        {{:issue, kind, name, detail}, state}

      {:ok, pp} ->
        key = to_string(pp)

        cond do
          depth > state.max_depth ->
            {{:issue, :depth_exceeded, key, %{certificate: name, depth: depth}}, state}

          key in ancestors ->
            {{:issue, :loop, key, %{certificate: name}}, state}

          MapSet.member?(state.visited, key) ->
            {{:issue, :duplicate, key, %{certificate: name}}, state}

          true ->
            state = %{state | visited: MapSet.put(state.visited, key)}

            case {covering(pp, state.fetched), URI.module(pp)} do
              {{dir, _outcome}, _} ->
                {{:point, entry, pp, dir}, state}

              {nil, {:ok, module}} ->
                # The whole module is fetched (D-012). Planned fetches of
                # this level cover later points too.
                {{:point, entry, pp, {:fetch, module}},
                 %{state | fetched: Map.put(state.fetched, module, :planned)}}

              {nil, {:error, error}} ->
                {{:issue, :bad_uri, key, error}, state}
            end
        end
    end
  end

  defp report(:skip, state, _results), do: {[], state}

  defp report({:issue, kind, uri, detail}, state, _results),
    do: {[], issue(state, kind, uri, detail)}

  defp report({:point, {cert, _name, depth, ancestors}, pp, covered}, state, results) do
    key = to_string(pp)

    {covered_by, outcome, state} =
      case covered do
        {:fetch, module} ->
          result = Map.fetch!(results, module)
          fetched = to_string(module)

          state =
            Enum.reduce(result.issues, state, fn {kind, uri}, st -> issue(st, kind, uri, nil) end)

          state =
            if result.outcome == :error,
              do: issue(state, :fetch_failed, fetched, result.detail),
              else: state

          fetch = %{uri: fetched, outcome: result.outcome, detail: result.detail}
          {fetched, result.outcome, %{state | fetches: [fetch | state.fetches]}}

        %URI{} = dir ->
          {to_string(dir), Map.fetch!(state.fetched, dir), state}
      end

    path = Cache.path(state.root, pp)

    if File.dir?(path) do
      point = %{
        uri: key,
        depth: depth,
        path: path,
        covered_by: covered_by,
        stale: outcome == :error
      }

      state = %{state | points: [point | state.points]}
      children(cert, path, key, depth, [key | ancestors], state)
    else
      {[], issue(state, :missing, key, %{covered_by: covered_by})}
    end
  end

  # The CA certificates directly in the publication point of `ca`, at
  # `path`, that validate against it (`Lumina.Validate.point/5`), as
  # entries of the next level.
  defp children(ca, path, key, depth, ancestors, state) do
    ca
    |> Validate.point(path, key, state.now)
    |> Enum.reduce({[], state}, fn
      %{kind: :decode_failed, uri: name, reason: reason}, {acc, state} ->
        {acc, issue(state, :decode_failed, name, reason)}

      %{valid: true, problems: [], certificate: cert, uri: name}, {acc, state} ->
        {[{cert, name, depth + 1, ancestors} | acc], state}

      %{valid: true, problems: warnings, certificate: cert, uri: name}, {acc, state} ->
        {[{cert, name, depth + 1, ancestors} | acc], issue(state, :warning, name, warnings)}

      %{problems: problems, uri: name}, {acc, state} ->
        {acc, issue(state, :invalid, name, Enum.filter(problems, &(&1.severity == :error)))}
    end)
    |> then(fn {children, state} -> {Enum.reverse(children), state} end)
  end

  defp covering(pp, fetched) do
    Enum.find_value(fetched, fn {%URI{} = dir, outcome} ->
      if dir.host == pp.host and dir.port == pp.port and
           List.starts_with?(pp.path, dir.path),
         do: {dir, outcome}
    end)
  end

  # Fetches the publication points concurrently: every host at once, and
  # at most `:per_host` rsync runs at a time on each (D-011). Returns
  # %{pp => result}.
  defp fetch_all(pps, state) do
    groups = pps |> Enum.group_by(&{&1.host, &1.port}) |> Map.values()

    groups
    |> Task.async_stream(
      fn group ->
        Task.async_stream(group, &{&1, fetch(&1, state)},
          max_concurrency: state.per_host,
          timeout: :infinity,
          ordered: false
        )
        |> Enum.map(fn {:ok, result} -> result end)
      end,
      max_concurrency: max(length(groups), 1),
      timeout: :infinity,
      ordered: false
    )
    |> Enum.flat_map(fn {:ok, results} -> results end)
    |> Map.new()
  end

  # One rsync run into a staging directory, committed on success. Returns
  # the outcome, its detail and the issues it raised, as {kind, uri}.
  defp fetch(pp, state) do
    %{root: root, opts: opts} = state
    key = to_string(pp)
    live = Cache.path(root, pp)
    rsync_opts = Keyword.get(opts, :rsync, [])
    rsync_opts = if File.dir?(live), do: [{:link_dest, live} | rsync_opts], else: rsync_opts
    Progress.emit(opts, {:fetch_started, key, pp.host})

    result =
      with {:ok, staging} <- Cache.stage(root) do
        case Rsync.fetch_dir(remap(pp, opts[:remap]), staging, rsync_opts) do
          {:ok, %{oversize: oversize}} ->
            oversize = for file <- oversize, do: {:oversize, key <> "/" <> file}

            case Cache.commit(root, pp, staging) do
              {:ok, %{removed: removed}} ->
                removed = for file <- removed, do: {:removed, key <> "/" <> file}
                %{outcome: :ok, detail: nil, issues: oversize ++ removed}

              {:error, reason} ->
                Cache.discard(staging)
                %{outcome: :error, detail: {:commit_failed, reason}, issues: oversize}
            end

          {:error, error} ->
            Cache.discard(staging)
            %{outcome: :error, detail: error, issues: []}
        end
      else
        {:error, reason} -> %{outcome: :error, detail: {:stage_failed, reason}, issues: []}
      end

    status = if result.outcome == :ok, do: :ok, else: {:error, result.detail}
    Cache.record(root, pp, status, state.now)

    Progress.emit(
      opts,
      {:fetch_finished, key, pp.host, result.outcome, files(opts, live, result)}
    )

    result
  end

  # Files in a fetched publication point, counted only for a progress
  # listener.
  defp files(opts, live, %{outcome: :ok}) do
    if opts[:progress],
      do:
        live |> Path.join("**") |> Path.wildcard(match_dot: true) |> Enum.count(&File.regular?/1),
      else: 0
  end

  defp files(_opts, _live, _result), do: 0

  defp remap(uri, nil), do: uri

  defp remap(%URI{} = uri, map) do
    authority = if uri.port, do: "#{uri.host}:#{uri.port}", else: uri.host

    case Map.fetch(map, authority) do
      {:ok, target} ->
        [host, port] = String.split(target, ":")
        %{uri | host: host, port: String.to_integer(port)}

      :error ->
        uri
    end
  end

  defp issue(state, kind, uri, detail),
    do: %{state | issues: [%{kind: kind, uri: uri, detail: detail} | state.issues]}
end
