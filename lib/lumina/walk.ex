defmodule Lumina.Walk do
  @moduledoc """
  Walks a repository from an accepted TA certificate and mirrors every
  publication point it reaches into the cache (RFC 6481 §5, #75).

  Starting with the TA, each CA certificate's SIA `caRepository` is a
  publication point. It's fetched recursively with `Lumina.Rsync.fetch_dir/3`
  (D-009), the CA certificates directly in it are found, and their
  publication points are walked the same way, breadth first.

  **Which certificates are followed** is decided in one place,
  `repository/1`: in M3 every CA certificate that *decodes*, with cA true
  and an rsync `caRepository` (D-005). M4 replaces "decodes" with
  "validates".

  **Fetching once:** a publication point inside a directory already
  fetched in this run (same host, and its path below that directory) isn't
  fetched again; it's read from the copy that fetch brought (D-009). Each
  fetch is staged and committed with `Lumina.Cache`, so a failed fetch
  keeps the last good copy (RFC 8897 §7); the walk then continues from that
  copy, marked stale, and the failure is reported. A failed fetch also
  covers the directories below it for the rest of the run, so they aren't
  retried one by one.

  **Limits (D-008):** a certificate deeper than `:max_depth` (the TA is
  depth 0) isn't followed, and a publication point already visited isn't
  walked again: a loop if it is the publication point of an ancestor,
  otherwise a duplicate. Both are reported, and neither stops the rest of
  the walk.

  The result:

    * `:points`: each publication point walked, with its depth, its cache
      path, the fetch that covered it and whether the copy is `stale`;
    * `:fetches`: each rsync run, with its outcome (their number is the
      number of rsync runs);
    * `:issues`: everything reported, as `%{kind, uri, detail}`, `kind` one
      of `:fetch_failed`, `:loop`, `:duplicate`, `:depth_exceeded`,
      `:decode_failed`, `:no_repository`, `:bad_uri`, `:oversize`,
      `:removed` (symlinks or special files dropped by `Cache.commit/3`)
      and `:missing` (a publication point that was never fetched and has
      no copy).
  """

  alias Lumina.{Cache, Certificate, Object, Rsync, URI}

  @default_max_depth 32

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

  Options: `:max_depth` (default 32), `:now` (the time recorded for each
  fetch), `:rsync` (options for `Lumina.Rsync.fetch_dir/3`), and `:remap`,
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
      now: Keyword.get_lazy(opts, :now, &DateTime.utc_now/0),
      # Directories fetched (or attempted) this run: URI => :ok | :error.
      fetched: %{},
      visited: MapSet.new(),
      points: [],
      fetches: [],
      issues: []
    }

    state = walk(:queue.from_list([{ta, "TA", 0, []}]), state)

    %{
      points: Enum.reverse(state.points),
      fetches: Enum.reverse(state.fetches),
      issues: Enum.reverse(state.issues)
    }
  end

  @doc """
  The publication point to follow for `cert`, or why it isn't followed.
  This is the one place that selects CAs (D-005): M3 follows every CA
  certificate that decodes, with cA true and an rsync `caRepository`.
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

  # The queue holds {certificate, its name for reports, depth, ancestor
  # publication points}.
  defp walk(queue, state) do
    case :queue.out(queue) do
      {:empty, _} ->
        state

      {{:value, {cert, name, depth, ancestors}}, queue} ->
        {children, state} = visit(cert, name, depth, ancestors, state)
        walk(Enum.reduce(children, queue, &:queue.in/2), state)
    end
  end

  defp visit(cert, name, depth, ancestors, state) do
    case repository(cert) do
      :not_ca ->
        {[], state}

      {:error, kind, detail} ->
        {[], issue(state, kind, name, detail)}

      {:ok, pp} ->
        key = to_string(pp)

        cond do
          depth > state.max_depth ->
            {[], issue(state, :depth_exceeded, key, %{certificate: name, depth: depth})}

          key in ancestors ->
            {[], issue(state, :loop, key, %{certificate: name})}

          MapSet.member?(state.visited, key) ->
            {[], issue(state, :duplicate, key, %{certificate: name})}

          true ->
            state = %{state | visited: MapSet.put(state.visited, key)}
            {covered_by, outcome, state} = ensure_fetched(pp, state)
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
              children(path, key, depth, [key | ancestors], state)
            else
              {[], issue(state, :missing, key, %{covered_by: covered_by})}
            end
        end
    end
  end

  # The CA certificates directly in a publication point, as queue entries.
  defp children(path, key, depth, ancestors, state) do
    {children, state} =
      path
      |> File.ls!()
      |> Enum.sort()
      |> Enum.filter(&(Path.extname(&1) == ".cer" and File.regular?(Path.join(path, &1))))
      |> Enum.reduce({[], state}, fn file, {acc, state} ->
        name = key <> "/" <> file

        case Object.decode_file(Path.join(path, file)) do
          {:ok, %Object{value: %Certificate{} = cert}} ->
            {[{cert, name, depth + 1, ancestors} | acc], state}

          {:error, reason} ->
            {acc, issue(state, :decode_failed, name, reason)}
        end
      end)

    {Enum.reverse(children), state}
  end

  # Fetches `pp` unless a directory fetched in this run covers it. Returns
  # the URI that covered it, and that fetch's outcome.
  defp ensure_fetched(pp, state) do
    case covering(pp, state.fetched) do
      {uri, outcome} -> {uri, outcome, state}
      nil -> fetch(pp, state)
    end
  end

  defp covering(pp, fetched) do
    Enum.find_value(fetched, fn {%URI{} = dir, outcome} ->
      if dir.host == pp.host and dir.port == pp.port and
           List.starts_with?(pp.path, dir.path),
         do: {to_string(dir), outcome}
    end)
  end

  defp fetch(pp, state) do
    %{root: root, opts: opts} = state
    key = to_string(pp)
    live = Cache.path(root, pp)
    rsync_opts = Keyword.get(opts, :rsync, [])
    rsync_opts = if File.dir?(live), do: [{:link_dest, live} | rsync_opts], else: rsync_opts

    {outcome, detail, state} =
      with {:ok, staging} <- Cache.stage(root) do
        case Rsync.fetch_dir(remap(pp, opts[:remap]), staging, rsync_opts) do
          {:ok, %{oversize: oversize}} ->
            state = Enum.reduce(oversize, state, &issue(&2, :oversize, key <> "/" <> &1, nil))

            case Cache.commit(root, pp, staging) do
              {:ok, %{removed: removed}} ->
                state = Enum.reduce(removed, state, &issue(&2, :removed, key <> "/" <> &1, nil))
                {:ok, nil, state}

              {:error, reason} ->
                Cache.discard(staging)
                {:error, {:commit_failed, reason}, state}
            end

          {:error, error} ->
            Cache.discard(staging)
            {:error, error, state}
        end
      else
        {:error, reason} -> {:error, {:stage_failed, reason}, state}
      end

    Cache.record(root, pp, if(outcome == :ok, do: :ok, else: {:error, detail}), state.now)
    state = if outcome == :error, do: issue(state, :fetch_failed, key, detail), else: state

    state = %{
      state
      | fetched: Map.put(state.fetched, pp, outcome),
        fetches: [%{uri: key, outcome: outcome, detail: detail} | state.fetches]
    }

    {key, outcome, state}
  end

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
