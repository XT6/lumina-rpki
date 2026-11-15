defmodule Lumina.Walk do
  @moduledoc """
  Walks a repository from an accepted TA certificate and mirrors every
  publication point it reaches into the cache (RFC 6481 §5, #75).

  Starting with the TA, each CA certificate's SIA `caRepository` is a
  publication point. The rsync module holding it is fetched recursively
  with `Lumina.Rsync.fetch_dir/3` (D-012), the CA certificates directly in
  the publication point are found, and their publication points are walked
  the same way, breadth first.

  **Which certificates are followed** (D-005, D-014, #134): a CA
  certificate listed on the current manifest of a CA already walked, in
  a publication point that is accepted (RFC 9286 §6), that validates
  against that CA at `:now` (`Lumina.Validate.point/5`, shared with
  `lumina validate`) and has an rsync `caRepository` (`repository/1`).
  The TA was validated when it was accepted (`Lumina.TA`). A failed
  publication point is reported with its reasons, and so is an invalid
  CA; nothing below either is walked. A valid CA's warnings are reported
  too. Files not on the manifest are ignored. Each accepted point is
  kept as its last valid copy (`Lumina.LastValid`, D-023), which stands
  in when the point later fails, as long as its manifest is current.

  **Fetching once:** a publication point in a module already fetched in
  this run (same host and port, same module) isn't fetched again; it's
  read from the copy that fetch brought (D-012). Each
  fetch is staged and committed with `Lumina.Cache`, so a failed fetch
  keeps the last good copy (RFC 8897 §7); the walk then continues from that
  copy, marked stale, and the failure is reported. A failed fetch also
  covers the rest of its module for the rest of the run, so it isn't
  retried for each publication point.

  **In parallel (D-011, #88):** the walk is planned and reported one
  level at a time, in walk order, as a sequential walk would give it.
  Underneath, fetches and validations don't wait for the level: a
  publication point is validated as soon as its module is in, and its
  valid children are scheduled at once, their modules fetched and their
  points validated ahead of the level that reports them. A slow or
  silent host then holds up only what lies below it. At most `:per_host`
  (default 8) rsync runs at once on each host, and one validation per
  scheduler.

  **Caught mid-update (RFC 6481 §5, D-007):** a publication point
  fetched this run that fails only because files its manifest lists are
  missing or don't match their hashes (RFC 9286 §6.4, §6.5) may have been
  read while its repository was being updated. Its module is fetched once
  more and the point validated again; a module is fetched again at most
  once per run, and the retry is reported (`:refetched`).

  **Limits (D-008):** a certificate deeper than `:max_depth` (the TA is
  depth 0) isn't followed, and a publication point already visited isn't
  walked again: a loop if it is the publication point of an ancestor,
  otherwise a duplicate. Both are reported, and neither stops the rest of
  the walk.

  The result:

    * `:points`: each publication point walked, with its depth, its cache
      path, the fetch that covered it, whether the copy is `stale` and
      its `status` (`:accepted`, `:failed`, or `:fallback` when its last
      valid copy stands in, RFC 9286 §6, D-023);
    * `:fetches`: each rsync run, by module URI, with its outcome (their number is the
      number of rsync runs);
    * `:issues`: everything reported, as `%{kind, uri, detail}`, `kind` one
      of `:fetch_failed`, `:loop`, `:duplicate`, `:depth_exceeded`,
      `:decode_failed`, `:point_failed` (a publication point RFC 9286 §6
      rejects, by its manifest URI; the detail lists the reasons),
      `:refetched` (a module fetched again because a point in it was caught
      mid-update; the detail names the manifest and the reasons),
      `:point_fallback` (one that failed but whose last valid copy, D-023,
      is used instead; the detail lists why the live copy failed),
      `:invalid` (a CA that doesn't validate; the detail lists its errors), `:warning` (a valid CA's warnings), `:no_repository`,
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
          stale: boolean(),
          status: :accepted | :failed | :fallback
        }
  @type fetch :: %{uri: String.t(), outcome: :ok | :error, detail: term()}
  @type result :: %{points: [point()], fetches: [fetch()], issues: [issue()]}

  @doc """
  Walks from `ta` (an accepted TA certificate) into the cache at `root`.

  Options: `:max_depth` (default 32), `:per_host` (rsync runs at once per
  host, default 8), `:now` (the validation time, also recorded for each
  fetch; default now),
  `:progress` (a `Lumina.Progress` listener, sent level and fetch events),
  `:before_refetch` (tests only: called with the module URI just before a
  mid-update retry, so a test can finish the "update"),
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
      # Modules fetched again this run because a point in them was caught
      # mid-update (RFC 6481 §5): at most once each.
      refetched: MapSet.new(),
      # Those of the current level: results validated before them are stale.
      refetched_in_level: MapSet.new(),
      # Fetches and validations running in tasks (#88): see `settle/2`.
      pool: %{
        # task ref => {:fetch, module} | {:validate, id, point}
        tasks: %{},
        # Fetches: waiting their turn per host, running per host, every
        # module requested this run, and the results.
        queued: %{},
        running: %{},
        requested: MapSet.new(),
        done: %{},
        # Points (by `point_id/3`) waiting for their module, scheduled
        # (waiting, queued, running or done), queued, validated, and found
        # missing from the cache.
        waiting: %{},
        claimed: MapSet.new(),
        validations: [],
        validating: 0,
        validated: %{},
        dismissed: MapSet.new()
      },
      points: [],
      fetches: [],
      issues: []
    }

    state = walk([{ta, "TA", 0, [], Lumina.Resources.effective(ta, nil)}], state)
    _ = drain(state)

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
  # points, its effective resources}. A level is planned in order and its
  # results are reported in order, so the outcome is the same as visiting
  # the entries one by one.
  #
  # Underneath (#88), fetches and validations run as soon as they can: a
  # publication point is validated when its module is in, and its valid
  # children are scheduled right away, their modules fetched and their
  # points validated in turn, ahead of the level that will report them.
  # A slow host then delays only the points below it. A level waits only
  # for its own points (`settle/2`); a result computed ahead is used when
  # the level plans the same point, for the same certificate and
  # resources (`point_id/3`).
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

    {ids, state} = settle(plans, state)
    results = Map.take(state.pool.done, to_fetch)
    validated = Map.take(state.pool.validated, ids)

    state = %{
      state
      | fetched:
          Enum.reduce(results, state.fetched, fn {pp, r}, acc -> Map.put(acc, pp, r.outcome) end),
        pool: %{state.pool | validated: Map.drop(state.pool.validated, ids)},
        refetched_in_level: MapSet.new()
    }

    {next, state} = Enum.flat_map_reduce(plans, state, &report(&1, &2, {results, validated}))

    Progress.emit(
      state.opts,
      {:level_finished, depth, %{points: length(state.points), issues: length(state.issues)}}
    )

    walk(next, state)
  end

  # A publication point to validate: {CA certificate, its effective
  # resources, publication point URI, depth, ancestor publication points}.
  # Its result depends on the certificate and the resources, so a result
  # computed ahead is used only for the same ones.
  defp point_id(key, cert, resources), do: {key, :erlang.phash2({cert.tbs_der, resources})}

  # Schedules the level's points and waits until each is validated or
  # found missing. Returns their ids and the state, with the results in
  # `pool.validated` and the fetch results in `pool.done`.
  defp settle(plans, state) do
    points =
      for {:point, {cert, _name, depth, ancestors, resources}, pp, _covered} <- plans,
          do: {cert, resources, pp, depth, ancestors}

    state = Enum.reduce(points, state, &schedule(&2, &1))
    ids = for {cert, resources, pp, _, _} <- points, do: point_id(to_string(pp), cert, resources)
    {ids, wait(ids, state)}
  end

  defp wait(ids, state) do
    pool = state.pool

    if Enum.all?(ids, &(Map.has_key?(pool.validated, &1) or MapSet.member?(pool.dismissed, &1))),
      do: state,
      else: wait(ids, await(state))
  end

  # Validates a point once its module is in: now if it is (fetched earlier
  # this run, or covered by a module fetched or failed), else when its
  # fetch, requested here, finishes. A point already scheduled for the same
  # certificate and resources isn't scheduled again.
  defp schedule(state, {cert, resources, pp, _depth, _ancestors} = point) do
    id = point_id(to_string(pp), cert, resources)

    with false <- MapSet.member?(state.pool.claimed, id),
         {:ok, module} <- URI.module(pp) do
      state = update_in(state.pool.claimed, &MapSet.put(&1, id))

      if module_done?(state, module) do
        enqueue(state, id, point)
      else
        state
        |> request(module)
        |> update_in(
          [:pool, :waiting],
          &Map.update(&1, module, [{id, point}], fn l -> [{id, point} | l] end)
        )
      end
    else
      _ -> state
    end
  end

  defp module_done?(state, module),
    do:
      Map.has_key?(state.pool.done, module) or
        Map.get(state.fetched, module, :planned) != :planned

  # Queues a point for validation if it is in the cache; otherwise
  # `report/3` finds it missing.
  defp enqueue(state, id, {_cert, _resources, pp, _depth, _ancestors} = point) do
    if File.dir?(Cache.path(state.root, pp)),
      do: next_validation(update_in(state.pool.validations, &(&1 ++ [{id, point}]))),
      else: update_in(state.pool.dismissed, &MapSet.put(&1, id))
  end

  # Handles one finished task.
  defp await(state) do
    tasks = state.pool.tasks

    receive do
      {ref, result} when is_map_key(tasks, ref) ->
        Process.demonitor(ref, [:flush])
        {job, tasks} = Map.pop(tasks, ref)
        state = put_in(state.pool.tasks, tasks)

        case job do
          {:fetch, module} ->
            state = fetched(state, module, result)
            {points, waiting} = Map.pop(state.pool.waiting, module, [])
            state = put_in(state.pool.waiting, waiting)

            Enum.reduce(Enum.reverse(points), state, fn {id, point}, st ->
              enqueue(st, id, point)
            end)

          {:validate, id, point} ->
            state = update_in(state.pool.validating, &(&1 - 1))

            # A result for a point dropped meanwhile (its module was
            # refetched) is stale.
            state =
              if MapSet.member?(state.pool.claimed, id),
                do: state |> put_in([:pool, :validated, id], result) |> ahead(point, result),
                else: state

            next_validation(state)
        end
    end
  end

  # Schedules the valid children of a validated point, ahead of the level
  # that will plan them, unless they would be a loop, a duplicate of a
  # point already walked, or too deep: `plan/2` decides those.
  defp ahead(state, {_cert, _resources, pp, depth, ancestors}, %{
         point: %{status: status},
         entries: entries
       })
       when status != :failed do
    key = to_string(pp)
    ancestors = [key | ancestors]

    Enum.reduce(entries, state, fn
      %{valid: true, certificate: cert, resources: resources}, st when depth < st.max_depth ->
        with {:ok, child} <- repository(cert),
             child_key = to_string(child),
             false <- child_key in ancestors,
             false <- MapSet.member?(st.visited, child_key) do
          schedule(st, {cert, resources, child, depth + 1, ancestors})
        else
          _ -> st
        end

      _entry, st ->
        st
    end)
  end

  defp ahead(state, _point, _result), do: state

  # Starts queued validations while fewer than one per scheduler runs
  # (each also runs in parallel inside, `Validate.point/5`).
  defp next_validation(%{pool: %{validations: [{id, point} | rest], validating: n}} = state) do
    if n < System.schedulers_online(), do: start_validation(state, id, point, rest), else: state
  end

  defp next_validation(state), do: state

  defp start_validation(state, id, {cert, resources, pp, _depth, _ancestors} = point, rest) do
    # Only these go to the task: `state` holds every report so far.
    %{root: root, now: now} = state
    key = to_string(pp)
    path = Cache.path(root, pp)
    task = Task.async(fn -> validate_point(cert, resources, path, key, now, root) end)
    pool = state.pool

    next_validation(%{
      state
      | pool: %{
          pool
          | validations: rest,
            validating: pool.validating + 1,
            tasks: Map.put(pool.tasks, task.ref, {:validate, id, point})
        }
    })
  end

  # Starts fetching `module` unless it was already requested this run,
  # at most `:per_host` at once per host (D-011); the rest wait their
  # turn.
  defp request(state, module) do
    if MapSet.member?(state.pool.requested, module) do
      state
    else
      host = {module.host, module.port}
      state = update_in(state.pool.requested, &MapSet.put(&1, module))

      state =
        update_in(state.pool.queued, &Map.update(&1, host, [module], fn q -> q ++ [module] end))

      start_fetches(state, host)
    end
  end

  defp start_fetches(state, host) do
    running = Map.get(state.pool.running, host, 0)

    case Map.get(state.pool.queued, host, []) do
      [module | rest] when running < state.per_host ->
        # Only these go to the task: `state` holds every report so far.
        context = Map.take(state, [:root, :opts, :now])
        task = Task.async(fn -> fetch(module, context) end)
        pool = state.pool

        start_fetches(
          %{
            state
            | pool: %{
                pool
                | queued: Map.put(pool.queued, host, rest),
                  running: Map.put(pool.running, host, running + 1),
                  tasks: Map.put(pool.tasks, task.ref, {:fetch, module})
              }
          },
          host
        )

      _ ->
        state
    end
  end

  defp fetched(state, module, result) do
    host = {module.host, module.port}
    pool = state.pool

    state = %{
      state
      | pool: %{
          pool
          | done: Map.put(pool.done, module, result),
            running: Map.update!(pool.running, host, &(&1 - 1))
        }
    }

    start_fetches(state, host)
  end

  # After a refetch of `module`, results computed ahead for points in it
  # are stale: they are dropped, and validated again if a level plans
  # them.
  defp forget(state, module) do
    prefix = to_string(module) <> "/"
    stale? = fn {key, _hash} -> String.starts_with?(key <> "/", prefix) end
    pool = state.pool

    %{
      state
      | pool: %{
          pool
          | claimed: MapSet.reject(pool.claimed, stale?),
            validated: Map.reject(pool.validated, fn {id, _} -> stale?.(id) end),
            validations: Enum.reject(pool.validations, fn {id, _} -> stale?.(id) end)
        }
    }
  end

  # When the walk ends, work scheduled ahead for points no level planned
  # (a point validated again after a refetch can list other children) is
  # dropped, and running tasks are waited for.
  defp drain(state) do
    state = %{state | pool: %{state.pool | queued: %{}, validations: [], waiting: %{}}}
    finish(state)
  end

  defp finish(%{pool: %{tasks: tasks}} = state) when tasks == %{}, do: state
  defp finish(state), do: finish(await(state))

  # Decides what an entry needs: nothing, an issue, or a publication point
  # read from a fetch (`:fetch` if it is fetched for itself, or the URI of
  # the fetch that covers it).
  defp plan({cert, name, depth, ancestors, _resources} = entry, state) do
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

  defp report(
         {:point, {cert, _name, depth, ancestors, resources}, pp, covered},
         state,
         {results, validated}
       ) do
    key = to_string(pp)

    {covered_by, module, outcome, state} =
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
          {fetched, module, result.outcome, %{state | fetches: [fetch | state.fetches]}}

        %URI{} = dir ->
          {to_string(dir), dir, Map.fetch!(state.fetched, dir), state}
      end

    path = Cache.path(state.root, pp)

    if File.dir?(path) do
      point = %{
        uri: key,
        depth: depth,
        path: path,
        covered_by: covered_by,
        stale: outcome == :error,
        status: :accepted
      }

      state = %{state | points: [point | state.points]}
      source = {module, outcome, Map.get(validated, point_id(key, cert, resources))}
      children({cert, resources}, path, key, depth, [key | ancestors], source, state)
    else
      {[], issue(state, :missing, key, %{covered_by: covered_by})}
    end
  end

  # The CA certificates the manifest of `ca`'s publication point lists, at
  # `path`, that validate against it (`Lumina.Validate.point/5`), as
  # entries of the next level. A point that fails (RFC 9286 §6) is an
  # issue, and nothing below it is walked (§6.6).
  defp children(ca, path, key, depth, ancestors, source, state) do
    {result, state} = validated(ca, path, key, source, state)

    case result do
      %{point: %{status: :failed} = point} ->
        errors = Enum.filter(point.problems, &(&1.severity == :error))
        {[], point_status(issue(state, :point_failed, point.manifest || key, errors), :failed)}

      %{point: point, entries: entries} ->
        state =
          if point.status == :fallback,
            do:
              point_status(issue(state, :point_fallback, point.manifest, point.failed), :fallback),
            else: state

        entries
        |> Enum.reduce({[], state}, fn
          %{kind: :decode_failed, uri: name, reason: reason}, {acc, state} ->
            {acc, issue(state, :decode_failed, name, reason)}

          %{valid: true, problems: [], certificate: cert, uri: name} = e, {acc, state} ->
            {[{cert, name, depth + 1, ancestors, e.resources} | acc], state}

          %{valid: true, problems: warnings, certificate: cert, uri: name} = e, {acc, state} ->
            {[{cert, name, depth + 1, ancestors, e.resources} | acc],
             issue(state, :warning, name, warnings)}

          %{problems: problems, uri: name}, {acc, state} ->
            {acc, issue(state, :invalid, name, Enum.filter(problems, &(&1.severity == :error)))}
        end)
        |> then(fn {children, state} -> {Enum.reverse(children), state} end)
    end
  end

  # The point validated (`Validate.point/5`). If a copy fetched this run
  # fails only because listed files are missing or don't match their
  # hashes, the repository may have been caught mid-update (RFC 6481 §5,
  # D-007): its module is fetched once more and the point validated again.
  defp validated({ca, resources}, path, key, {module, outcome, first}, state) do
    validate = fn -> validate_point(ca, resources, path, key, state.now, state.root) end
    module_key = to_string(module)

    # A result from before this level's refetch of the module is stale.
    result =
      if first && not MapSet.member?(state.refetched_in_level, module_key),
        do: first,
        else: validate.()

    if outcome == :ok and mid_update?(result.point) and
         not MapSet.member?(state.refetched, module_key) do
      if hook = state.opts[:before_refetch], do: hook.(module_key)
      fetched = fetch(module, state)

      fetch = %{uri: module_key, outcome: fetched.outcome, detail: fetched.detail}

      state =
        Enum.reduce(fetched.issues, state, fn {kind, uri}, st -> issue(st, kind, uri, nil) end)

      state = %{
        forget(state, module)
        | refetched: MapSet.put(state.refetched, module_key),
          refetched_in_level: MapSet.put(state.refetched_in_level, module_key),
          fetches: [fetch | state.fetches]
      }

      state =
        issue(state, :refetched, module_key, %{
          manifest: result.point.manifest,
          reasons: live_errors(result.point)
        })

      {validate.(), state}
    else
      {result, state}
    end
  end

  defp validate_point(ca, resources, path, key, now, root),
    do: Validate.point(ca, path, key, now, last_valid: root, save: true, resources: resources)

  @mid_update [:file_missing, :hash_mismatch]

  defp mid_update?(point) do
    case live_errors(point) do
      [] -> false
      errors -> Enum.all?(errors, &(&1.rule in @mid_update))
    end
  end

  # Why the copy fetched this run failed, even when its last valid copy
  # stands in.
  defp live_errors(%{status: :fallback, failed: failed}), do: failed

  defp live_errors(%{status: :failed, problems: problems}),
    do: Enum.filter(problems, &(&1.severity == :error))

  defp live_errors(_point), do: []

  # Marks the point just recorded (the head of `points`) failed.
  defp point_status(%{points: [point | rest]} = state, status),
    do: %{state | points: [%{point | status: status} | rest]}

  defp covering(pp, fetched) do
    Enum.find_value(fetched, fn {%URI{} = dir, outcome} ->
      if dir.host == pp.host and dir.port == pp.port and
           List.starts_with?(pp.path, dir.path),
         do: {dir, outcome}
    end)
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
