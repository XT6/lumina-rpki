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

  **RRDP first (D-040, #206):** a CA whose certificate names an HTTPS
  `rpkiNotify` (the first one, `notify_uri/1`) is synced over RRDP
  (`Lumina.RRDP.Sync`), and its publication point read from the
  repository's store (`Lumina.RRDP.Store`). The notification URI is then
  the unit of fetching, as the module is for rsync: synced once per run
  (and once per sync, through `:fetched`) for every CA that names it,
  at most `:per_host` at once per host (HTTPS and rsync counted apart),
  retried once after a dropped connection (D-039). When the sync fails
  (`rrdp_failed`), the CA's rsync module is fetched in the same run
  (`rrdp_fallback`) and the point read from rsync; the last good store
  stays for the next run. `rrdp: false` (`lumina sync --no-rrdp`, #208)
  turns RRDP off. Each accepted point's source is recorded
  (`Lumina.Source`).

  **Fetching once:** a publication point in a module already fetched in
  this run (same host and port, same module) isn't fetched again; it's
  read from the copy that fetch brought (D-012). Each
  fetch is staged and committed with `Lumina.Cache`, so a failed fetch
  keeps the last good copy (RFC 8897 §7); the walk then continues from that
  copy, marked stale, and the failure is reported. A failed fetch also
  covers the rest of its module for the rest of the run, so it isn't
  retried for each publication point. A sync walks each TAL's tree in
  turn, and passes what one walk fetched to the next (`:fetched`,
  `:refetched`, #102): a module several trees share, such as a hosted
  repository serving CAs under several RIRs, is fetched once per sync,
  and a module that failed isn't retried.

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
  fetched over rsync this run (an RRDP repository is applied atomically) that fails only because files its manifest lists are
  missing or don't match their hashes (RFC 9286 §6.4, §6.5) may have been
  read while its repository was being updated. Its module is fetched once
  more and the point validated again; a module is fetched again at most
  once per run, and the retry is reported (`:refetched`).

  **A dropped connection (D-039, #193):** a module fetch that fails in a
  way that may not happen again (`Lumina.Rsync.transient?/1`: the
  connection dropped, a socket error, a connect timeout) is tried once
  more after a short delay (10 to 30 s, random), into the same staging
  directory, so rsync fetches only what the first run didn't bring. The
  delay doesn't hold the host's place (D-011): the retry queues again
  first in line. A module is retried at most once per sync: the result's
  `:fetched` carries its final outcome to the next walk, which doesn't
  fetch it again. The mid-update refetch below isn't retried.

  **Limits (D-008):** a certificate deeper than `:max_depth` (the TA is
  depth 0) isn't followed, and a publication point already visited isn't
  walked again: a loop if it is the publication point of an ancestor,
  otherwise a duplicate. Both are reported, and neither stops the rest of
  the walk. A publication point is identified by its CA's manifest
  (`point_key/2`): several CAs may share one directory, each with its own
  manifest (RFC 9286 §1, RFC 6481 §2.2), and each is walked (#195).

  The result:

    * `:points`: each publication point walked, with its depth, the path
      it was read from, the fetch that covered it (`covered_by`: the
      module or notification URI), its `source` (`{:rrdp, notify}` or
      `{:rsync, module}`), whether the copy is `stale` and
      its `status` (`:accepted`, `:failed`, or `:fallback` when its last
      valid copy stands in, RFC 9286 §6, D-023);
    * `:fetches`: each rsync run, by module URI, with its outcome (their number is the
      number of rsync runs; a first run that was retried is `:retried`);
    * `:rrdp`: each RRDP repository this walk synced, the
      `Lumina.RRDP.Sync` result (outcome, session, serial, warnings);
    * `:fetched` and `:refetched`: every module fetched (or attempted) so
      far, with its outcome, and those fetched again after a mid-update
      failure, including the ones given as options, for the next walk of
      the same sync;
    * `:issues`: everything reported, as `%{kind, uri, detail}`, `kind` one
      of `:fetch_failed`, `:loop`, `:duplicate`, `:depth_exceeded`,
      `:decode_failed`, `:point_failed` (a publication point RFC 9286 §6
      rejects, by its manifest URI; the detail lists the reasons),
      `:refetched` (a module fetched again because a point in it was caught
      mid-update; the detail names the manifest and the reasons),
      `:retried` (a module fetched or an RRDP repository synced once more
      after a transient failure; the detail is the first run's error),
      `:rrdp_failed` (an RRDP sync that failed, by notification URI; the
      detail has its `reason` and `error`), `:rrdp_fallback` (the rsync
      module fetched instead, D-040; the detail names the notification),
      `:rrdp_warning` (a sync's warnings, D-042, RFC 9697, and a rejected
      delta that gave way to the snapshot),
      `:point_fallback` (one that failed but whose last valid copy, D-023,
      is used instead; the detail lists why the live copy failed),
      `:invalid` (a CA that doesn't validate; the detail lists its errors), `:warning` (a valid CA's warnings), `:no_repository`,
      `:bad_uri`, `:oversize`,
      `:removed` (symlinks or special files dropped by `Cache.commit/3`)
      and `:missing` (a publication point that was never fetched and has
      no copy).
  """

  alias Lumina.{Cache, Certificate, Progress, Rsync, Source, URI, Validate}
  alias Lumina.RRDP.Sync, as: RRDPSync

  @default_max_depth 32
  @default_per_host 8

  @type issue :: %{kind: atom(), uri: String.t(), detail: term()}
  @type point :: %{
          uri: String.t(),
          depth: non_neg_integer(),
          path: Path.t(),
          covered_by: String.t(),
          source: Source.source(),
          stale: boolean(),
          status: :accepted | :failed | :fallback
        }
  @type fetch :: %{uri: String.t(), outcome: :ok | :error | :retried, detail: term()}
  @type result :: %{
          points: [point()],
          fetches: [fetch()],
          issues: [issue()],
          fetched: %{URI.t() => :ok | :error},
          refetched: MapSet.t(String.t()),
          rrdp: [RRDPSync.result()]
        }

  @doc """
  Walks from `ta` (an accepted TA certificate) into the cache at `root`.

  Options: `:max_depth` (default 32), `:per_host` (rsync runs at once per
  host, default 8), `:now` (the validation time, also recorded for each
  fetch; default now),
  `:progress` (a `Lumina.Progress` listener, sent level and fetch events),
  `:before_refetch` (tests only: called with the module URI just before a
  mid-update retry, so a test can finish the "update"),
  `:fetched` and `:refetched` (the result's, from an earlier walk of the
  same sync: modules not to fetch again, #102),
  `:rrdp` (default `true`, or the `:lumina` application's `:rrdp`
  setting, which the test suite sets to `false`), `:rrdp_opts` (options
  for `Lumina.RRDP.Sync.run/3`, such as `:cacerts` in tests),
  `:rsync` (options for `Lumina.Rsync.fetch_dir/3`), `:retry_delay`
  (milliseconds before retrying a transient failure, D-039; default
  random between 10 and 30 s; tests set it low), and `:remap`,
  for tests: a map from `"host:port"` in repository URIs to the
  `"host:port"` actually connected to, for rsync and RRDP alike.
  Remapping changes only where connections go; cache paths and reports
  keep the URIs from the certificates.
  """
  @spec run(Certificate.t(), Path.t(), keyword()) :: result()
  def run(%Certificate{} = ta, root, opts \\ []) do
    state = %{
      root: root,
      opts: opts,
      max_depth: Keyword.get(opts, :max_depth, @default_max_depth),
      per_host: Keyword.get(opts, :per_host, @default_per_host),
      now: Keyword.get_lazy(opts, :now, &DateTime.utc_now/0),
      # RRDP for CAs that name a notification URI (D-040); off with
      # `rrdp: false` (the test suite's default, test_helper.exs).
      rrdp: Keyword.get_lazy(opts, :rrdp, fn -> Application.get_env(:lumina, :rrdp, true) end),
      # Units of fetching (rsync modules, RRDP notification URIs) whose
      # fetch this walk has reported, and the RRDP syncs reported.
      reported: MapSet.new(),
      rrdp_results: [],
      # Units fetched (or attempted) this run: URI => :ok | :error
      # (:planned while a level is being planned), starting with those of
      # earlier walks in the same sync (#102).
      fetched: Keyword.get(opts, :fetched, %{}),
      visited: MapSet.new(),
      # Modules fetched again this run because a point in them was caught
      # mid-update (RFC 6481 §5): at most once each.
      refetched: Keyword.get(opts, :refetched, MapSet.new()),
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
        # Modules whose first run failed transiently, back in the queue:
        # module => {staging directory, first error} (D-039).
        retries: %{},
        # Set when the walk is over: retries still pending are dropped.
        draining: false,
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
      issues: Enum.reverse(state.issues),
      fetched: state.fetched,
      refetched: state.refetched,
      rrdp: Enum.reverse(state.rrdp_results)
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

  @doc """
  What identifies `cert`'s publication point `pp` in a walk (#195): the
  rsync URI of its manifest (SIA `rpkiManifest`, RFC 6487 §4.8.8.1), or
  `pp` itself if it names none. Several CAs may publish in one
  `caRepository` directory, each with its own manifest (RFC 9286 §1,
  RFC 6481 §2.2), so the directory alone doesn't identify a CA's point.
  """
  @spec point_key(Certificate.t(), URI.t()) :: String.t()
  def point_key(%Certificate{} = cert, %URI{} = pp) do
    case Enum.find(Certificate.sia_uris(cert, :rpki_manifest), &rsync?/1) do
      nil -> to_string(pp)
      manifest -> manifest
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
    depth = level |> hd() |> elem(2)
    points = for {:point, {cert, _, _, _, _}, pp} <- plans, do: {cert, pp}

    # The fetches this level still needs (some may run ahead already).
    to_fetch =
      for({cert, pp} <- points, {:ok, unit} <- [unit(state, cert, pp)], do: unit)
      |> Enum.uniq()
      |> Enum.reject(&unit_done?(state, &1))

    Progress.emit(
      state.opts,
      {:level_started, depth, %{points: length(points), fetches: length(to_fetch)}}
    )

    {ids, state} = settle(plans, state)
    validated = Map.take(state.pool.validated, ids)

    state = %{
      state
      | pool: %{state.pool | validated: Map.drop(state.pool.validated, ids)},
        refetched_in_level: MapSet.new()
    }

    {next, state} = Enum.flat_map_reduce(plans, state, &report(&1, &2, validated))

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
      for {:point, {cert, _name, depth, ancestors, resources}, pp} <- plans,
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

  # Validates a point once its unit of fetching is in: now if it is
  # (fetched earlier this run), else when its fetch, requested here,
  # finishes. A point already scheduled for the same certificate and
  # resources isn't scheduled again.
  defp schedule(state, {cert, resources, pp, _depth, _ancestors} = point) do
    id = point_id(to_string(pp), cert, resources)

    if MapSet.member?(state.pool.claimed, id),
      do: state,
      else: state |> update_in([:pool, :claimed], &MapSet.put(&1, id)) |> wait_for(id, point)
  end

  # Requests the point's unit of fetching, or queues the point for
  # validation if it is done. Called again when an RRDP sync fails: the
  # unit is then the point's rsync module (D-040).
  defp wait_for(state, id, {cert, _resources, pp, _depth, _ancestors} = point) do
    case unit(state, cert, pp) do
      {:ok, unit} ->
        if unit_done?(state, unit) do
          enqueue(state, id, point)
        else
          state
          |> request(unit)
          |> update_in(
            [:pool, :waiting],
            &Map.update(&1, unit, [{id, point}], fn l -> [{id, point} | l] end)
          )
        end

      {:error, _} ->
        state
    end
  end

  # What a point is fetched with (D-040, #206): its CA's RRDP repository,
  # the first HTTPS rpkiNotify in its SIA (RFC 8182 §3.2), unless RRDP is
  # off or that repository failed this run; otherwise its rsync module
  # (D-012). Either way a `Lumina.URI`, the key of the fetch.
  defp unit(state, cert, pp) do
    with true <- state.rrdp,
         {:ok, notify} <- notify_uri(cert),
         false <- unit_outcome(state, notify) == :error do
      {:ok, notify}
    else
      _ -> URI.module(pp)
    end
  end

  @doc """
  The RRDP repository of `cert`: the first HTTPS `rpkiNotify` URI in its
  SIA (RFC 8182 §3.2) that `Lumina.URI.parse/1` accepts, or `:none`.
  """
  @spec notify_uri(Certificate.t()) :: {:ok, URI.t()} | :none
  def notify_uri(%Certificate{} = cert) do
    cert
    |> Certificate.sia_uris(:rpki_notify)
    |> Enum.find_value(:none, fn uri ->
      with true <- String.starts_with?(String.downcase(uri), "https://"),
           {:ok, notify} <- URI.parse(uri),
           do: {:ok, notify},
           else: (_ -> nil)
    end)
  end

  # The outcome of a unit's fetch this run or in an earlier walk of the
  # same sync (#102): :ok, :error, or nil if not fetched yet.
  defp unit_outcome(state, unit) do
    case state.pool.done do
      %{^unit => %{outcome: outcome}} -> outcome
      _ -> Map.get(state.fetched, unit)
    end
  end

  defp unit_done?(state, unit), do: unit_outcome(state, unit) in [:ok, :error]

  # Where a point is read: its repository's RRDP store (#201) when RRDP
  # serves it, else the rsync tree.
  defp point_path(state, cert, pp) do
    case unit(state, cert, pp) do
      {:ok, %URI{scheme: "https"} = notify} -> Source.path(state.root, {:rrdp, notify}, pp)
      _ -> Source.path(state.root, :rsync, pp)
    end
  end

  # Queues a point for validation if it is in the cache; otherwise
  # `report/3` finds it missing.
  defp enqueue(state, id, {cert, _resources, pp, _depth, _ancestors} = point) do
    if File.dir?(point_path(state, cert, pp)),
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
          {:fetch, module} when result.outcome == :retry ->
            retry_later(state, module, result)

          {:retry_wait, module, retry} ->
            retry_now(state, module, retry)

          {:fetch, module} ->
            state = fetched(state, module, result)
            {points, waiting} = Map.pop(state.pool.waiting, module, [])
            state = put_in(state.pool.waiting, waiting)

            # Validated now, or, after a failed RRDP sync, waiting for
            # their rsync modules (D-040).
            Enum.reduce(Enum.reverse(points), state, fn {id, point}, st ->
              wait_for(st, id, point)
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
  defp ahead(state, {ca, _resources, pp, depth, ancestors}, %{
         point: %{status: status},
         entries: entries
       })
       when status != :failed do
    ancestors = [point_key(ca, pp) | ancestors]

    Enum.reduce(entries, state, fn
      %{valid: true, certificate: cert, resources: resources}, st when depth < st.max_depth ->
        with {:ok, child} <- repository(cert),
             child_key = point_key(cert, child),
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
    path = point_path(state, cert, pp)
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
      host = host(module)
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
        {retry, retries} = Map.pop(state.pool.retries, module, :allowed)

        task =
          case module do
            %URI{scheme: "https"} -> Task.async(fn -> rrdp_fetch(module, context, retry) end)
            _ -> Task.async(fn -> fetch(module, context, retry) end)
          end

        pool = %{state.pool | retries: retries}

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
    state
    |> update_in([:pool, :done], &Map.put(&1, module, result))
    |> release(module)
  end

  # The fetch of `module` no longer holds its host's place (D-011).
  defp release(state, module) do
    host = host(module)
    state |> update_in([:pool, :running, host], &(&1 - 1)) |> start_fetches(host)
  end

  # A transient failure (D-039): the host's place goes to the next fetch
  # while a task waits out the delay, then the module queues again, first
  # in line.
  defp retry_later(state, module, %{staging: staging, detail: error}) do
    state = release(state, module)

    if state.pool.draining do
      abandon(state, module, staging, error)
    else
      delay = Keyword.get_lazy(state.opts, :retry_delay, fn -> Enum.random(10_000..30_000) end)
      task = Task.async(fn -> Process.sleep(delay) end)
      put_in(state.pool.tasks[task.ref], {:retry_wait, module, {staging, error}})
    end
  end

  defp retry_now(state, module, {staging, error} = retry) do
    if state.pool.draining do
      abandon(state, module, staging, error)
    else
      host = host(module)

      state
      |> update_in([:pool, :retries], &Map.put(&1, module, retry))
      |> update_in([:pool, :queued], &Map.update(&1, host, [module], fn q -> [module | q] end))
      |> start_fetches(host)
    end
  end

  # A retry the walk no longer needs: the first run's failure stands.
  # (An RRDP sync has no staging directory and records its own state.)
  defp abandon(state, %URI{scheme: "https"}, _staging, _error), do: state

  defp abandon(state, module, staging, error) do
    Cache.discard(staging)
    Cache.record(state.root, module, {:error, error}, state.now)
    state
  end

  # Fetches run at most `:per_host` at once per host (D-011); rsync and
  # HTTPS on one host count separately.
  defp host(%URI{} = unit), do: {unit.scheme, unit.host, unit.port}

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
    pool = %{state.pool | queued: %{}, validations: [], waiting: %{}, draining: true}

    # Retries already queued again are dropped too.
    state =
      Enum.reduce(pool.retries, %{state | pool: %{pool | retries: %{}}}, fn
        {module, {staging, error}}, st -> abandon(st, module, staging, error)
      end)

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
        id = point_key(cert, pp)

        cond do
          depth > state.max_depth ->
            {{:issue, :depth_exceeded, key, %{certificate: name, depth: depth}}, state}

          id in ancestors ->
            {{:issue, :loop, key, %{certificate: name}}, state}

          MapSet.member?(state.visited, id) ->
            {{:issue, :duplicate, key, %{certificate: name}}, state}

          true ->
            state = %{state | visited: MapSet.put(state.visited, id)}

            # The whole module is fetched (D-012), or the CA's RRDP
            # repository synced (D-040): `unit/3`, once a point is reported.
            case URI.module(pp) do
              {:ok, _module} -> {{:point, entry, pp}, state}
              {:error, error} -> {{:issue, :bad_uri, key, error}, state}
            end
        end
    end
  end

  defp report(:skip, state, _results), do: {[], state}

  defp report({:issue, kind, uri, detail}, state, _results),
    do: {[], issue(state, kind, uri, detail)}

  defp report({:point, {cert, _name, depth, ancestors, resources}, pp}, state, validated) do
    key = to_string(pp)
    {unit, state} = report_units(state, cert, pp)
    outcome = unit_outcome(state, unit)
    covered_by = to_string(unit)
    path = point_path(state, cert, pp)

    if File.dir?(path) do
      source =
        case unit do
          %URI{scheme: "https"} -> {:rrdp, unit}
          _ -> {:rsync, unit}
        end

      point = %{
        uri: key,
        depth: depth,
        path: path,
        covered_by: covered_by,
        source: source,
        stale: outcome == :error,
        status: :accepted
      }

      state = %{state | points: [point | state.points]}
      first = Map.get(validated, point_id(key, cert, resources))
      ancestors = [point_key(cert, pp) | ancestors]

      {children, state} =
        children({cert, resources}, path, key, depth, ancestors, {unit, outcome, first}, state)

      # Where the point was read from, for offline validation (#207),
      # which then sees the copy this walk saw (or its last valid copy).
      _ = Source.save(state.root, point_key(cert, pp), source, state.now)

      {children, state}
    else
      {[], issue(state, :missing, key, %{covered_by: covered_by})}
    end
  end

  # Reports the fetches a point was read from, the first time each comes
  # up in walk order: its RRDP sync and, if that failed, its rsync module
  # (D-040). Returns the unit the point is read from.
  defp report_units(state, cert, pp) do
    {:ok, module} = URI.module(pp)

    with true <- state.rrdp,
         {:ok, notify} <- notify_uri(cert) do
      state = report_unit(state, notify)

      if unit_outcome(state, notify) == :error do
        # Only the walk that ran the sync reports the fallback (#102).
        fallback? =
          Map.has_key?(state.pool.done, notify) and
            not MapSet.member?(state.reported, {notify, module})

        state =
          if fallback?,
            do:
              issue(
                %{state | reported: MapSet.put(state.reported, {notify, module})},
                :rrdp_fallback,
                to_string(module),
                %{notify: to_string(notify)}
              ),
            else: state

        {module, report_unit(state, module)}
      else
        {notify, state}
      end
    else
      _ -> {module, report_unit(state, module)}
    end
  end

  # A fetch run by this walk, reported once; one an earlier walk ran
  # (`:fetched`) was reported there.
  defp report_unit(state, unit) do
    with %{^unit => result} <- state.pool.done,
         false <- MapSet.member?(state.reported, unit) do
      state = %{
        state
        | reported: MapSet.put(state.reported, unit),
          fetched: Map.put(state.fetched, unit, result.outcome)
      }

      report_fetch(state, unit, result)
    else
      _ -> state
    end
  end

  defp report_fetch(state, %URI{scheme: "https"} = notify, result) do
    uri = to_string(notify)
    sync = result.rrdp
    state = %{state | rrdp_results: [sync | state.rrdp_results]}

    state =
      case result.retried do
        nil -> state
        first -> issue(state, :retried, uri, first.error)
      end

    state =
      if sync.warnings != [] or sync.fallback,
        do: issue(state, :rrdp_warning, uri, %{warnings: sync.warnings, fallback: sync.fallback}),
        else: state

    case sync.outcome do
      {:failed, reason} -> issue(state, :rrdp_failed, uri, %{reason: reason, error: sync.error})
      _ -> state
    end
  end

  defp report_fetch(state, module, result) do
    fetched = to_string(module)

    state =
      Enum.reduce(result.issues, state, fn {kind, uri}, st -> issue(st, kind, uri, nil) end)

    # A first run that failed transiently and was retried (D-039).
    state =
      case result.retried do
        nil ->
          state

        first ->
          retried = %{uri: fetched, outcome: :retried, detail: first}
          issue(%{state | fetches: [retried | state.fetches]}, :retried, fetched, first)
      end

    state =
      if result.outcome == :error,
        do: issue(state, :fetch_failed, fetched, result.detail),
        else: state

    fetch = %{uri: fetched, outcome: result.outcome, detail: result.detail}
    %{state | fetches: [fetch | state.fetches]}
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

    # Only rsync: an RRDP repository is applied atomically.
    if module.scheme == "rsync" and outcome == :ok and mid_update?(result.point) and
         not MapSet.member?(state.refetched, module_key) do
      if hook = state.opts[:before_refetch], do: hook.(module_key)
      fetched = fetch(module, state, :no)

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

  # One rsync run into a staging directory, committed on success. Returns
  # the outcome, its detail and the issues it raised, as {kind, uri}, and
  # the first run's error if this is a retry (`retried`). `retry` is
  # `:allowed` (a transient failure returns outcome `:retry` with the
  # staging directory, kept for the retry), `:no`, or the
  # `{staging, first error}` of the run being retried (D-039).
  defp fetch(pp, state, retry) do
    %{root: root, opts: opts} = state
    key = to_string(pp)
    live = Cache.path(root, pp)
    rsync_opts = Keyword.get(opts, :rsync, [])
    rsync_opts = if File.dir?(live), do: [{:link_dest, live} | rsync_opts], else: rsync_opts
    Progress.emit(opts, {:fetch_started, key, pp.host})

    {staged, first} =
      case retry do
        {staging, first} -> {{:ok, staging}, first}
        _ -> {Cache.stage(root), nil}
      end

    result =
      with {:ok, staging} <- staged do
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
            if retry == :allowed and Rsync.transient?(error) do
              %{outcome: :retry, detail: error, issues: [], staging: staging}
            else
              Cache.discard(staging)
              %{outcome: :error, detail: error, issues: []}
            end
        end
      else
        {:error, reason} -> %{outcome: :error, detail: {:stage_failed, reason}, issues: []}
      end

    finished(Map.put(result, :retried, first), pp, live, state)
  end

  # One RRDP repository synced (`Lumina.RRDP.Sync`, #203 to #205): its
  # outcome is :ok when its store can be read this run (snapshot, deltas,
  # unchanged or recent), :error otherwise (D-040). A failure that may not
  # happen again (the connection dropped, a socket error, a connect
  # timeout) is :retry when allowed (D-039).
  defp rrdp_fetch(notify, context, retry) do
    %{root: root, opts: opts, now: now} = context
    key = to_string(notify)
    Progress.emit(opts, {:fetch_started, key, notify.host})

    sync_opts =
      [now: now, progress: opts[:progress], remap: opts[:remap]]
      |> Enum.reject(&is_nil(elem(&1, 1)))
      |> Keyword.merge(Keyword.get(opts, :rrdp_opts, []))

    sync = RRDPSync.run(notify, root, sync_opts)
    first = with {_staging, first} <- retry, do: first, else: (_ -> nil)

    result =
      case sync.outcome do
        {:failed, _} ->
          if retry == :allowed and transient_https?(sync.error),
            do: %{outcome: :retry, detail: sync, issues: [], staging: nil},
            else: %{outcome: :error, detail: sync, issues: []}

        _ ->
          %{outcome: :ok, detail: nil, issues: []}
      end
      |> Map.merge(%{rrdp: sync, retried: first})

    if result.outcome == :retry do
      Progress.emit(opts, {:fetch_retrying, key, notify.host, sync.error})
    else
      Progress.emit(
        opts,
        {:fetch_finished, key, notify.host, result.outcome, sync.objects || 0}
      )
    end

    result
  end

  defp transient_https?(%{reason: reason}),
    do: reason in [:socket_error, :connect_timeout, :truncated]

  defp transient_https?(_error), do: false

  defp finished(%{outcome: :retry} = result, pp, _live, state) do
    Progress.emit(state.opts, {:fetch_retrying, to_string(pp), pp.host, result.detail})
    result
  end

  defp finished(result, pp, live, state) do
    status = if result.outcome == :ok, do: :ok, else: {:error, result.detail}
    Cache.record(state.root, pp, status, state.now)

    Progress.emit(
      state.opts,
      {:fetch_finished, to_string(pp), pp.host, result.outcome, files(state.opts, live, result)}
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
