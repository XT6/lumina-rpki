defmodule Lumina.Progress do
  @moduledoc """
  Progress reports for long-running work (#96): `lumina sync`, and
  validation in `lumina validate` and `lumina vrps` (#180). Every
  long-running operation reports progress (D-036).

  The work emits **events** through a `:progress` option, a one-argument
  function (`emit/2`). Library calls without it pay nothing. Fetches run
  in parallel tasks, so the function may be called from any process.

  Events of a sync:

    * `{:tal_started, path, index, total}`
    * `{:ta_trying, uri}`: TA retrieval tries a URI (`Lumina.TA`)
    * `{:level_started, level, %{points: n, fetches: n}}`: a walk level,
      with its publication points and the rsync runs it needs
    * `{:fetch_started, uri, host}` and
      `{:fetch_finished, uri, host, outcome, files}` (`files`: regular files
      in the publication point after the fetch)
    * `{:fetch_retrying, uri, host, error}`: a fetch that failed
      transiently ends this way instead, and starts again after a delay
      (D-039)
    * `{:level_finished, level, %{points: n, issues: n}}`: running totals
      for the walk

  Events of an RRDP repository sync (`Lumina.RRDP.Sync`, #203; drawn
  once the walk syncs over RRDP, #206):

    * `{:rrdp_started, notify}` and `{:rrdp_finished, notify, outcome}`
    * `{:rrdp_download, notify, kind, bytes}` every MiB received and
      `{:rrdp_downloaded, notify, kind, bytes}` once the file is in
      (`kind` is `:notification`, `:snapshot` or `:delta`)
    * `{:rrdp_objects, notify, count}`: snapshot objects written to the
      store, every 1000 and at the end, or delta elements applied
    * `{:rrdp_fallback, notify, reason}`: a delta was rejected, and the
      snapshot is used instead (#204)

  Events of a validation (`Lumina.Validate.run/3`):

    * `{:tal_started, path, index, total}`, sent by the CLI
    * `{:validation_level_started, level, %{points: n}}` and
      `{:validation_level_finished, level, %{points: n}}`: a level of the
      offline walk, with its publication points
    * `{:point_validated, %{objects: n, invalid: n}}`: a publication point
      validated, with its CA certificates and signed objects (its
      manifest included) and how many are invalid

  `update/3` folds events into a state and `render/3` turns a state into
  status text; both are pure. `start/2` runs them in a process that draws
  on a device:

    * `:tty`: one status line, redrawn in place at most every 200 ms;
    * `:plain`: timestamped lines, one per finished level and one every
      10 s, with no control characters, for logs and pipes.
  """

  @tty_interval 200
  @plain_interval 10_000

  @type event :: tuple()

  @doc "Calls the `:progress` function in `opts`, if there is one."
  @spec emit(keyword(), event()) :: :ok
  def emit(opts, event) do
    case opts[:progress] do
      nil -> :ok
      fun -> _ = fun.(event)
    end

    :ok
  end

  @doc "The initial state, at monotonic time `now` (milliseconds)."
  @spec new(integer()) :: map()
  def new(now) do
    %{
      started: now,
      tal: nil,
      tal_index: 0,
      tal_total: 0,
      ta: nil,
      level: nil,
      level_points: 0,
      points: 0,
      issues: 0,
      fetches_done: 0,
      fetches_failed: 0,
      fetches_retried: 0,
      level_fetches: 0,
      running: %{},
      files: 0,
      # Validation (#180): set by its events.
      validating: false,
      validated: 0,
      objects: 0,
      invalid: 0
    }
  end

  @doc "Folds `event`, received at monotonic time `now`, into `state`."
  @spec update(map(), event(), integer()) :: map()
  def update(state, {:tal_started, path, index, total}, _now) do
    %{
      state
      | tal: Path.basename(path),
        tal_index: index,
        tal_total: total,
        ta: nil,
        level: nil,
        running: %{}
    }
  end

  def update(state, {:ta_trying, uri}, _now), do: %{state | ta: uri}

  def update(state, {:level_started, level, %{points: points, fetches: fetches}}, _now),
    do: %{state | level: level, level_points: points, level_fetches: fetches}

  def update(state, {:fetch_started, uri, host}, now),
    do: %{state | running: Map.put(state.running, uri, {host, now})}

  def update(state, {:fetch_finished, uri, _host, outcome, files}, _now) do
    %{
      state
      | running: Map.delete(state.running, uri),
        fetches_done: state.fetches_done + 1,
        fetches_failed: state.fetches_failed + if(outcome == :ok, do: 0, else: 1),
        files: state.files + files
    }
  end

  def update(state, {:fetch_retrying, uri, _host, _error}, _now) do
    %{
      state
      | running: Map.delete(state.running, uri),
        fetches_retried: state.fetches_retried + 1
    }
  end

  def update(state, {:level_finished, _level, %{points: points, issues: issues}}, _now),
    do: %{state | points: points, issues: issues}

  def update(state, {:validation_level_started, level, %{points: points}}, _now),
    do: %{state | validating: true, level: level, level_points: points}

  def update(state, {:point_validated, %{objects: objects, invalid: invalid}}, _now) do
    %{
      state
      | validating: true,
        validated: state.validated + 1,
        objects: state.objects + objects,
        invalid: state.invalid + invalid
    }
  end

  def update(state, _other, _now), do: state

  @doc """
  Status text for `state` at monotonic time `now`, without a newline.
  `:tty` text is cut to `columns`.
  """
  @spec render(map(), integer(), keyword()) :: String.t()
  def render(state, now, opts \\ []) do
    parts =
      [
        "#{seconds(now - state.started)}s",
        state.tal && "#{state.tal} (#{state.tal_index}/#{state.tal_total})",
        stage(state)
        | if(state.validating, do: validation(state), else: fetching(state, now))
      ]
      |> Enum.filter(& &1)

    text = Enum.join(parts, "  ")

    case opts[:columns] do
      nil -> text
      columns -> String.slice(text, 0, max(columns - 1, 10))
    end
  end

  defp fetching(state, now) do
    [
      state.level != nil && "points #{state.points}",
      state.level != nil && rsync(state),
      state.level != nil && "files #{state.files}",
      slowest(state, now)
    ]
  end

  defp validation(state) do
    [
      "points #{state.validated}",
      "objects #{state.objects}",
      state.invalid > 0 && "invalid #{state.invalid}"
    ]
  end

  defp stage(%{level: nil, ta: nil}), do: nil
  defp stage(%{level: nil, ta: ta}), do: "ta: #{ta}"

  defp stage(%{level: level, level_points: points}),
    do: "level #{level} (#{points} point#{if points == 1, do: "", else: "s"})"

  defp rsync(state) do
    failed = if state.fetches_failed > 0, do: ", #{state.fetches_failed} failed", else: ""
    retried = if state.fetches_retried > 0, do: ", #{state.fetches_retried} retried", else: ""
    "rsync #{state.fetches_done} done, #{map_size(state.running)} running#{failed}#{retried}"
  end

  # The fetch running longest, once it has taken more than 5 s: a slow or
  # stuck host shows here.
  defp slowest(%{running: running}, now) when map_size(running) > 0 do
    {host, since} = running |> Map.values() |> Enum.min_by(&elem(&1, 1))
    elapsed = now - since
    if elapsed > 5_000, do: "slowest: #{host} #{seconds(elapsed)}s"
  end

  defp slowest(_state, _now), do: nil

  defp seconds(ms), do: div(ms, 1000)

  # The drawing process.

  @doc """
  Starts a process drawing progress on `device` in `mode` (`:tty` or
  `:plain`). Returns the function to pass as `:progress`, and a stop
  function that draws the last state, ends the line and waits.
  """
  @spec start(IO.device(), :tty | :plain) :: {(event() -> any()), (-> :ok)}
  def start(device, mode) do
    pid =
      spawn_link(fn ->
        loop(%{device: device, mode: mode, state: new(now()), drawn: 0, dirty: false})
      end)

    stop = fn ->
      ref = Process.monitor(pid)
      send(pid, {:stop, self()})

      receive do
        {:DOWN, ^ref, _, _, _} -> :ok
      end
    end

    {fn event -> send(pid, {:progress, event, now()}) end, stop}
  end

  defp loop(%{mode: mode} = r) do
    interval = if mode == :tty, do: @tty_interval, else: @plain_interval

    receive do
      {:progress, event, at} ->
        r = %{r | state: update(r.state, event, at), dirty: true}

        cond do
          mode == :plain and match?({:level_finished, _, _}, event) -> loop(draw(r))
          mode == :plain and match?({:validation_level_finished, _, _}, event) -> loop(draw(r))
          mode == :plain and match?({:tal_started, _, _, _}, event) -> loop(draw(r))
          now() - r.drawn >= interval -> loop(draw(r))
          true -> loop(r)
        end

      {:stop, _from} ->
        _ =
          cond do
            mode == :tty -> IO.write(r.device, "\r\e[2K")
            r.dirty -> draw(r)
            true -> :ok
          end

        :ok
    after
      interval -> loop(draw(r))
    end
  end

  defp draw(%{mode: :tty} = r) do
    IO.write(r.device, ["\r\e[2K", render(r.state, now(), columns: columns())])
    %{r | drawn: now(), dirty: false}
  end

  defp draw(%{mode: :plain} = r) do
    stamp = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    IO.write(r.device, "#{stamp} #{render(r.state, now())}\n")
    %{r | drawn: now(), dirty: false}
  end

  defp columns do
    case :io.columns() do
      {:ok, columns} -> columns
      _ -> 80
    end
  end

  defp now, do: System.monotonic_time(:millisecond)

  @doc """
  Whether stderr is a terminal. OTP has no documented call for this;
  `:prim_tty.isatty/1` (OTP 26 and later) answers it, and anything else
  counts as not a terminal.
  """
  @spec stderr_tty?() :: boolean()
  def stderr_tty? do
    :prim_tty.isatty(:stderr) == true
  rescue
    _ -> false
  end
end
