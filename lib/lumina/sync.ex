defmodule Lumina.Sync do
  @moduledoc """
  One sync run (#76): for each TAL, retrieve its TA (`Lumina.TA`, #74) and
  walk its repository into the cache (`Lumina.Walk`, #75). The `lumina
  sync` command (`Lumina.CLI`) parses the flags and prints `summary/1`.

  A run starts with `Lumina.Cache.recover/1`, which repairs what an
  interrupted run left. Two runs on one cache at once would stage and swap
  the same directories, so a run holds a lock file, `<cache>/.lock`, with
  its OS process id. A lock whose process no longer exists was left by a
  crash and is taken over.

  If every URI of a TAL fails but an earlier run accepted its TA, the walk
  goes ahead from that stale TA, and the failure is reported.

  The TALs are walked one after the other, and each walk starts with the
  modules the earlier ones fetched (#102): a module that several trees
  share is fetched once per run, and one that failed isn't retried. A
  point in it is reported by the walk that reaches it, covered by that
  module; the fetch, and a failure, by the walk that ran it.

  When a TAL's walk has run, the time is recorded in
  `<cache>/.state/syncs/<TA SKI hex>.json`, keyed like the stored TA, and
  `last_synced/2` reads it back: `lumina vrps --sync` syncs a TAL whose
  last sync is older than `--max-age` (#185, D-037). A walk that ran
  counts even if some fetches failed (a delegated host that is always
  down would otherwise force a sync every time); a TAL whose TA couldn't
  be retrieved, with no earlier TA to walk from, doesn't.
  """

  alias Lumina.{Cache, Progress, TA, TAL, Walk}

  @type report :: %{
          tal: Path.t(),
          ta: {:ok, map()} | {:error, map()},
          walk: Walk.result() | nil,
          failed?: boolean()
        }

  @doc """
  Runs the TALs `tals` (`[{path, %TAL{}}]`) into the cache at `root`.
  Returns one report per TAL, in order, or `{:error, {:locked, pid}}`.

  Options are passed on: `:timeout` (seconds, rsync I/O and the whole
  HTTPS fetch), `:max_depth`, `:per_host`, `:now`, `:progress` (a `Lumina.Progress`
  listener), and for tests `:https`, `:rsync` and `:remap`.
  """
  @spec run([{Path.t(), TAL.t()}], Path.t(), keyword()) ::
          {:ok, [report()]} | {:error, {:locked, String.t()} | File.posix()}
  def run(tals, root, opts \\ []) do
    with :ok <- File.mkdir_p(root),
         :ok <- lock(root) do
      try do
        {:ok, _} = Cache.recover(root)
        total = length(tals)

        # What each walk fetched goes to the next (#102), so a module
        # shared by several trees is fetched once.
        {reports, _modules} =
          tals
          |> Enum.with_index(1)
          |> Enum.map_reduce([], fn {{path, tal}, index}, modules ->
            Progress.emit(opts, {:tal_started, path, index, total})
            report = sync_tal(path, tal, root, modules ++ opts)

            # When the walk ran (#185): lumina vrps --sync measures age from it.
            _ =
              if report.walk,
                do: record(root, tal, Keyword.get_lazy(opts, :now, &DateTime.utc_now/0))

            {report,
             if(report.walk,
               do: Map.to_list(Map.take(report.walk, [:fetched, :refetched])),
               else: modules
             )}
          end)

        {:ok, reports}
      after
        unlock(root)
      end
    end
  end

  @doc """
  Whether a report's TAL synced at its root (#185, D-037): its TA was
  retrieved this run, not a stale copy, and the TA's own publication point
  was fetched (its module's fetch didn't fail). Failures further down
  don't count; `lumina vrps --sync` only warns about them.
  """
  @spec ta_synced?(report()) :: boolean()
  def ta_synced?(%{ta: {:ok, _}, walk: %{points: [%{depth: 0, stale: false} | _]}}), do: true
  def ta_synced?(_report), do: false

  @doc """
  When `tal`'s tree was last synced into the cache at `root` (its walk
  ran), or `nil` if never, or if the record can't be read.
  """
  @spec last_synced(Path.t(), TAL.t()) :: DateTime.t() | nil
  def last_synced(root, %TAL{} = tal) do
    with {:ok, text} <- File.read(state_file(root, tal)),
         {:ok, %{"synced_at" => at}} <- JSON.decode(text),
         {:ok, time, 0} <- DateTime.from_iso8601(at) do
      time
    else
      _ -> nil
    end
  end

  defp record(root, tal, time) do
    file = state_file(root, tal)
    temp = file <> ".tmp"

    with :ok <- File.mkdir_p(Path.dirname(file)),
         :ok <- File.write(temp, JSON.encode!(%{"synced_at" => DateTime.to_iso8601(time)})),
         do: File.rename(temp, file)
  end

  defp state_file(root, tal) do
    ski = Base.encode16(TAL.subject_key_identifier(tal), case: :lower)
    Path.join([root, ".state", "syncs", ski <> ".json"])
  end

  defp sync_tal(path, tal, root, opts) do
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)
    opts = Keyword.put(fetcher_opts(opts), :now, now)

    case TA.retrieve(tal, root, opts) do
      {:ok, ta} ->
        walk = Walk.run(ta.certificate, root, opts)
        %{tal: path, ta: {:ok, ta}, walk: walk, failed?: walk_failed?(walk)}

      {:error, %{stale: nil}} = error ->
        %{tal: path, ta: error, walk: nil, failed?: true}

      {:error, %{stale: stale}} = error ->
        %{tal: path, ta: error, walk: Walk.run(stale.certificate, root, opts), failed?: true}
    end
  end

  # :timeout reaches both fetchers.
  defp fetcher_opts(opts) do
    case opts[:timeout] do
      nil ->
        opts

      timeout ->
        opts
        |> Keyword.update(:rsync, [timeout: timeout], &Keyword.put(&1, :timeout, timeout))
        |> Keyword.update(:https, [timeout: timeout], &Keyword.put(&1, :timeout, timeout))
    end
  end

  defp walk_failed?(walk), do: Enum.any?(walk.issues, &(&1.kind in [:fetch_failed, :missing]))

  @doc "A text summary of the reports, one block per TAL."
  @spec summary([report()]) :: String.t()
  def summary(reports) do
    blocks = Enum.map(reports, &tal_block/1)
    fetches = reports |> Enum.flat_map(&if(&1.walk, do: &1.walk.fetches, else: [])) |> length()
    failed = Enum.count(reports, & &1.failed?)

    Enum.join(blocks, "\n") <>
      "\n#{length(reports)} TAL(s), #{fetches} rsync fetch(es), #{failed} TAL(s) with failures\n"
  end

  defp tal_block(report) do
    [
      "#{report.tal}\n",
      ta_lines(report.ta),
      walk_lines(report.walk)
    ]
    |> IO.iodata_to_binary()
  end

  defp ta_lines({:ok, ta}) do
    [
      "  ta: #{ta.uri}\n",
      failed_attempts(ta.attempts),
      warnings(ta.attempts)
    ]
  end

  defp ta_lines({:error, %{attempts: attempts, stale: stale}}) do
    [
      "  ta: FAILED, every URI\n",
      failed_attempts(attempts),
      if(stale,
        do: "  ta: using the copy accepted #{DateTime.to_iso8601(stale.fetched_at)} (stale)\n",
        else: "  ta: no earlier copy; repository not walked\n"
      )
    ]
  end

  defp failed_attempts(attempts) do
    for %{outcome: outcome} = attempt <- attempts, outcome != :accepted do
      "    tried #{attempt.uri}: #{outcome} (#{reason(attempt.detail)})\n"
    end
  end

  defp warnings(attempts) do
    for attempt <- attempts, warning <- attempt.warnings do
      case warning do
        {:wildcard_certificate, uri, name} ->
          "    warning: #{uri}: certificate matched by wildcard #{name}\n"

        {:profile, problem} ->
          "    warning: #{attempt.uri}: #{problem.rule} (#{problem.message})\n"
      end
    end
  end

  defp walk_lines(nil), do: []

  defp walk_lines(walk) do
    failed = Enum.count(walk.fetches, &(&1.outcome == :error))
    stale = Enum.count(walk.points, & &1.stale)
    failed_points = Enum.count(walk.points, &(&1.status == :failed))
    fallback = Enum.count(walk.points, &(&1.status == :fallback))

    # Modules an earlier TAL's walk fetched in this run (#102).
    ours = MapSet.new(walk.fetches, & &1.uri)

    shared =
      walk.points |> Enum.map(& &1.covered_by) |> Enum.uniq() |> Enum.count(&(&1 not in ours))

    # CA certificates holding resources outside their issuer's (#155); the
    # walk validates no signed objects, so their EE certificates are
    # lumina validate's.
    overclaims =
      Enum.count(walk.issues, &(&1.kind == :invalid and Lumina.Chain.overclaim?(&1.detail)))

    notes =
      for {n, label} <- [
            {stale, "stale"},
            {failed_points, "failed"},
            {fallback, "from the last valid copy"}
          ],
          n > 0,
          do: "#{n} #{label}"

    [
      "  publication points: #{length(walk.points)}" <>
        if(notes != [], do: " (#{Enum.join(notes, ", ")})", else: "") <> "\n",
      "  rsync fetches: #{length(walk.fetches)}, #{failed} failed" <>
        if(shared > 0, do: "; #{shared} modules fetched for an earlier TAL", else: "") <> "\n",
      if(overclaims > 0,
        do:
          "  overclaims: #{overclaims} (resources outside the issuer's, RFC 6487 section 7.2)\n",
        else: []
      ),
      for issue <- walk.issues do
        "    #{issue.kind}: #{issue.uri}" <>
          if(issue.detail, do: " (#{reason(issue.detail)})", else: "") <> "\n"
      end
    ]
  end

  # A short reason for a failure's detail. For rsync failures Lumina can't
  # classify further, rsync's own first line says what went wrong.
  defp reason(%{reason: reason, output: output})
       when reason in [:usage_error, :protocol_error, :rsync_error] do
    case output |> String.split("\n", trim: true) |> Enum.map(&String.trim/1) do
      [line | _] -> "#{reason}: #{String.slice(line, 0, 200)}"
      [] -> to_string(reason)
    end
  end

  defp reason(%{reason: reason}), do: to_string(reason)

  defp reason(%{manifest: manifest, reasons: reasons}),
    do: "#{manifest}: #{Enum.map_join(reasons, ", ", &to_string(&1.rule))}; fetched again"

  defp reason(%{certificate: name}), do: "from #{name}"
  defp reason(%{covered_by: uri}), do: "no copy; fetched with #{uri}"

  defp reason([%{rule: _} | _] = problems),
    do: Enum.map_join(problems, ", ", &Lumina.Chain.rule_text/1)

  defp reason(other), do: inspect(other)

  # The lock.

  defp lock(root) do
    file = Path.join(root, ".lock")
    pid = System.pid()

    case File.open(file, [:write, :exclusive]) do
      {:ok, io} ->
        IO.write(io, pid)
        File.close(io)

      {:error, :eexist} ->
        holder = file |> File.read!() |> String.trim()

        if alive?(holder) do
          {:error, {:locked, holder}}
        else
          # Left by a run that crashed.
          _ = File.rm(file)
          lock(root)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp unlock(root), do: _ = File.rm(Path.join(root, ".lock"))

  defp alive?(pid) do
    pid =~ ~r/\A\d+\z/ and
      match?({_, 0}, System.cmd("kill", ["-0", pid], stderr_to_stdout: true))
  end
end
