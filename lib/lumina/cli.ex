defmodule Lumina.CLI do
  @moduledoc """
  The `lumina` command line tool, built as an escript (`mix escript.build`).

  It follows the command plus flags model (D-001 in doc/decisions.md):

      lumina <command> [flags] [arguments]
      lumina print [--brief] FILE...
      lumina sync [--cache DIR] [--tal FILE]... [--timeout SECONDS] [--max-depth N]
      lumina validate [--cache DIR] [--tal FILE]... [--now TIME] [--max-invalid PERCENT]
      lumina help [command]

  Exit codes, shared by all commands: 0 success, 1 a file failed to
  decode, a fetch failed or too much is invalid, 2 a usage error
  (including an unknown command or flag).
  """

  alias Lumina.{Object, Print, Progress, Rsync, Sync, TAL, Validate}

  @usage """
  Usage: lumina <command> [flags] [arguments]

  Commands:
    print     print RPKI objects and TALs in human-readable form
    sync      fetch the trust anchors and repositories into the local cache
    validate  validate the certificates and signed objects in the local cache, offline
    help      show help for lumina or a command

  Run "lumina help <command>" for a command's flags.

  Exit codes: 0 success, 1 a file failed to decode, a fetch failed or
  too much is invalid, 2 usage error.
  """

  @print_usage """
  Usage: lumina print [--brief] FILE...

  Print RPKI objects (.cer, .crl, .mft, .roa, and the envelope of .gbr, .sig
  and .tak) and trust anchor locators (.tal) as human-readable text, one
  field per line. Printing shows what is in each file; it doesn't validate
  it.

  Flags:
    --brief   leave out most cryptographic detail (key identifiers, keys,
              signatures, digests, signer details, manifest hashes); keep
              validity dates, names, resources, URIs, prefixes and file names

  Exit codes: 0 all files printed, 1 a file failed to decode, 2 usage error.
  """

  @sync_usage """
  Usage: lumina sync [--cache DIR] [--tal FILE]... [--timeout SECONDS] [--max-depth N]
                     [--per-host N] [--rsync PATH] [--progress | --quiet]

  For each TAL, fetch its trust anchor certificate (HTTPS first, then
  rsync) and validate it, then walk the repository from it and mirror
  every publication point into the cache with rsync, following only CA
  certificates that validate. A failed fetch keeps the last good copy.
  Needs rsync 3.1.0 or later, on PATH or given with --rsync.

  Flags:
    --cache DIR        the cache directory (default: the user cache
                       directory, ~/Library/Caches/lumina on macOS,
                       ~/.cache/lumina on Linux)
    --tal FILE         sync only this TAL; repeat to pick several
                       (default: every .tal file in ./tals/)
    --timeout SECONDS  rsync I/O timeout, and the time allowed for each
                       HTTPS fetch (default: 300)
    --max-depth N      the deepest CA certificate followed below the trust
                       anchor (default: 32)
    --per-host N       rsync runs at once to any one host (default: 8);
                       more is faster on a slow link, and more load on
                       the repository server
    --rsync PATH       the rsync binary to use, 3.1.0 or later (default: the
                       first rsync on PATH)
    --progress         report progress on stderr even when it isn't a
                       terminal, as timestamped lines (on a terminal, a
                       status line is shown anyway)
    --quiet            no progress report

  Prints one summary per TAL: the TA URI used, the publication points
  and rsync fetches, every failure with its reason, and the CA
  certificates that don't validate.

  Exit codes: 0 everything fetched (an invalid CA certificate doesn't
  change that), 1 some fetch failed (the cache is still usable), no TA
  validated, another sync holds the cache, or rsync is missing or too
  old, 2 usage error.
  """

  @validate_usage """
  Usage: lumina validate [--cache DIR] [--tal FILE]... [--now TIME]
                         [--max-invalid PERCENT]

  Validate what the last sync put in the cache, without fetching
  anything: for each TAL, its stored trust anchor certificate, then every
  CA certificate and signed object below it, top down through the CA
  certificates that validate. A signed object is checked for its CMS
  envelope, signature and EE certificate; manifest and ROA contents are
  not checked yet.

  Flags:
    --cache DIR   the cache directory (default: as for lumina sync)
    --tal FILE    validate only this TAL's tree; repeat to pick several
                  (default: every .tal file in ./tals/)
    --now TIME    validate as of this time, ISO 8601: 2030-01-01T00:00:00Z,
                  or a date, 2030-01-01, for its midnight UTC (default:
                  the current time)
    --max-invalid PERCENT
                  the share of a TAL's CA certificates and signed objects
                  that may be invalid before the run fails, 0 to 100
                  (default: 10); 0 fails on any invalid one

  Prints one summary per TAL: the trust anchor, the number of valid and
  invalid CA certificates and signed objects of each type, every invalid
  one with its reasons, warnings, and publication points missing from
  the cache.

  Exit codes: 0 valid (at most PERCENT invalid objects per TAL; missing
  publication points are listed but don't count), 1 a TAL with no trust
  anchor in the cache, an invalid one, or more than PERCENT invalid
  objects, 2 usage error.
  """

  @rsync_hint " (on macOS, /usr/bin/rsync is openrsync: install rsync with Homebrew and put it first in PATH, or give it with --rsync PATH)"

  @help %{"print" => @print_usage, "sync" => @sync_usage, "validate" => @validate_usage}

  @doc "Escript entry point."
  @spec main([String.t()]) :: no_return()
  def main(args) do
    # Log messages (such as TLS warnings) go to stderr, so stdout holds
    # only the command's output.
    # A handler's device can't be changed in place, so the handler is
    # replaced by a copy writing to stderr.
    _ =
      with {:ok, config} <- :logger.get_handler_config(:default),
           :ok <- :logger.remove_handler(:default) do
        config = config |> Map.drop([:id, :module]) |> put_in([:config, :type], :standard_error)
        _ = :logger.add_handler(:default, :logger_std_h, config)
      end

    System.halt(run(args))
  end

  @doc """
  Runs the command line `args`, writing to `out` and `err`, and returns the
  exit code. Separate from `main/1` so it can be tested without halting.

  `internal` is for tests only: options passed to `Lumina.Sync.run/3`
  (`:remap`, `:https`, `:rsync`, `:now`) and `:tal_dir`, the folder that
  stands in for `./tals/`.
  """
  @spec run([String.t()], IO.device(), IO.device(), keyword()) :: 0 | 1 | 2
  def run(args, out \\ :stdio, err \\ :stderr, internal \\ []) do
    case args do
      [help] when help in ["help", "-h", "--help"] -> written(out, @usage, 0)
      ["help", command] -> help(command, out, err)
      ["print" | rest] -> print_command(rest, out, err)
      ["sync" | rest] -> sync_command(rest, out, err, internal)
      ["validate" | rest] -> validate_command(rest, out, err, internal)
      _ -> written(err, @usage, 2)
    end
  end

  defp help(command, out, err) do
    case Map.fetch(@help, command) do
      {:ok, text} -> written(out, text, 0)
      :error -> written(err, "lumina: unknown command #{inspect(command)}\n\n" <> @usage, 2)
    end
  end

  defp print_command(args, out, err) do
    case OptionParser.parse(args, strict: [brief: :boolean, help: :boolean], aliases: [h: :help]) do
      {[help: true], [], []} ->
        written(out, @print_usage, 0)

      {opts, [_ | _] = paths, []} ->
        if opts[:help],
          do: written(err, @print_usage, 2),
          else: print(paths, opts[:brief] == true, out, err)

      {_opts, _paths, invalid} when invalid != [] ->
        written(
          err,
          "lumina print: unknown flag #{invalid |> hd() |> elem(0)}\n\n" <> @print_usage,
          2
        )

      _ ->
        written(err, @print_usage, 2)
    end
  end

  @sync_flags [
    cache: :string,
    tal: :keep,
    timeout: :integer,
    max_depth: :integer,
    per_host: :integer,
    rsync: :string,
    progress: :boolean,
    quiet: :boolean,
    help: :boolean
  ]

  defp sync_command(args, out, err, internal) do
    case OptionParser.parse(args, strict: @sync_flags, aliases: [h: :help]) do
      {[help: true], [], []} ->
        written(out, @sync_usage, 0)

      {opts, [], []} ->
        with {:ok, paths} <- tal_paths(opts, internal),
             {:ok, tals} <- read_tals(paths),
             {:ok, limits} <- limits(opts) do
          internal = rsync_flag(opts[:rsync], internal)

          case rsync_check(internal) do
            :ok ->
              with_progress(opts, err, fn progress ->
                sync(
                  tals,
                  opts[:cache] || default_cache(),
                  limits ++ progress ++ internal,
                  out,
                  err
                )
              end)

            {:error, message} ->
              written(err, "lumina sync: #{message}\n", 1)
          end
        else
          {:error, message} -> written(err, "lumina sync: #{message}\n", 2)
        end

      {_opts, _args, [{flag, _} | _]} ->
        written(err, "lumina sync: unknown or invalid flag #{flag}\n\n" <> @sync_usage, 2)

      {_opts, [arg | _], []} ->
        written(err, "lumina sync: unexpected argument #{arg}\n\n" <> @sync_usage, 2)
    end
  end

  @validate_flags [
    cache: :string,
    tal: :keep,
    now: :string,
    max_invalid: :integer,
    help: :boolean
  ]

  defp validate_command(args, out, err, internal) do
    case OptionParser.parse(args, strict: @validate_flags, aliases: [h: :help]) do
      {[help: true], [], []} ->
        written(out, @validate_usage, 0)

      {opts, [], []} ->
        with {:ok, paths} <- tal_paths(opts, internal),
             {:ok, tals} <- read_tals(paths),
             {:ok, now} <- now_flag(opts[:now], internal),
             {:ok, max_invalid} <- max_invalid_flag(Keyword.get(opts, :max_invalid, 10)) do
          cache = opts[:cache] || default_cache()

          reports =
            for {path, tal} <- tals, do: {path, Validate.run(tal, cache, now: now)}

          IO.write(out, Validate.summary(reports, now))

          if Enum.any?(reports, fn {_path, report} -> Validate.failed?(report, max_invalid) end),
            do: 1,
            else: 0
        else
          {:error, message} -> written(err, "lumina validate: #{message}\n", 2)
        end

      {_opts, _args, [{flag, _} | _]} ->
        written(err, "lumina validate: unknown or invalid flag #{flag}\n\n" <> @validate_usage, 2)

      {_opts, [arg | _], []} ->
        written(err, "lumina validate: unexpected argument #{arg}\n\n" <> @validate_usage, 2)
    end
  end

  defp max_invalid_flag(percent) when percent in 0..100, do: {:ok, percent}
  defp max_invalid_flag(_percent), do: {:error, "--max-invalid must be a percentage, 0 to 100"}

  defp now_flag(nil, internal), do: {:ok, Keyword.get_lazy(internal, :now, &DateTime.utc_now/0)}

  defp now_flag(text, _internal) do
    case {DateTime.from_iso8601(text), Date.from_iso8601(text)} do
      {{:ok, time, _offset}, _} -> {:ok, time}
      {_, {:ok, date}} -> {:ok, DateTime.new!(date, ~T[00:00:00], "Etc/UTC")}
      _ -> {:error, "--now must be an ISO 8601 time, such as 2030-01-01T00:00:00Z, or a date"}
    end
  end

  defp tal_paths(opts, internal) do
    case Keyword.get_values(opts, :tal) do
      [] ->
        dir = Keyword.get(internal, :tal_dir, "tals")

        case dir |> Path.join("*.tal") |> Path.wildcard() |> Enum.sort() do
          [] -> {:error, "no .tal files in #{dir}/; give one with --tal FILE"}
          paths -> {:ok, paths}
        end

      paths ->
        {:ok, paths}
    end
  end

  # Every TAL is read before anything is fetched, so a bad one is a usage
  # error that costs nothing.
  defp read_tals(paths) do
    Enum.reduce_while(paths, {:ok, []}, fn path, {:ok, acc} ->
      case TAL.decode_file(path) do
        {:ok, tal} -> {:cont, {:ok, acc ++ [{path, tal}]}}
        {:error, reason} -> {:halt, {:error, "#{path}: #{Print.error(reason, path)}"}}
      end
    end)
  end

  defp limits(opts) do
    cond do
      opts[:timeout] != nil and opts[:timeout] < 1 ->
        {:error, "--timeout must be at least 1"}

      opts[:max_depth] != nil and opts[:max_depth] < 0 ->
        {:error, "--max-depth must be 0 or more"}

      opts[:per_host] != nil and opts[:per_host] < 1 ->
        {:error, "--per-host must be at least 1"}

      true ->
        {:ok, Keyword.take(opts, [:timeout, :max_depth, :per_host])}
    end
  end

  # Repositories need rsync 3.1.0 or later. Checked before anything is
  # fetched, so an old rsync fails clearly instead of every fetch failing.
  # Progress on stderr (#96): a status line when stderr is a terminal,
  # timestamped lines with --progress otherwise, nothing with --quiet.
  defp with_progress(opts, err, fun) do
    tty? = err == :stderr and Progress.stderr_tty?()

    if opts[:quiet] || !(tty? || opts[:progress]) do
      fun.([])
    else
      {listener, stop} = Progress.start(err, if(tty?, do: :tty, else: :plain))

      try do
        fun.(progress: listener)
      after
        stop.()
      end
    end
  end

  # --rsync PATH: the binary for every rsync run, TA retrieval included.
  defp rsync_flag(nil, internal), do: internal

  defp rsync_flag(path, internal) do
    path = Path.expand(path)
    Keyword.update(internal, :rsync, [rsync: path], &Keyword.put(&1, :rsync, path))
  end

  defp rsync_check(internal) do
    rsync_opts = Keyword.get(internal, :rsync, [])
    given = rsync_opts[:rsync]
    path = given || System.find_executable("rsync")

    case Rsync.check(rsync_opts) do
      {:ok, _} ->
        :ok

      {:error, :rsync_not_found} when given != nil ->
        {:error, "#{path} not found or not executable; Lumina needs rsync 3.1.0 or later"}

      {:error, :rsync_not_found} ->
        {:error, "rsync not found on PATH; Lumina needs rsync 3.1.0 or later#{@rsync_hint}"}

      {:error, {:rsync_too_old, version}} ->
        {:error, "#{path} is rsync #{version}; Lumina needs 3.1.0 or later#{@rsync_hint}"}

      {:error, :rsync_version_unknown} ->
        {:error,
         "#{path}: can't tell which rsync version it is; Lumina needs 3.1.0 or later#{@rsync_hint}"}
    end
  end

  defp default_cache, do: :filename.basedir(:user_cache, "lumina") |> to_string()

  defp sync(tals, cache, opts, out, err) do
    case Sync.run(tals, cache, Keyword.delete(opts, :tal_dir)) do
      {:ok, reports} ->
        IO.write(out, Sync.summary(reports))
        if Enum.any?(reports, & &1.failed?), do: 1, else: 0

      {:error, {:locked, pid}} ->
        written(err, "lumina sync: #{cache} is in use by another sync (process #{pid})\n", 1)

      {:error, reason} ->
        written(err, "lumina sync: #{cache}: #{:file.format_error(reason)}\n", 1)
    end
  end

  defp written(device, text, code) do
    IO.write(device, text)
    code
  end

  defp print(paths, brief, out, err) do
    many? = length(paths) > 1

    results =
      paths
      |> Enum.with_index()
      |> Enum.map(fn {path, index} ->
        if many?, do: IO.write(out, if(index > 0, do: "\n", else: "") <> "==> #{path} <==\n")

        case decode_file(path) do
          {:ok, object} ->
            IO.write(out, Print.render(object, brief: brief))
            :ok

          {:error, reason} ->
            IO.write(err, "lumina: #{path}: #{Print.error(reason, path)}\n")
            :error
        end
      end)

    if Enum.all?(results, &(&1 == :ok)), do: 0, else: 1
  end

  # TALs aren't repository objects (RFC 6481 doesn't register .tal), so
  # they have their own parser.
  defp decode_file(path) do
    if Path.extname(path) == ".tal", do: TAL.decode_file(path), else: Object.decode_file(path)
  end
end
