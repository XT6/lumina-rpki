defmodule Lumina.CLI do
  @moduledoc """
  The `lumina` command line tool, built as an escript (`mix escript.build`).

  It follows the command plus flags model (D-001 in doc/decisions.md):

      lumina <command> [flags] [arguments]
      lumina print [--brief] FILE...
      lumina sync [--cache DIR] [--tal FILE]... [--timeout SECONDS] [--max-depth N]
                  [--no-rrdp] [--rrdp-max-size SIZE] [--rrdp-idle-timeout SECONDS]
      lumina validate [--cache DIR] [--tal FILE]... [--now TIME] [--max-invalid PERCENT]
                      [--progress | --quiet]
      lumina vrps [--cache DIR] [--tal FILE]... [--now TIME] [--max-invalid PERCENT]
                  [--format csv|json] [--output FILE] [--wide] [--progress | --quiet]
      lumina clean [--cache DIR] [--tal FILE]... [--force] [--quiet]
      lumina version
      lumina help [command]

  Every run but `lumina version` starts with a banner on stderr (the
  version, the runtimes and the start time), left out with `--quiet`
  (D-045).

  Exit codes, shared by all commands: 0 success, 1 a file failed to
  decode, a fetch failed or too much is invalid, 2 a usage error
  (including an unknown command or flag).
  """

  alias Lumina.{Clean, Object, Print, Progress, Rsync, Sync, TAL, Validate, VRP}

  @usage """
  Usage: lumina <command> [flags] [arguments]

  Commands:
    print     print RPKI objects and TALs in human-readable form
    sync      fetch the trust anchors and repositories into the local cache
    validate  validate the certificates and signed objects in the local cache, offline
    vrps      validate the local cache, offline, and write the VRPs
    clean     empty the local cache, or remove what some TALs use from it
    version   print lumina's version
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
                     [--per-host N] [--rsync PATH] [--no-rrdp]
                     [--rrdp-max-size SIZE] [--rrdp-idle-timeout SECONDS]
                     [--progress | --quiet]

  For each TAL, fetch its trust anchor certificate (HTTPS first, then
  rsync) and validate it, then walk the repository from it and mirror
  every publication point into the cache, following only CA certificates
  that are on their issuer's current manifest and validate. A CA that
  names an RRDP repository (an HTTPS rpkiNotify) is synced over RRDP
  (RFC 8182), and its publication point fetched with rsync instead if
  that fails; other CAs are fetched with rsync.
  A publication point whose manifest check fails (RFC 9286 section 6) is
  listed with its reasons; its last valid copy, kept from an earlier
  sync, is used while its manifest is current, and otherwise nothing
  below it is walked. A failed fetch
  keeps the last good copy.
  Needs rsync 3.1.0 or later, on PATH or given with --rsync.

  Flags:
    --cache DIR        the cache directory (default: the user cache
                       directory, ~/Library/Caches/lumina on macOS,
                       ~/.cache/lumina on Linux)
    --tal FILE         sync only this TAL; repeat to pick several
                       (default: every .tal file in ./tals/)
    --timeout SECONDS  rsync I/O timeout, and the time allowed for each
                       trust anchor fetched over HTTPS (default: 300)
    --max-depth N      the deepest CA certificate followed below the trust
                       anchor (default: 32)
    --per-host N       rsync runs at once to any one host (default: 8);
                       more is faster on a slow link, and more load on
                       the repository server
    --rsync PATH       the rsync binary to use, 3.1.0 or later (default: the
                       first rsync on PATH)
    --no-rrdp          fetch every publication point with rsync, never
                       over RRDP (trust anchors are still fetched over
                       HTTPS first)
    --rrdp-max-size SIZE
                       the largest RRDP snapshot or delta file downloaded,
                       in bytes or with K, M or G (default: 2G); a larger
                       one fails the repository's RRDP sync
    --rrdp-idle-timeout SECONDS
                       how long an RRDP download may go without data
                       before it fails (default: 300); there is no limit
                       on its total time
    --progress         report progress on stderr (the default): a status
                       line on a terminal, timestamped lines otherwise
    --quiet            no progress report

  Prints one summary per TAL: the TA URI used, the publication points,
  the rsync fetches and the RRDP repositories by outcome (snapshot,
  deltas, unchanged, recent: synced less than a minute ago, or failed
  and fetched with rsync), every failure and warning with its reason,
  and the CA
  certificates that don't validate. A CA certificate holding resources
  outside its issuer's is listed with them, and counted as an overclaim.
  A fetch whose connection dropped or timed out is tried once more after
  10 to 30 s, and listed as retried.

  Exit codes: 0 each trust anchor and its own publication point fetched
  (a fetch failing further down is listed, with a warning, and an
  invalid CA certificate doesn't change that either), 1 a trust anchor
  not retrieved (an earlier copy is used if there is one) or its own
  publication point not fetched, another sync holds the cache, or rsync
  is missing or too old, 2 usage error.
  """

  @validate_usage """
  Usage: lumina validate [--cache DIR] [--tal FILE]... [--now TIME]
                         [--max-invalid PERCENT] [--progress | --quiet]

  Validate what the last sync put in the cache, without fetching
  anything: for each TAL, its stored trust anchor certificate, then every
  CA certificate and signed object below it, top down through the CA
  certificates that validate. Only files on each CA's current manifest
  are used. A publication point the manifest checks reject (RFC 9286
  section 6) is validated from its last valid copy, kept by lumina sync,
  while that copy's manifest is current; otherwise it counts as one
  invalid manifest, with nothing in it validated. A signed object is checked for its CMS envelope, signature
  and EE certificate, and a ROA for its content too (RFC 9582).

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
    --progress    report progress on stderr (the default): a status
                  line on a terminal, timestamped lines otherwise
    --quiet       no progress report

  Prints one summary per TAL: the trust anchor, the number of valid and
  invalid CA certificates and signed objects of each type, every invalid
  one with its reasons, warnings, and publication points missing from
  the cache. A certificate holding resources outside its issuer's (a CA
  certificate, or a signed object's EE certificate) is listed with them,
  and counted as an overclaim; it counts as invalid toward PERCENT.

  Exit codes: 0 valid (at most PERCENT invalid objects per TAL; missing
  publication points are listed but don't count), 1 a TAL with no trust
  anchor in the cache, an invalid one, or more than PERCENT invalid
  objects, 2 usage error.
  """

  @vrps_usage """
  Usage: lumina vrps [--cache DIR] [--tal FILE]... [--now TIME]
                     [--max-invalid PERCENT] [--format csv|json]
                     [--output FILE] [--wide] [--progress | --quiet]
                     [--sync [--max-age DURATION] [--timeout SECONDS]
                      [--max-depth N] [--per-host N] [--rsync PATH]
                      [--no-rrdp] [--rrdp-max-size SIZE]
                      [--rrdp-idle-timeout SECONDS]]

  Validate the cache as lumina validate does, offline, and write the
  Validated ROA Payloads (VRPs) of the valid ROAs: one per distinct AS,
  prefix, maxLength and trust anchor, however many ROAs state it. The
  trust anchor is named after its TAL file, without .tal.

  With --sync, first sync, as lumina sync does, each TAL that needs it:
  the cache has no trust anchor for it, or its last sync is older than
  --max-age. Other TALs are validated from the cache as they are.

  Flags:
    --cache DIR   the cache directory (default: as for lumina sync)
    --tal FILE    use only this TAL's tree; repeat to pick several
                  (default: every .tal file in ./tals/)
    --now TIME    validate as of this time, as for lumina validate
    --max-invalid PERCENT
                  as for lumina validate (default: 10); above it the VRPs
                  are still written, with a warning
    --format csv|json
                  the output format (default: csv). csv: a header line,
                  then ASN,IP Prefix,Max Length,Trust Anchor rows, such as
                  AS13335,1.0.0.0/24,24,apnic. json: an object with
                  "metadata" (times, version, trust anchors, counts) and
                  "roas", the same rows, such as {"asn":"AS13335",
                  "prefix":"1.0.0.0/24","maxLength":24,"ta":"apnic"}
    --output FILE write the VRPs to FILE, replacing it in one step,
                  instead of to standard output
    --wide        for debugging: add a URI column ("uri" in JSON) with
                  the rsync URI of the ROA, and write one row per VRP and
                  ROA, so a VRP that several ROAs state appears once for
                  each
    --progress    report progress on stderr (the default): a status
                  line on a terminal, timestamped lines otherwise
    --quiet       no progress report
    --sync        sync the TALs that need it first (see above)
    --max-age DURATION
                  with --sync: how old a TAL's last sync may be, such as
                  90s, 30m, 2h or 1d, or seconds (default: 1h)
    --timeout SECONDS, --max-depth N, --per-host N, --rsync PATH,
    --no-rrdp, --rrdp-max-size SIZE, --rrdp-idle-timeout SECONDS
                  with --sync: as for lumina sync

  A short summary says why each TAL was synced or not and gives the
  sync's summary, the VRPs of each TAL, and warnings. It goes to
  standard output with --output, as the VRPs are in FILE, and to
  standard error without it. The progress report goes to standard
  error.

  Exit codes: 0 written, 1 a TAL with no trust anchor in the cache, an
  invalid one, or more than PERCENT invalid objects (the VRPs of the
  others, and of a TAL over PERCENT, are still written), a sync that
  couldn't fetch a trust anchor or its own publication point (the VRPs
  are written from what the cache holds; failures further down are only
  warnings), or FILE can't be written, 2 usage error.
  """

  @clean_usage """
  Usage: lumina clean [--cache DIR] [--tal FILE]... [--force] [--quiet]

  Remove what lumina sync put in the cache. Without --tal, the whole
  cache is emptied, including what no TAL uses any more (the directory
  itself stays). With --tal, only what each TAL's tree used at its last
  sync goes: its trust anchor, its rsync modules and RRDP repositories,
  and the records kept for its publication points; anything the tree of
  another TAL synced into the cache also uses stays. The next sync
  fetches everything removed again.

  It lists what it will remove and asks before removing anything.

  Flags:
    --cache DIR   the cache directory (default: as for lumina sync)
    --tal FILE    clean only what this TAL's tree uses; repeat to pick
                  several (default: the whole cache)
    --force       don't ask; for scripts and cron jobs. Without it, a run
                  whose standard input isn't a terminal removes nothing
    --quiet       no banner

  A TAL never synced into the cache has nothing to remove: a warning,
  and the rest goes ahead. A TAL synced by lumina before 0.8.1 has no
  record of its repositories, so only its trust anchor and sync record
  are removed; clean without --tal, or sync it again first.

  Prints what was removed: files and bytes, and for --tal what each TAL
  lost and kept.

  Exit codes: 0 removed, or nothing to remove, 1 the cache is in use by a
  sync, the removal wasn't confirmed, or a file couldn't be removed,
  2 usage error.
  """

  @version_usage """
  Usage: lumina version

  Print lumina's version, such as "lumina 0.8.1", on standard output.
  lumina --version does the same.

  Every other run starts with a banner on standard error: the version,
  the Erlang/OTP and Elixir versions and the start time (UTC). --quiet
  leaves it out.

  Exit codes: 0 printed, 2 usage error.
  """

  @rsync_hint " (on macOS, /usr/bin/rsync is openrsync: install rsync with Homebrew and put it first in PATH, or give it with --rsync PATH)"

  @help %{
    "print" => @print_usage,
    "sync" => @sync_usage,
    "validate" => @validate_usage,
    "vrps" => @vrps_usage,
    "clean" => @clean_usage,
    "version" => @version_usage
  }

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

    System.halt(run(args, :stdio, :stderr, banner: true))
  end

  @doc """
  Runs the command line `args`, writing to `out` and `err`, and returns the
  exit code. Separate from `main/1` so it can be tested without halting.

  `internal` is for `main/1` and tests: `:banner` (write the banner
  first, D-045; `main/1` sets it), options passed to `Lumina.Sync.run/3`
  (`:remap`, `:https`, `:rsync`, `:now`), `:tal_dir`, the folder that
  stands in for `./tals/`, and `:generated`, the time `lumina vrps
  --format json` gives as made. `:started` is the time the banner gives
  (default: now).
  """
  @spec run([String.t()], IO.device(), IO.device(), keyword()) :: 0 | 1 | 2
  def run(args, out \\ :stdio, err \\ :stderr, internal \\ []) do
    if internal[:banner] == true and banner?(args) do
      started = Keyword.get_lazy(internal, :started, &DateTime.utc_now/0)
      IO.write(err, Lumina.banner(started) <> "\n")
    end

    case args do
      [version] when version in ["version", "--version"] ->
        written(out, "lumina #{Lumina.version()}\n", 0)

      ["version" | _] ->
        written(err, @version_usage, 2)

      [help] when help in ["help", "-h", "--help"] ->
        written(out, @usage, 0)

      ["help", command] ->
        help(command, out, err)

      ["print" | rest] ->
        print_command(rest, out, err)

      ["sync" | rest] ->
        sync_command(rest, out, err, internal)

      ["validate" | rest] ->
        validate_command(rest, out, err, internal)

      ["vrps" | rest] ->
        vrps_command(rest, out, err, internal)

      ["clean" | rest] ->
        clean_command(rest, out, err, internal)

      _ ->
        written(err, @usage, 2)
    end
  end

  # The banner is left out for lumina version, which says it already, and
  # with --quiet (D-045).
  defp banner?(["version" | _]), do: false
  defp banner?(["--version" | _]), do: false
  defp banner?(args), do: "--quiet" not in args

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
    rrdp: :boolean,
    rrdp_max_size: :string,
    rrdp_idle_timeout: :integer,
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
                  sync_opts(limits, progress, internal),
                  out,
                  err,
                  "lumina sync",
                  &synced(&1, &2, "lumina sync")
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
    progress: :boolean,
    quiet: :boolean,
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
          reports = validate_all(tals, opts, now, err)
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

  @clean_flags [cache: :string, tal: :keep, force: :boolean, quiet: :boolean, help: :boolean]

  # lumina clean (#226, D-047). `internal`: `:input`, the device the answer
  # is read from (default :stdio), and `:interactive`, whether it is a
  # terminal (default: whether standard input is one).
  defp clean_command(args, out, err, internal) do
    case OptionParser.parse(args, strict: @clean_flags, aliases: [h: :help]) do
      {[help: true], [], []} ->
        written(out, @clean_usage, 0)

      {opts, [], []} ->
        selected =
          case Keyword.get_values(opts, :tal) do
            [] -> {:ok, :all}
            paths -> read_tals(paths)
          end

        case selected do
          {:ok, what} -> clean(opts[:cache] || default_cache(), what, opts, out, err, internal)
          {:error, message} -> written(err, "lumina clean: #{message}\n", 2)
        end

      {_opts, _args, [{flag, _} | _]} ->
        written(err, "lumina clean: unknown or invalid flag #{flag}\n\n" <> @clean_usage, 2)

      {_opts, [arg | _], []} ->
        written(err, "lumina clean: unexpected argument #{arg}\n\n" <> @clean_usage, 2)
    end
  end

  defp clean(cache, what, opts, out, err, internal) do
    if File.dir?(cache) do
      result =
        Sync.with_lock(cache, fn ->
          {:ok, _} = Lumina.Cache.recover(cache)
          plan = Clean.plan(cache, what)
          clean_warnings(plan, cache, err)

          cond do
            plan.paths == [] ->
              written(out, "#{cache}: nothing to remove\n", 0)

            confirmed?(plan, cache, opts, err, internal) ->
              case Clean.remove(cache, plan) do
                :ok ->
                  written(out, clean_summary(plan, cache, "removed"), 0)

                {:error, path, reason} ->
                  written(
                    err,
                    "lumina clean: #{path}: #{:file.format_error(reason)}\n",
                    1
                  )
              end

            true ->
              1
          end
        end)

      case result do
        {:error, {:locked, pid}} ->
          written(err, "lumina clean: #{cache} is in use by a sync (process #{pid})\n", 1)

        {:error, reason} ->
          written(err, "lumina clean: #{cache}: #{:file.format_error(reason)}\n", 1)

        code ->
          code
      end
    else
      written(out, "#{cache}: nothing to remove\n", 0)
    end
  end

  defp clean_warnings(%{tals: :all}, _cache, _err), do: :ok

  defp clean_warnings(plan, cache, err) do
    for tal <- plan.tals do
      cond do
        tal.never_synced ->
          IO.write(
            err,
            "lumina clean: warning: #{tal.path} was never synced into #{cache}; nothing to remove for it\n"
          )

        tal.tree_unknown ->
          IO.write(
            err,
            "lumina clean: warning: #{tal.path} was synced by lumina before 0.8.1, which didn't record its repositories; " <>
              "only its trust anchor and sync record are removed (clean without --tal, or sync it again first)\n"
          )

        true ->
          :ok
      end
    end

    if plan.others_unknown,
      do:
        IO.write(
          err,
          "lumina clean: warning: another TAL in #{cache} was synced by lumina before 0.8.1, so what it uses isn't known; " <>
            "every repository is kept (clean without --tal, or sync the TALs again first)\n"
        )

    :ok
  end

  # D-047: ask, unless --force; without a terminal to ask on, remove nothing.
  defp confirmed?(plan, cache, opts, err, internal) do
    interactive =
      Keyword.get_lazy(internal, :interactive, fn ->
        try do
          :prim_tty.isatty(:stdin) == true
        rescue
          _ -> false
        end
      end)

    cond do
      opts[:force] ->
        true

      not interactive ->
        IO.write(
          err,
          clean_summary(plan, cache, "would remove") <>
            "lumina clean: standard input isn't a terminal, so nothing was removed; give --force to remove without asking\n"
        )

        false

      true ->
        IO.write(err, clean_summary(plan, cache, "will remove") <> "Remove? [y/N] ")

        case IO.gets(Keyword.get(internal, :input, :stdio), "") do
          answer when is_binary(answer) and answer != "" ->
            if String.downcase(String.trim(answer)) in ["y", "yes"],
              do: true,
              else: written(err, "nothing removed\n", false)

          _ ->
            written(err, "\nnothing removed\n", false)
        end
    end
  end

  defp clean_summary(%{tals: :all} = plan, cache, verb),
    do: "#{cache}: #{verb} everything: #{files(plan)}\n"

  defp clean_summary(plan, cache, verb) do
    lines =
      for tal <- plan.tals, not tal.never_synced do
        parts =
          for {n, one, many} <- [
                {if(tal.ta, do: 1, else: 0), "trust anchor", "trust anchors"},
                {tal.modules, "rsync module", "rsync modules"},
                {tal.notifications, "RRDP repository", "RRDP repositories"},
                {tal.points, "publication point record", "publication point records"}
              ],
              n > 0,
              do: "#{n} #{if n == 1, do: one, else: many}"

        parts = if parts == [], do: ["its sync record"], else: parts

        kept =
          if tal.shared > 0,
            do:
              "; kept #{tal.shared} repositor#{if tal.shared == 1, do: "y", else: "ies"} another TAL uses",
            else: ""

        "  #{tal.path}: #{Enum.join(parts, ", ")}#{kept}\n"
      end

    "#{cache}: #{verb} #{files(plan)}\n" <> Enum.join(lines)
  end

  defp files(plan),
    do:
      "#{plan.files} file#{if plan.files == 1, do: "", else: "s"}, #{Progress.bytes(plan.bytes)}"

  @vrps_flags [
    cache: :string,
    tal: :keep,
    now: :string,
    max_invalid: :integer,
    format: :string,
    output: :string,
    wide: :boolean,
    progress: :boolean,
    quiet: :boolean,
    sync: :boolean,
    max_age: :string,
    timeout: :integer,
    max_depth: :integer,
    per_host: :integer,
    rsync: :string,
    rrdp: :boolean,
    rrdp_max_size: :string,
    rrdp_idle_timeout: :integer,
    help: :boolean
  ]

  defp vrps_command(args, out, err, internal) do
    case OptionParser.parse(args, strict: @vrps_flags, aliases: [h: :help]) do
      {[help: true], [], []} ->
        written(out, @vrps_usage, 0)

      {opts, [], []} ->
        with {:ok, paths} <- tal_paths(opts, internal),
             {:ok, tals} <- read_tals(paths),
             {:ok, now} <- now_flag(opts[:now], internal),
             {:ok, max_invalid} <- max_invalid_flag(Keyword.get(opts, :max_invalid, 10)),
             {:ok, format} <- format_flag(Keyword.get(opts, :format, "csv")),
             {:ok, max_age} <- max_age_flag(opts),
             {:ok, limits} <- limits(opts) do
          # The summary goes to stdout when the VRPs go to a file, else to
          # stderr (#239, D-049).
          report = if opts[:output], do: out, else: err

          synced =
            if opts[:sync],
              do: sync_needed(tals, opts, max_age, limits, report, err, internal),
              else: 0

          reports = validate_all(tals, opts, now, err)

          vrps = VRP.sort(for {_path, {:ok, r}} <- reports, v <- r.vrps, do: v)

          failed =
            Enum.filter(reports, fn {_path, report} -> Validate.failed?(report, max_invalid) end)

          IO.write(report, vrps_summary(reports, failed, max_invalid))

          wide = [wide: opts[:wide] == true]

          data =
            case format do
              :csv ->
                VRP.csv(vrps, wide)

              :json ->
                generated = Keyword.get_lazy(internal, :generated, &DateTime.utc_now/0)

                metadata = %{
                  generated: generated,
                  now: now,
                  trust_anchors: ta_status(reports, failed)
                }

                VRP.json(vrps, metadata, wide)
            end

          case write_vrps(opts[:output], data, out) do
            :ok ->
              if failed == [], do: synced, else: 1

            {:error, reason} ->
              written(
                err,
                "lumina vrps: can't write #{opts[:output]}: #{:file.format_error(reason)}\n",
                1
              )
          end
        else
          {:error, message} -> written(err, "lumina vrps: #{message}\n", 2)
        end

      {_opts, _args, [{flag, _} | _]} ->
        written(err, "lumina vrps: unknown or invalid flag #{flag}\n\n" <> @vrps_usage, 2)

      {_opts, [arg | _], []} ->
        written(err, "lumina vrps: unexpected argument #{arg}\n\n" <> @vrps_usage, 2)
    end
  end

  # Validate.run/3 for each TAL, with a progress report on stderr (#180).
  defp validate_all(tals, opts, now, err) do
    cache = opts[:cache] || default_cache()
    total = length(tals)

    {progress, stop} = progress_listener(opts, err)

    try do
      for {{path, tal}, index} <- Enum.with_index(tals, 1) do
        Progress.emit(progress, {:tal_started, path, index, total})

        {path, Validate.run(tal, cache, [now: now, name: Validate.ta_name(path)] ++ progress)}
      end
    after
      stop.()
    end
  end

  @sync_only [
    :max_age,
    :timeout,
    :max_depth,
    :per_host,
    :rsync,
    :rrdp,
    :rrdp_max_size,
    :rrdp_idle_timeout
  ]

  # --max-age DURATION in seconds; it and the other sync flags need --sync.
  defp max_age_flag(opts) do
    case {opts[:sync], Enum.find(@sync_only, &Keyword.has_key?(opts, &1))} do
      {sync, flag} when sync != true and flag != nil ->
        name = String.replace(to_string(flag), "_", "-")
        name = if flag == :rrdp and opts[:rrdp] == false, do: "no-rrdp", else: name
        {:error, "--#{name} needs --sync"}

      _ ->
        case duration(Keyword.get(opts, :max_age, "1h")) do
          {:ok, seconds} -> {:ok, seconds}
          :error -> {:error, "--max-age must be a duration such as 90s, 30m, 2h or 1d"}
        end
    end
  end

  @units %{"" => 1, "s" => 1, "m" => 60, "h" => 3600, "d" => 86_400}

  defp duration(text) do
    case Integer.parse(text) do
      {n, unit} when n > 0 and is_map_key(@units, unit) -> {:ok, n * @units[unit]}
      _ -> :error
    end
  end

  # --sync (#185, D-037): syncs the TALs that have no trust anchor in the
  # cache or whose last sync is older than `max_age` seconds, in one
  # Sync.run/3 so they share modules (#102), and says why each TAL is
  # synced or not (#239). Ages are measured on the clock, not at --now.
  # The summary goes to `report`, errors to `err`. Returns the exit code
  # the sync contributes: 1 if it failed or couldn't run; the VRPs are
  # written from the cache anyway.
  defp sync_needed(tals, opts, max_age, limits, report, err, internal) do
    cache = opts[:cache] || default_cache()
    clock = Keyword.get_lazy(internal, :now, &DateTime.utc_now/0)

    stale =
      Enum.filter(tals, fn {path, tal} ->
        case sync_reason(cache, tal, clock, max_age, Keyword.get(opts, :max_age, "1h")) do
          {:skip, why} ->
            IO.write(report, "lumina vrps: not syncing #{path}: #{why}\n")
            false

          {:sync, why} ->
            IO.write(report, "lumina vrps: syncing #{path}: #{why}\n")
            true
        end
      end)

    internal = rsync_flag(opts[:rsync], internal)

    cond do
      stale == [] ->
        0

      (check = rsync_check(internal)) != :ok ->
        {:error, message} = check
        written(report, "lumina vrps: warning: can't sync: #{message}\n", 1)

      true ->
        with_progress(opts, err, fn progress ->
          sync(
            stale,
            cache,
            sync_opts(limits, progress, internal),
            report,
            err,
            "lumina vrps",
            &synced(&1, &2, "lumina vrps")
          )
        end)
    end
  end

  # A sync's exit code (D-037, #187): 0 when each TAL's trust anchor was
  # retrieved and its own publication point fetched (Sync.ta_synced?/1),
  # even if fetches below failed, which only warn; else 1.
  defp synced(reports, out, command) do
    code = if Enum.all?(reports, &Sync.ta_synced?/1), do: 0, else: 1

    cond do
      not Enum.any?(reports, & &1.failed?) ->
        :ok

      command == "lumina vrps" ->
        IO.write(
          out,
          "lumina vrps: warning: the sync had failures (above); the VRPs are written from what the cache holds\n"
        )

      code == 0 ->
        IO.write(out, "warning: some fetches below the trust anchors failed (above)\n")

      true ->
        :ok
    end

    code
  end

  defp sync_reason(cache, tal, clock, max_age, max_age_text) do
    last = Sync.last_synced(cache, tal)

    cond do
      Lumina.TA.stored(cache, tal) == nil ->
        {:sync, "no trust anchor in the cache"}

      last == nil ->
        {:sync, "no record of an earlier sync"}

      DateTime.diff(clock, last) > max_age ->
        {:sync, "last synced #{DateTime.to_iso8601(last)}, more than #{max_age_text} ago"}

      true ->
        age = ago(max(DateTime.diff(clock, last), 0))

        {:skip,
         "last synced #{DateTime.to_iso8601(last)}, #{age} ago (--max-age #{max_age_text})"}
    end
  end

  defp ago(seconds) when seconds < 60, do: count(seconds, "second")
  defp ago(seconds) when seconds < 3600, do: count(div(seconds, 60), "minute")
  defp ago(seconds) when seconds < 86_400, do: count(div(seconds, 3600), "hour")
  defp ago(seconds), do: count(div(seconds, 86_400), "day")

  defp count(n, unit), do: "#{n} #{unit}#{if n == 1, do: "", else: "s"}"

  defp format_flag("csv"), do: {:ok, :csv}
  defp format_flag("json"), do: {:ok, :json}
  defp format_flag(other), do: {:error, "--format must be csv or json, not #{inspect(other)}"}

  # Each TAL's trust anchor for the JSON metadata (#167): its name, file
  # and outcome, as the summary on stderr gives it.
  defp ta_status(reports, failed) do
    for {path, report} <- reports do
      status =
        case {List.keymember?(failed, path, 0), report} do
          {false, _} -> "ok"
          {true, {:error, :no_ta}} -> "no_trust_anchor"
          {true, {:ok, %{ta: %{valid: false}}}} -> "invalid_trust_anchor"
          {true, {:ok, _}} -> "too_many_invalid"
        end

      %{name: Validate.ta_name(path), tal: path, status: status}
    end
  end

  # One line per TAL on stderr, and why a TAL fails (D-034: its VRPs are
  # still written when only the share of invalid objects is too high).
  defp vrps_summary(reports, failed, max_invalid) do
    for {path, report} <- reports do
      line =
        case report do
          {:ok, r} -> "#{Validate.ta_name(path)}: #{length(VRP.distinct(r.vrps))} VRPs\n"
          {:error, :no_ta} -> "#{Validate.ta_name(path)}: no VRPs\n"
        end

      warning =
        case {List.keymember?(failed, path, 0), report} do
          {false, _} ->
            ""

          {true, {:error, :no_ta}} ->
            "lumina vrps: #{path}: no trust anchor in the cache; run lumina sync first\n"

          {true, {:ok, %{ta: %{valid: false}}}} ->
            "lumina vrps: #{path}: the trust anchor in the cache is invalid; run lumina validate for the reasons\n"

          {true, {:ok, _}} ->
            "lumina vrps: warning: #{path}: more than #{max_invalid}% of the CA certificates and signed objects are invalid; its VRPs are written anyway (run lumina validate for the details)\n"
        end

      [line, warning]
    end
  end

  # To a file, atomically: a temporary file next to it, renamed over it,
  # so a reader sees the old file or the new one, never half of one.
  defp write_vrps(nil, data, out), do: IO.binwrite(out, data)

  defp write_vrps(path, data, _out) do
    temp =
      Path.join(
        Path.dirname(path),
        ".#{Path.basename(path)}.#{System.unique_integer([:positive])}.tmp"
      )

    with :ok <- File.write(temp, data),
         :ok <- File.rename(temp, path) do
      :ok
    else
      error ->
        _ = File.rm(temp)
        error
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

      opts[:rrdp_idle_timeout] != nil and opts[:rrdp_idle_timeout] < 1 ->
        {:error, "--rrdp-idle-timeout must be at least 1"}

      opts[:rrdp_max_size] != nil and size(opts[:rrdp_max_size]) == :error ->
        {:error, "--rrdp-max-size must be a size such as 500M, 2G or a number of bytes"}

      true ->
        # The D-043 limits of every RRDP download (#208): the snapshot and
        # delta files, and the seconds without data on any fetch.
        rrdp_opts =
          Enum.flat_map(opts, fn
            {:rrdp_max_size, text} -> [max_file: elem(size(text), 1)]
            {:rrdp_idle_timeout, seconds} -> [idle_timeout: seconds]
            _ -> []
          end)

        {:ok,
         Keyword.take(opts, [:timeout, :max_depth, :per_host, :rrdp]) ++
           if(rrdp_opts != [], do: [rrdp_opts: rrdp_opts], else: [])}
    end
  end

  @size_units %{"" => 1, "K" => 1024, "M" => 1024 ** 2, "G" => 1024 ** 3}

  # A size in bytes, or with a binary K, M or G suffix.
  defp size(text) do
    case Integer.parse(text) do
      {n, unit} when n > 0 and is_map_key(@size_units, unit) -> {:ok, n * @size_units[unit]}
      _ -> :error
    end
  end

  # The options of a sync: the flags' limits first, so they win over the
  # internal ones, and the RRDP limits merged into internal :rrdp_opts
  # (tests pass certificates there).
  defp sync_opts(limits, progress, internal) do
    rrdp_opts = Keyword.merge(internal[:rrdp_opts] || [], limits[:rrdp_opts] || [])

    Keyword.delete(limits, :rrdp_opts) ++
      progress ++
      if(rrdp_opts != [], do: [rrdp_opts: rrdp_opts], else: []) ++
      Keyword.delete(internal, :rrdp_opts)
  end

  # Repositories need rsync 3.1.0 or later. Checked before anything is
  # fetched, so an old rsync fails clearly instead of every fetch failing.
  # Progress on stderr (#96, D-036): a status line when stderr is a
  # terminal, timestamped lines otherwise, nothing with --quiet.
  defp with_progress(opts, err, fun) do
    {progress, stop} = progress_listener(opts, err)

    try do
      fun.(progress)
    after
      stop.()
    end
  end

  # The :progress option for the work, and a function that stops the
  # report. Progress is on by default (D-036): a status line on a
  # terminal, timestamped lines elsewhere; --quiet turns it off.
  defp progress_listener(opts, err) do
    tty? = err == :stderr and Progress.stderr_tty?()

    if opts[:quiet] do
      {[], fn -> :ok end}
    else
      {listener, stop} = Progress.start(err, if(tty?, do: :tty, else: :plain))
      {[progress: listener], stop}
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

  # Runs the sync and prints its summary to `out`; `code` gives the exit
  # code from the reports, and may add to the summary.
  defp sync(tals, cache, opts, out, err, command, code) do
    case Sync.run(tals, cache, Keyword.drop(opts, [:tal_dir, :generated])) do
      {:ok, reports} ->
        IO.write(out, Sync.summary(reports))
        code.(reports, out)

      {:error, {:locked, pid}} ->
        written(err, "#{command}: #{cache} is in use by another sync (process #{pid})\n", 1)

      {:error, reason} ->
        written(err, "#{command}: #{cache}: #{:file.format_error(reason)}\n", 1)
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
