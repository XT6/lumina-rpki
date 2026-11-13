defmodule Lumina.CLI do
  @moduledoc """
  The `lumina` command line tool, built as an escript (`mix escript.build`).

  It follows the command plus flags model (D-001 in doc/decisions.md):

      lumina <command> [flags] [arguments]
      lumina print [--brief] FILE...
      lumina sync [--cache DIR] [--tal FILE]... [--timeout SECONDS] [--max-depth N]
      lumina help [command]

  Exit codes, shared by all commands: 0 success, 1 a file failed to
  decode or a fetch failed, 2 a usage error (including an unknown command
  or flag).
  """

  alias Lumina.{Object, Print, Sync, TAL}

  @usage """
  Usage: lumina <command> [flags] [arguments]

  Commands:
    print   print RPKI objects and TALs in human-readable form
    sync    fetch the trust anchors and repositories into the local cache
    help    show help for lumina or a command

  Run "lumina help <command>" for a command's flags.

  Exit codes: 0 success, 1 a file failed to decode or a fetch failed,
  2 usage error.
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

  For each TAL, fetch its trust anchor certificate (HTTPS first, then
  rsync) and check it against the TAL, then walk the repository from it
  and mirror every publication point into the cache with rsync. A failed
  fetch keeps the last good copy. Nothing is validated yet: this only
  fetches.

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

  Prints one summary per TAL: the TA URI used, the publication points
  and rsync fetches, and every failure with its reason.

  Exit codes: 0 everything fetched, 1 some fetch failed (the cache is
  still usable) or another sync holds the cache, 2 usage error.
  """

  @help %{"print" => @print_usage, "sync" => @sync_usage}

  @doc "Escript entry point."
  @spec main([String.t()]) :: no_return()
  def main(args), do: System.halt(run(args))

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
          sync(tals, opts[:cache] || default_cache(), limits ++ internal, out, err)
        else
          {:error, message} -> written(err, "lumina sync: #{message}\n", 2)
        end

      {_opts, _args, [{flag, _} | _]} ->
        written(err, "lumina sync: unknown or invalid flag #{flag}\n\n" <> @sync_usage, 2)

      {_opts, [arg | _], []} ->
        written(err, "lumina sync: unexpected argument #{arg}\n\n" <> @sync_usage, 2)
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

      true ->
        {:ok, Keyword.take(opts, [:timeout, :max_depth])}
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
