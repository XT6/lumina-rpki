defmodule Lumina.CLI do
  @moduledoc """
  The `lumina` command line tool, built as an escript (`mix escript.build`).

  It follows the command plus flags model (D-001 in doc/decisions.md):

      lumina <command> [flags] [arguments]
      lumina print [--brief] FILE...
      lumina help [command]

  Exit codes, shared by all commands: 0 success, 1 a file failed to
  decode, 2 a usage error (including an unknown command or flag).
  """

  alias Lumina.{Object, Print}

  @usage """
  Usage: lumina <command> [flags] [arguments]

  Commands:
    print   print RPKI objects in human-readable form
    help    show help for lumina or a command

  Run "lumina help <command>" for a command's flags.

  Exit codes: 0 success, 1 a file failed to decode, 2 usage error.
  """

  @print_usage """
  Usage: lumina print [--brief] FILE...

  Print RPKI objects (.cer, .crl, .mft, .roa, and the envelope of .gbr, .sig
  and .tak) as human-readable text, one field per line. Printing shows what
  is in each file; it doesn't validate it.

  Flags:
    --brief   leave out most cryptographic detail (key identifiers, keys,
              signatures, digests, signer details, manifest hashes); keep
              validity dates, names, resources, URIs, prefixes and file names

  Exit codes: 0 all files printed, 1 a file failed to decode, 2 usage error.
  """

  @help %{"print" => @print_usage}

  @doc "Escript entry point."
  @spec main([String.t()]) :: no_return()
  def main(args), do: System.halt(run(args))

  @doc """
  Runs the command line `args`, writing to `out` and `err`, and returns the
  exit code. Separate from `main/1` so it can be tested without halting.
  """
  @spec run([String.t()], IO.device(), IO.device()) :: 0 | 1 | 2
  def run(args, out \\ :stdio, err \\ :stderr) do
    case args do
      [help] when help in ["help", "-h", "--help"] -> written(out, @usage, 0)
      ["help", command] -> help(command, out, err)
      ["print" | rest] -> print_command(rest, out, err)
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

        case Object.decode_file(path) do
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
end
