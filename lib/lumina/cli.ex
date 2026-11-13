defmodule Lumina.CLI do
  @moduledoc """
  The `lumina` command line tool, built as an escript (`mix escript.build`).

      lumina --print FILE...   print RPKI objects in human-readable form
      lumina --help            show usage

  Exit codes: 0 when every file printed, 1 when any file failed to decode,
  2 for usage errors. The validator commands come in M7.
  """

  alias Lumina.{Object, Print}

  @usage """
  Usage: lumina --print FILE...

  Print RPKI objects (.cer, .crl, .mft, .roa, and the envelope of .gbr, .sig
  and .tak) as human-readable text, one field per line. Printing shows what
  is in each file; it doesn't validate it.

  Options:
    --print FILE...   decode and print each file
    -h, --help        show this help

  Exit codes: 0 all files printed, 1 a file failed to decode, 2 usage error.
  """

  @doc "Escript entry point."
  @spec main([String.t()]) :: no_return()
  def main(args), do: System.halt(run(args))

  @doc """
  Runs the command with `args`, writing to `out` and `err`, and returns the
  exit code. Separate from `main/1` so it can be tested without halting.
  """
  @spec run([String.t()], IO.device(), IO.device()) :: 0 | 1 | 2
  def run(args, out \\ :stdio, err \\ :stderr) do
    case args do
      [flag] when flag in ["-h", "--help"] ->
        IO.write(out, @usage)
        0

      ["--print" | [_ | _] = paths] ->
        if Enum.any?(paths, &String.starts_with?(&1, "-")),
          do: usage(err),
          else: print(paths, out, err)

      _ ->
        usage(err)
    end
  end

  defp usage(err) do
    IO.write(err, @usage)
    2
  end

  defp print(paths, out, err) do
    many? = length(paths) > 1

    results =
      paths
      |> Enum.with_index()
      |> Enum.map(fn {path, index} ->
        if many?, do: IO.write(out, if(index > 0, do: "\n", else: "") <> "==> #{path} <==\n")

        case Object.decode_file(path) do
          {:ok, object} ->
            IO.write(out, Print.render(object))
            :ok

          {:error, reason} ->
            IO.write(err, "lumina: #{path}: #{Print.error(reason, path)}\n")
            :error
        end
      end)

    if Enum.all?(results, &(&1 == :ok)), do: 0, else: 1
  end
end
