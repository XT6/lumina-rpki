defmodule Mix.Tasks.Lumina.CompareVrps do
  @shortdoc "Compares lumina vrps output with Routinator's published CSV"

  @moduledoc """
  Compares a CSV written by `lumina vrps` with a reference CSV in the same
  columns, by default the one Routinator publishes for all trust anchors,
  downloaded now (#168, D-035). See `Lumina.VRPCompare`.

      lumina vrps --output vrps.csv
      mix lumina.compare_vrps vrps.csv
      mix lumina.compare_vrps --csv routinator.csv vrps.csv

  Prints, per trust anchor, the distinct VRPs on each side and the ones
  only one side has. Lumina's trust anchor names (its TAL files' names)
  are mapped to the reference's: `ripe-ncc` is `ripe`,
  `apnic-rfc7730-https` is `apnic`. Lines that aren't VRPs are reported
  and skipped. Differences don't fail the task: some come from the
  repositories changing between the two runs; the M7 done test bounds
  them (#170).

  ## Options

    * `--csv FILE` - read the reference from FILE instead of downloading it
    * `--url URL` - download the reference from URL (default:
      #{Lumina.VRPCompare.url()})
    * `--limit N` - list at most N VRPs per trust anchor and side (default: 20)
  """

  use Mix.Task

  alias Lumina.VRPCompare

  @switches [csv: :string, url: :string, limit: :integer]

  @impl Mix.Task
  def run(args) do
    case OptionParser.parse(args, strict: @switches) do
      {opts, [lumina_csv], []} ->
        Mix.Task.run("app.start")
        limit = Keyword.get(opts, :limit, 20)
        lumina = parse!(read!(lumina_csv), lumina_csv)
        {source, text} = reference!(opts)
        reference = parse!(text, source)

        Mix.shell().info(VRPCompare.report(VRPCompare.compare(lumina, reference), limit))
        malformed(lumina_csv, lumina, limit)
        malformed(source, reference, limit)

      _ ->
        Mix.raise(
          "usage: mix lumina.compare_vrps [--csv FILE | --url URL] [--limit N] LUMINA_CSV"
        )
    end
  end

  defp reference!(opts) do
    case {opts[:csv], opts[:url]} do
      {nil, url} ->
        url = url || VRPCompare.url()
        Mix.shell().info("Downloading #{url}")

        case VRPCompare.fetch(url) do
          {:ok, body} -> {url, body}
          {:error, error} -> Mix.raise("can't download #{url}: #{inspect(error)}")
        end

      {file, nil} ->
        {file, read!(file)}

      _ ->
        Mix.raise("give --csv or --url, not both")
    end
  end

  defp read!(path) do
    case File.read(path) do
      {:ok, text} -> text
      {:error, reason} -> Mix.raise("can't read #{path}: #{:file.format_error(reason)}")
    end
  end

  defp parse!(text, source) do
    case VRPCompare.parse(text) do
      {:ok, parsed} -> parsed
      {:error, message} -> Mix.raise("#{source}: #{message}")
    end
  end

  defp malformed(_source, %{malformed: []}, _limit), do: :ok

  defp malformed(source, %{malformed: lines}, limit) do
    Mix.shell().error("#{source}: #{length(lines)} lines skipped, not VRPs:")

    lines
    |> Enum.take(limit)
    |> Enum.each(fn {number, line, reason} ->
      Mix.shell().error("  line #{number}: #{reason}: #{line}")
    end)
  end
end
