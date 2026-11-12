defmodule Mix.Tasks.Lumina.Asn1.Extract do
  @shortdoc "Extracts ASN.1 modules from the RFC texts"

  @moduledoc """
  Extracts the ASN.1 modules Lumina compiles from the RFC texts in
  `doc/rfc/` into `asn1/rfc/`, one file per module. See
  `Mix.Lumina.ASN1` for the module list and `asn1/README.md`.

      mix lumina.asn1.extract           # write asn1/rfc/*.asn1
      mix lumina.asn1.extract --check   # fail if the committed files differ

  ## Options

    * `--check` - don't write; fail if any file differs from a fresh extraction
    * `--rfc-dir` - RFC library (default: `doc/rfc`)
    * `--output` - output directory (default: `asn1/rfc`)
  """

  use Mix.Task

  alias Mix.Lumina.ASN1

  @switches [check: :boolean, rfc_dir: :string, output: :string]

  @impl Mix.Task
  def run(args) do
    {opts, _rest} = OptionParser.parse!(args, strict: @switches)
    rfc_dir = Keyword.get(opts, :rfc_dir, "doc/rfc")
    output = Keyword.get(opts, :output, ASN1.output_dir())

    extracted =
      for spec <- ASN1.modules() do
        text = File.read!(Path.join(rfc_dir, "rfc#{spec.rfc}.txt"))

        case ASN1.extract(spec, text) do
          {:ok, contents} -> {Path.join(output, ASN1.file_name(spec)), contents}
          {:error, message} -> Mix.raise("RFC #{spec.rfc}: #{message}")
        end
      end

    if opts[:check], do: check!(extracted, output), else: write!(extracted, output)
  end

  defp write!(extracted, output) do
    File.mkdir_p!(output)

    for {path, contents} <- extracted do
      File.write!(path, contents)
      Mix.shell().info("wrote #{path}")
    end

    remove_stale!(extracted, output)
  end

  # Files for modules no longer in the list would otherwise linger.
  defp remove_stale!(extracted, output) do
    expected = MapSet.new(extracted, &elem(&1, 0))

    for path <- Path.wildcard(Path.join(output, "*.asn1")), path not in expected do
      File.rm!(path)
      Mix.shell().info("removed #{path}")
    end
  end

  defp check!(extracted, output) do
    expected = MapSet.new(extracted, &elem(&1, 0))

    stale =
      for {path, contents} <- extracted, File.read(path) != {:ok, contents}, do: path

    extra =
      for path <- Path.wildcard(Path.join(output, "*.asn1")), path not in expected, do: path

    case stale ++ extra do
      [] ->
        Mix.shell().info("#{output} is up to date")

      paths ->
        Mix.raise(
          "out of date: #{Enum.join(paths, ", ")}. Run `mix lumina.asn1.extract` " <>
            "and commit the result. Never edit extracted modules by hand."
        )
    end
  end
end
