defmodule Mix.Tasks.Lumina.Asn1.Extract do
  @shortdoc "Extracts ASN.1 modules from the RFC texts and applies the patches"

  @moduledoc """
  Extracts the ASN.1 modules Lumina compiles from the RFC texts in
  `doc/rfc/` into `asn1/rfc/`, one file per module, then applies the
  patches in `asn1/patches/` to produce the compiler inputs in
  `asn1/build/`. See `Mix.Lumina.ASN1`, `Mix.Lumina.ASN1.Patch` and
  `asn1/README.md`.

      mix lumina.asn1.extract           # write asn1/rfc/ and asn1/build/
      mix lumina.asn1.extract --check   # fail if either differs from a fresh run

  The task fails if a patch doesn't apply exactly, changes lines its kind
  doesn't allow, or belongs to no listed module.

  ## Options

    * `--check` - don't write; fail if any file differs from a fresh run
    * `--rfc-dir` - RFC library (default: `doc/rfc`)
    * `--output` - extracted modules (default: `asn1/rfc`)
    * `--build` - patched modules (default: `asn1/build`)
    * `--patches` - patch directory (default: `asn1/patches`)
  """

  use Mix.Task

  alias Mix.Lumina.ASN1

  @switches [check: :boolean, rfc_dir: :string, output: :string, build: :string, patches: :string]

  @impl Mix.Task
  def run(args) do
    {opts, _rest} = OptionParser.parse!(args, strict: @switches)
    rfc_dir = Keyword.get(opts, :rfc_dir, "doc/rfc")
    output = Keyword.get(opts, :output, ASN1.output_dir())
    build = Keyword.get(opts, :build, ASN1.build_dir())
    patches = Keyword.get(opts, :patches, ASN1.patches_dir())

    :ok = check_patch_names!(patches)

    files =
      Enum.flat_map(ASN1.modules(), fn spec ->
        text = File.read!(Path.join(rfc_dir, "rfc#{spec.rfc}.txt"))
        extracted = ok!(ASN1.extract(spec, text), "RFC #{spec.rfc}")
        patch = read_patch(patches, spec)
        built = ok!(ASN1.build(spec, extracted, patch), "patch")

        [
          {Path.join(output, ASN1.file_name(spec)), extracted},
          {Path.join(build, ASN1.file_name(spec)), built}
        ]
      end)

    dirs = [output, build]
    if opts[:check], do: check!(files, dirs), else: write!(files, dirs)
  end

  defp ok!({:ok, value}, _context), do: value
  defp ok!({:error, message}, context), do: Mix.raise("#{context}: #{message}")

  defp read_patch(dir, spec) do
    case File.read(Path.join(dir, spec.name <> ".patch")) do
      {:ok, patch} -> patch
      {:error, :enoent} -> nil
    end
  end

  # A patch for a module that isn't extracted would silently do nothing.
  defp check_patch_names!(dir) do
    known = MapSet.new(ASN1.modules(), &(&1.name <> ".patch"))

    case Enum.reject(Path.wildcard(Path.join(dir, "*.patch")), &(Path.basename(&1) in known)) do
      [] -> :ok
      [path | _] -> Mix.raise("#{path} doesn't match any module in Mix.Lumina.ASN1.modules/0")
    end
  end

  defp write!(files, dirs) do
    Enum.each(dirs, &File.mkdir_p!/1)

    for {path, contents} <- files do
      File.write!(path, contents)
      Mix.shell().info("wrote #{path}")
    end

    for path <- extra_files(files, dirs) do
      File.rm!(path)
      Mix.shell().info("removed #{path}")
    end
  end

  defp check!(files, dirs) do
    stale = for {path, contents} <- files, File.read(path) != {:ok, contents}, do: path

    case stale ++ extra_files(files, dirs) do
      [] ->
        Mix.shell().info("#{Enum.join(dirs, " and ")} are up to date")

      paths ->
        Mix.raise(
          "out of date: #{Enum.join(paths, ", ")}. Run `mix lumina.asn1.extract` " <>
            "and commit the result. Never edit extracted or built modules by hand; " <>
            "change a patch in asn1/patches/ instead."
        )
    end
  end

  # Files left over from modules that are no longer listed.
  defp extra_files(files, dirs) do
    expected = MapSet.new(files, &elem(&1, 0))

    for dir <- dirs,
        path <- Path.wildcard(Path.join(dir, "*.asn1")),
        path not in expected,
        do: path
  end
end
