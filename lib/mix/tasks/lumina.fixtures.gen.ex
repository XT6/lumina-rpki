defmodule Mix.Tasks.Lumina.Fixtures.Gen do
  @shortdoc "Regenerates Barry test fixtures"

  @moduledoc """
  Runs Barry on fixture descriptors and replaces the generated output.

      mix lumina.fixtures.gen                     # every fixture
      mix lumina.fixtures.gen m0-minimal-valid    # one or more fixtures, by id

  For each fixture folder (`test/fixtures/barry/<id>/`) the task removes
  the old `case.tal`, `rsync/` and `rrdp/`, runs Barry on `case.repo` with
  the fixture's validity period, then checks the fixture's metadata and
  output. It fails if Barry fails or a fixture doesn't pass the check.

  Barry generates fresh keys on every run, so regenerated files differ byte
  for byte from the committed ones. The validity period is fixed (see
  `Mix.Lumina.Fixtures.default_barry_opts/0`), so fixtures don't expire.

  Barry is taken from `_tools/bin/barry` (see `doc/barry.md`), or from
  `$LUMINA_TOOLS/bin/barry`.

  ## Options

    * `--dir` - fixture root (default: `test/fixtures/barry`)
  """

  use Mix.Task

  alias Mix.Lumina.{Fixtures, RFC}

  @impl Mix.Task
  def run(args) do
    {opts, ids} = OptionParser.parse!(args, strict: [dir: :string])
    root = Keyword.get(opts, :dir, Fixtures.dir())
    barry = barry_path()
    library = RFC.load_library()

    case_dirs = select(root, ids)

    if case_dirs == [] do
      Mix.shell().info("No fixtures found under #{root}.")
    end

    problems =
      Enum.flat_map(case_dirs, fn case_dir ->
        generate!(case_dir, barry)

        case Fixtures.load(case_dir, library) do
          {:ok, fixture} ->
            Mix.shell().info("generated #{fixture.id}")
            []

          {:error, problems} ->
            problems
        end
      end)

    if problems != [] do
      Enum.each(problems, &Mix.shell().error("#{&1.file}: #{&1.message}"))
      Mix.raise("#{length(problems)} fixture problem(s)")
    end
  end

  @doc """
  Regenerates one fixture folder with the Barry binary at `barry`.
  """
  @spec generate!(Path.t(), Path.t()) :: :ok
  def generate!(case_dir, barry) do
    unless File.regular?(Path.join(case_dir, "case.repo")) do
      Mix.raise("#{case_dir}: missing case.repo")
    end

    opts =
      case Fixtures.read_metadata(case_dir) do
        {:ok, meta} -> Fixtures.barry_opts(meta)
        {:error, message} -> Mix.raise("#{Fixtures.meta_path(case_dir)}: #{message}")
      end

    Enum.each(["case.tal", "rsync", "rrdp"], &File.rm_rf!(Path.join(case_dir, &1)))

    args = ["--now=#{opts[:now]}", "--later=#{opts[:later]}", "case.repo"]

    case System.cmd(barry, args, cd: case_dir, stderr_to_stdout: true) do
      {_output, 0} -> :ok
      {output, status} -> Mix.raise("#{case_dir}: barry exited with #{status}:\n#{output}")
    end
  end

  @doc "Path of the Barry binary."
  @spec barry_path() :: Path.t()
  def barry_path do
    tools = System.get_env("LUMINA_TOOLS") || Path.expand("_tools")
    path = Path.join([tools, "bin", "barry"])

    if File.regular?(path),
      do: path,
      else:
        Mix.raise("Barry not found at #{path}. Run scripts/install-barry.sh (see doc/barry.md).")
  end

  defp select(root, []), do: Fixtures.case_dirs(root)

  defp select(root, ids) do
    for id <- ids do
      case_dir = Path.join(root, id)

      if File.dir?(case_dir),
        do: case_dir,
        else: Mix.raise("no fixture #{inspect(id)} in #{root}")
    end
  end
end
