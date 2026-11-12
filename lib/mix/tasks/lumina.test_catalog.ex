defmodule Mix.Tasks.Lumina.TestCatalog do
  @shortdoc "Generates the test fixture catalog"

  @moduledoc """
  Writes `doc/tests/CATALOG.md` from the Barry fixture metadata: every
  fixture grouped by milestone, with its rationale, RFC references and
  expected outcome.

      mix lumina.test_catalog           # write the catalog
      mix lumina.test_catalog --check   # fail if the committed catalog is out of date

  The task fails if any fixture fails its metadata check.

  ## Options

    * `--check` - don't write; fail if the catalog differs from what would be generated
    * `--output` - catalog path (default: `doc/tests/CATALOG.md`)
    * `--dir` - fixture root (default: `test/fixtures/barry`)
  """

  use Mix.Task

  alias Mix.Lumina.{Catalog, Fixtures}

  @switches [check: :boolean, output: :string, dir: :string]

  @impl Mix.Task
  def run(args) do
    {opts, _rest} = OptionParser.parse!(args, strict: @switches)
    output = Keyword.get(opts, :output, Catalog.path())

    case Fixtures.load_all(Keyword.get(opts, :dir, Fixtures.dir())) do
      {fixtures, []} ->
        catalog = Catalog.render(fixtures, output)
        if opts[:check], do: check!(output, catalog), else: write!(output, catalog)

      {_fixtures, problems} ->
        Enum.each(problems, &Mix.shell().error("#{&1.file}: #{&1.message}"))

        Mix.raise(
          "#{length(problems)} fixture problem(s); fix them before generating the catalog"
        )
    end
  end

  defp write!(output, catalog) do
    File.mkdir_p!(Path.dirname(output))
    File.write!(output, catalog)
    Mix.shell().info("wrote #{output}")
  end

  defp check!(output, catalog) do
    case File.read(output) do
      {:ok, ^catalog} ->
        Mix.shell().info("#{output} is up to date")

      _ ->
        Mix.raise(
          "#{output} is out of date. Run `mix lumina.test_catalog` and commit the result."
        )
    end
  end
end
