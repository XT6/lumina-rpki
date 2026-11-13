defmodule Mix.Tasks.Lumina.TestCatalog do
  @shortdoc "Generates the test fixture catalog"

  @moduledoc """
  Writes `doc/tests/CATALOG.md`: every Barry fixture grouped by milestone,
  with its rationale, RFC references and expected outcome, and every unit
  test grouped by module, with the module's `@moduledoc`, each test's
  `describe` block, RFC references and `doc` tag.

      mix lumina.test_catalog           # write the catalog
      mix lumina.test_catalog --check   # fail if the committed catalog is out of date

  The task fails if any fixture fails its metadata check or any test module
  is undocumented.

  ## Options

    * `--check` - don't write; fail if the catalog differs from what would be generated
    * `--output` - catalog path (default: `doc/tests/CATALOG.md`)
    * `--dir` - fixture root (default: `test/fixtures/barry`)
    * `--tests` - test directory to scan (default: `test`)
    * `--tal-cases` - test TAL corpus (default: `test/fixtures/tals/cases`)
  """

  use Mix.Task

  alias Mix.Lumina.{Catalog, Fixtures, TALCases, TestScanner}

  @switches [check: :boolean, output: :string, dir: :string, tests: :string, tal_cases: :string]

  @impl Mix.Task
  def run(args) do
    {opts, _rest} = OptionParser.parse!(args, strict: @switches)
    output = Keyword.get(opts, :output, Catalog.path())

    {fixtures, fixture_problems} = Fixtures.load_all(Keyword.get(opts, :dir, Fixtures.dir()))
    {modules, scan_problems} = TestScanner.scan_dir(Keyword.get(opts, :tests, "test"))
    {tal_cases, tal_problems} = TALCases.load_all(Keyword.get(opts, :tal_cases, TALCases.dir()))

    case fixture_problems ++ tal_problems ++ scan_problems ++ TestScanner.check_docs(modules) do
      [] ->
        catalog = Catalog.render(fixtures, modules, output, tal_cases)
        if opts[:check], do: check!(output, catalog), else: write!(output, catalog)

      problems ->
        Enum.each(problems, &Mix.shell().error(location(&1) <> ": " <> &1.message))
        Mix.raise("#{length(problems)} problem(s); fix them before generating the catalog")
    end
  end

  defp location(%{line: line} = problem), do: "#{problem.file}:#{line}"
  defp location(problem), do: problem.file

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
