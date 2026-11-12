defmodule Mix.Tasks.Lumina.RfcCoverage do
  @shortdoc "Lists which RFC sections are covered by tests"

  @moduledoc """
  Lists, per RFC and section, the tests that reference it through the `:rfc`
  tag, and the Barry fixtures that reference it in their metadata. See
  `doc/testing.md`.

      mix lumina.rfc_coverage
      mix lumina.rfc_coverage --rfc 8897

  With `--rfc`, every section of that RFC is listed, including the ones no
  test covers. Use it with RFC 8897 to see which RP requirements are covered.

  The task fails if any reference is malformed or points to an RFC or
  section missing from the RFC library, or if a fixture fails its metadata
  check.

  ## Options

    * `--rfc` - list every section of this RFC, covered or not
    * `--tests` - test directory to scan (default: `test`)
    * `--rfc-dir` - RFC library directory (default: `doc/rfc`)
    * `--fixtures` - Barry fixture directory (default: `test/fixtures/barry`)
  """

  use Mix.Task

  alias Mix.Lumina.{Fixtures, RFC, RFCTags}

  @switches [rfc: :integer, tests: :string, rfc_dir: :string, fixtures: :string]

  @impl Mix.Task
  def run(args) do
    {opts, _rest} = OptionParser.parse!(args, strict: @switches)
    library = RFC.load_library(Keyword.get(opts, :rfc_dir, "doc/rfc"))
    {tests, problems} = RFCTags.scan_dir(Keyword.get(opts, :tests, "test"))

    {fixtures, fixture_problems} =
      Fixtures.load_all(Keyword.get(opts, :fixtures, Fixtures.dir()), library)

    case problems ++ RFCTags.validate(tests, library) ++ fixture_problems do
      [] ->
        (tests ++ Enum.map(fixtures, &fixture_entry/1))
        |> report(library, opts[:rfc])
        |> Mix.shell().info()

      problems ->
        Enum.each(problems, &Mix.shell().error(location(&1) <> ": " <> &1.message))
        Mix.raise("#{length(problems)} invalid RFC reference(s)")
    end
  end

  defp fixture_entry(fixture) do
    %{
      file: Fixtures.meta_path(fixture.dir),
      line: 1,
      name: "fixture: " <> fixture.title,
      refs: fixture.rfc
    }
  end

  defp location(%{line: line} = problem), do: "#{problem.file}:#{line}"
  defp location(problem), do: problem.file

  @doc """
  Builds the coverage report. With `only_rfc`, every section of that RFC is
  listed; otherwise only covered sections are.
  """
  @spec report([RFCTags.tagged_test()], RFC.library(), pos_integer() | nil) :: String.t()
  def report(tests, library, only_rfc \\ nil) do
    coverage =
      for test <- tests, string <- test.refs, reduce: %{} do
        acc ->
          {:ok, ref} = RFC.parse(string)
          Map.update(acc, {ref.rfc, ref.section}, [test], &(&1 ++ [test]))
      end

    if only_rfc, do: full_report(only_rfc, coverage, library), else: covered_report(coverage)
  end

  defp covered_report(coverage) when coverage == %{}, do: "No tests reference an RFC section."

  defp covered_report(coverage) do
    coverage
    |> Enum.group_by(fn {{rfc, _}, _} -> rfc end, fn {{_, section}, tests} -> {section, tests} end)
    |> Enum.sort()
    |> Enum.map_join("\n\n", fn {rfc, sections} ->
      by_section = Map.new(sections)

      lines =
        by_section
        |> Map.keys()
        |> RFC.sort_sections()
        |> Enum.map(&section_lines(&1, by_section[&1]))

      Enum.join(["RFC #{rfc}" | lines], "\n")
    end)
  end

  defp full_report(rfc, coverage, library) do
    sections =
      case Map.fetch(library, rfc) do
        {:ok, sections} -> RFC.sort_sections(sections)
        :error -> Mix.raise("RFC #{rfc} is not in the RFC library")
      end

    covered = Enum.count(sections, &Map.has_key?(coverage, {rfc, &1}))

    lines = Enum.map(sections, &section_lines(&1, Map.get(coverage, {rfc, &1}, [])))

    Enum.join(["RFC #{rfc}: #{covered} of #{length(sections)} sections covered" | lines], "\n")
  end

  defp section_lines(section, []), do: "  §#{section}  (not covered)"

  defp section_lines(section, tests) do
    Enum.join(
      ["  §#{section}" | Enum.map(tests, &"      #{&1.file}:#{&1.line}  #{&1.name}")],
      "\n"
    )
  end
end
