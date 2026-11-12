defmodule Mix.Tasks.Lumina.TestCatalogTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.Lumina.TestCatalog

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp_dir} do
    fixtures = Path.join(tmp_dir, "fixtures")
    File.mkdir_p!(fixtures)
    %{fixtures: fixtures, output: Path.join([tmp_dir, "tests", "CATALOG.md"])}
  end

  defp run_task(args), do: ExUnit.CaptureIO.capture_io(fn -> TestCatalog.run(args) end)

  defp add_fixture(fixtures, id, meta) do
    case_dir = Path.join(fixtures, id)
    File.mkdir_p!(Path.join(case_dir, "rsync"))
    File.write!(Path.join(case_dir, "case.repo"), "ta.cer\n")
    File.write!(Path.join(case_dir, "case.tal"), "rsync://localhost/ta.cer\n")
    File.write!(Path.join([case_dir, "rsync", "ta.cer"]), "x")
    File.write!(Path.join(case_dir, "case.exs"), meta)
  end

  @meta """
  %{id: "m0-sample", title: "Sample", milestone: "M0", rationale: "Why.",
    rfc: ["6487#4"], expected: :valid}
  """

  test "writes the catalog, then --check passes", %{fixtures: fixtures, output: output} do
    add_fixture(fixtures, "m0-sample", @meta)

    assert run_task(["--dir", fixtures, "--output", output]) =~ "wrote #{output}"
    assert File.read!(output) =~ "### `m0-sample`: Sample"
    assert run_task(["--dir", fixtures, "--output", output, "--check"]) =~ "is up to date"
  end

  test "--check fails when a fixture is added without regenerating", %{
    fixtures: fixtures,
    output: output
  } do
    run_task(["--dir", fixtures, "--output", output])
    add_fixture(fixtures, "m0-sample", @meta)

    assert_raise Mix.Error, ~r/is out of date/, fn ->
      run_task(["--dir", fixtures, "--output", output, "--check"])
    end
  end

  test "--check fails when a fixture changes without regenerating", %{
    fixtures: fixtures,
    output: output
  } do
    add_fixture(fixtures, "m0-sample", @meta)
    run_task(["--dir", fixtures, "--output", output])
    add_fixture(fixtures, "m0-sample", String.replace(@meta, ~s("Why."), ~s("A better reason.")))

    assert_raise Mix.Error, ~r/is out of date/, fn ->
      run_task(["--dir", fixtures, "--output", output, "--check"])
    end
  end

  test "--check fails when the catalog is missing", %{fixtures: fixtures, output: output} do
    assert_raise Mix.Error, ~r/is out of date/, fn ->
      run_task(["--dir", fixtures, "--output", output, "--check"])
    end
  end

  test "fails when a fixture fails its metadata check", %{fixtures: fixtures, output: output} do
    add_fixture(fixtures, "m0-sample", String.replace(@meta, ~s(rationale: "Why.",), ""))

    assert_raise Mix.Error, ~r/1 fixture problem/, fn ->
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        run_task(["--dir", fixtures, "--output", output])
      end)
    end

    refute File.exists?(output)
  end
end
