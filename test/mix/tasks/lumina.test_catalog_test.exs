defmodule Mix.Tasks.Lumina.TestCatalogTest do
  @moduledoc """
  Tests the catalog task, especially --check, which is what makes CI fail
  when a fixture or test changes without the catalog being regenerated.
  Fixtures and test sources are written to temporary directories.
  """
  use ExUnit.Case, async: true

  alias Mix.Tasks.Lumina.TestCatalog

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp_dir} do
    fixtures = Path.join(tmp_dir, "fixtures")
    tests = Path.join(tmp_dir, "tests")
    File.mkdir_p!(fixtures)
    File.mkdir_p!(tests)
    %{fixtures: fixtures, tests: tests, output: Path.join([tmp_dir, "doc", "CATALOG.md"])}
  end

  # Runs the task against the temporary directories in `ctx`.
  defp run_task(ctx, extra \\ []) do
    args = ["--dir", ctx.fixtures, "--tests", ctx.tests, "--output", ctx.output | extra]
    ExUnit.CaptureIO.capture_io(fn -> TestCatalog.run(args) end)
  end

  defp run_task_quietly(ctx) do
    ExUnit.CaptureIO.capture_io(:stderr, fn -> run_task(ctx) end)
  end

  defp add_fixture(ctx, id, meta) do
    case_dir = Path.join(ctx.fixtures, id)
    File.mkdir_p!(Path.join(case_dir, "rsync"))
    File.write!(Path.join(case_dir, "case.repo"), "ta.cer\n")
    File.write!(Path.join(case_dir, "case.tal"), "rsync://localhost/ta.cer\n")
    File.write!(Path.join([case_dir, "rsync", "ta.cer"]), "x")
    File.mkdir_p!(Path.join(case_dir, "rrdp"))
    File.write!(Path.join([case_dir, "rrdp", "notification.xml"]), "<notification/>")
    File.write!(Path.join(case_dir, "case.exs"), meta)
  end

  defp write_test(ctx, source), do: File.write!(Path.join(ctx.tests, "sample_test.exs"), source)

  @meta """
  %{id: "m0-sample", title: "Sample", milestone: "M0", rationale: "Why.",
    rfc: ["6487#4"], expected: :valid}
  """

  @documented """
  defmodule SampleTest do
    @moduledoc "Covers sampling."
    use ExUnit.Case
    test "samples" do
    end
  end
  """

  test "writes the catalog, then --check passes", ctx do
    add_fixture(ctx, "m0-sample", @meta)
    write_test(ctx, @documented)

    assert run_task(ctx) =~ "wrote #{ctx.output}"
    catalog = File.read!(ctx.output)
    assert catalog =~ "#### `m0-sample`: Sample"
    assert catalog =~ "### `SampleTest`"
    assert run_task(ctx, ["--check"]) =~ "is up to date"
  end

  test "--check fails when a fixture is added without regenerating", ctx do
    run_task(ctx)
    add_fixture(ctx, "m0-sample", @meta)

    assert_raise Mix.Error, ~r/is out of date/, fn -> run_task(ctx, ["--check"]) end
  end

  test "--check fails when a fixture changes without regenerating", ctx do
    add_fixture(ctx, "m0-sample", @meta)
    run_task(ctx)
    add_fixture(ctx, "m0-sample", String.replace(@meta, ~s("Why."), ~s("A better reason.")))

    assert_raise Mix.Error, ~r/is out of date/, fn -> run_task(ctx, ["--check"]) end
  end

  test "--check fails when a unit test is added without regenerating", ctx do
    write_test(ctx, @documented)
    run_task(ctx)

    write_test(
      ctx,
      String.replace(@documented, "  end\nend", "  end\n  test \"also samples\" do\n  end\nend")
    )

    assert_raise Mix.Error, ~r/is out of date/, fn -> run_task(ctx, ["--check"]) end
  end

  test "--check fails when the catalog is missing", ctx do
    assert_raise Mix.Error, ~r/is out of date/, fn -> run_task(ctx, ["--check"]) end
  end

  test "fails when a fixture fails its metadata check", ctx do
    add_fixture(ctx, "m0-sample", String.replace(@meta, ~s(rationale: "Why.",), ""))

    assert_raise Mix.Error, ~r/1 problem/, fn -> run_task_quietly(ctx) end
    refute File.exists?(ctx.output)
  end

  test "fails when a test module has no @moduledoc", ctx do
    write_test(ctx, String.replace(@documented, "  @moduledoc \"Covers sampling.\"\n", ""))

    assert_raise Mix.Error, ~r/1 problem/, fn -> run_task_quietly(ctx) end
    refute File.exists?(ctx.output)
  end
end
