defmodule Mix.Tasks.Lumina.Asn1.ExtractTest do
  @moduledoc """
  Tests the extraction task, especially --check, which makes CI fail when an
  extracted module is edited by hand instead of being regenerated from the
  RFC text.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.ASN1
  alias Mix.Tasks.Lumina.Asn1.Extract

  @moduletag :tmp_dir

  defp run_task(args), do: ExUnit.CaptureIO.capture_io(fn -> Extract.run(args) end)

  test "writes every module, then --check passes", %{tmp_dir: dir} do
    run_task(["--output", dir])

    for spec <- ASN1.modules() do
      assert File.regular?(Path.join(dir, ASN1.file_name(spec))), spec.name
    end

    assert run_task(["--output", dir, "--check"]) =~ "is up to date"
  end

  test "--check fails when an extracted module was edited by hand", %{tmp_dir: dir} do
    run_task(["--output", dir])
    path = Path.join(dir, "RPKI-ROA-2023.asn1")
    File.write!(path, String.replace(File.read!(path), "INTEGER", "BOOLEAN", global: false))

    assert_raise Mix.Error, ~r/out of date: .*RPKI-ROA-2023.asn1/, fn ->
      run_task(["--output", dir, "--check"])
    end
  end

  test "--check fails on a file for a module that is no longer listed", %{tmp_dir: dir} do
    run_task(["--output", dir])
    File.write!(Path.join(dir, "Stale.asn1"), "Stale DEFINITIONS ::= BEGIN END\n")

    assert_raise Mix.Error, ~r/Stale.asn1/, fn -> run_task(["--output", dir, "--check"]) end
  end

  test "writing removes files for modules that are no longer listed", %{tmp_dir: dir} do
    File.write!(Path.join(dir, "Stale.asn1"), "Stale DEFINITIONS ::= BEGIN END\n")
    assert run_task(["--output", dir]) =~ "removed"
    refute File.exists?(Path.join(dir, "Stale.asn1"))
  end
end
