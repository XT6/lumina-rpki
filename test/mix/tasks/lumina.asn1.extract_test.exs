defmodule Mix.Tasks.Lumina.Asn1.ExtractTest do
  @moduledoc """
  Tests the extraction task, especially --check, which makes CI fail when an
  extracted or built module is edited by hand instead of being regenerated
  from the RFC text and the patches. Also checks that broken or stray
  patches stop the task.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.ASN1
  alias Mix.Tasks.Lumina.Asn1.Extract

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp} do
    patches = Path.join(tmp, "patches")
    File.mkdir_p!(patches)

    for path <- Path.wildcard("asn1/patches/*.patch"),
        do: File.cp!(path, Path.join(patches, Path.basename(path)))

    %{rfc: Path.join(tmp, "rfc"), build: Path.join(tmp, "build"), patches: patches}
  end

  defp run_task(ctx, extra \\ []) do
    args = ["--output", ctx.rfc, "--build", ctx.build, "--patches", ctx.patches | extra]
    ExUnit.CaptureIO.capture_io(fn -> Extract.run(args) end)
  end

  test "writes every extracted and built module, then --check passes", ctx do
    run_task(ctx)

    for spec <- ASN1.modules(), dir <- [ctx.rfc, ctx.build] do
      assert File.regular?(Path.join(dir, ASN1.file_name(spec))), "#{dir}/#{spec.name}"
    end

    assert run_task(ctx, ["--check"]) =~ "are up to date"
  end

  test "the output matches what is committed", ctx do
    run_task(ctx)

    for spec <- ASN1.modules(),
        {dir, committed} <- [{ctx.rfc, "asn1/rfc"}, {ctx.build, "asn1/build"}] do
      assert File.read!(Path.join(dir, ASN1.file_name(spec))) ==
               File.read!(Path.join(committed, ASN1.file_name(spec))),
             "#{committed}/#{spec.name}"
    end
  end

  test "--check fails when an extracted module was edited by hand", ctx do
    run_task(ctx)
    path = Path.join(ctx.rfc, "RPKI-ROA-2023.asn1")
    File.write!(path, String.replace(File.read!(path), "INTEGER", "BOOLEAN", global: false))

    assert_raise Mix.Error, ~r/out of date: .*rfc\/RPKI-ROA-2023.asn1/, fn ->
      run_task(ctx, ["--check"])
    end
  end

  test "--check fails when a built module was edited by hand", ctx do
    run_task(ctx)
    path = Path.join(ctx.build, "RPKIManifest.asn1")
    File.write!(path, String.replace(File.read!(path), "0..MAX", "1..MAX"))

    assert_raise Mix.Error, ~r/out of date: .*build\/RPKIManifest.asn1/, fn ->
      run_task(ctx, ["--check"])
    end
  end

  test "--check fails on a file for a module that is no longer listed", ctx do
    run_task(ctx)
    File.write!(Path.join(ctx.build, "Stale.asn1"), "Stale DEFINITIONS ::= BEGIN END\n")

    assert_raise Mix.Error, ~r/Stale.asn1/, fn -> run_task(ctx, ["--check"]) end
  end

  test "writing removes files for modules that are no longer listed", ctx do
    File.mkdir_p!(ctx.rfc)
    File.write!(Path.join(ctx.rfc, "Stale.asn1"), "Stale DEFINITIONS ::= BEGIN END\n")

    assert run_task(ctx) =~ "removed"
    refute File.exists?(Path.join(ctx.rfc, "Stale.asn1"))
  end

  test "fails when a patch no longer applies to the extracted text", ctx do
    path = Path.join(ctx.patches, "RPKI-ROA-2023.patch")

    File.write!(
      path,
      String.replace(File.read!(path), " DEFINITIONS EXPLICIT", " DEFINITIONS IMPLICIT")
    )

    assert_raise Mix.Error, ~r/RPKI-ROA-2023.patch: hunk at line \d+ does not match/, fn ->
      run_task(ctx)
    end
  end

  test "fails when a patch makes a change its kind doesn't allow", ctx do
    path = Path.join(ctx.patches, "RPKIManifest.patch")

    File.write!(path, """
    --- a/RPKIManifest.asn1
    +++ b/RPKIManifest.asn1
    @@ -32,1 +32,2 @@
    -      version        [0] INTEGER DEFAULT 0,
    +   -- LUMINA PATCH (content-type): not really.
    +      version        [0] INTEGER DEFAULT 1,
    """)

    assert_raise Mix.Error, ~r/a content-type patch may not remove/, fn -> run_task(ctx) end
  end

  test "fails on a patch for a module that isn't listed", ctx do
    File.write!(Path.join(ctx.patches, "Unknown.patch"), "@@ -1,1 +1,1 @@\n-a\n+b\n")
    assert_raise Mix.Error, ~r/Unknown.patch doesn't match any module/, fn -> run_task(ctx) end
  end
end
