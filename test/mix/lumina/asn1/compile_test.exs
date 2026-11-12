defmodule Mix.Lumina.ASN1.CompileTest do
  @moduledoc """
  Checks that the patched modules in asn1/build/ compile with OTP's asn1ct
  using DER encoding rules, and that the published modules in asn1/rfc/
  don't. The second part shows each patch is still needed: if a future OTP
  accepts a published module, the test fails, so the patch can be dropped.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.ASN1

  @moduletag :tmp_dir

  # Compiles one module; `deps` is where the .asn1db files of its imports are.
  defp compile(source, out, deps) do
    File.mkdir_p!(out)
    opts = [:der, :noobj, {:outdir, String.to_charlist(out)}, {:i, String.to_charlist(deps)}]

    {result, _output} =
      ExUnit.CaptureIO.with_io(fn -> :asn1ct.compile(String.to_charlist(source), opts) end)

    result
  end

  # Compiles the patched modules in list order, each module's imports first.
  defp compile_build(out) do
    for spec <- ASN1.modules() do
      {spec.name, compile(Path.join(ASN1.build_dir(), ASN1.file_name(spec)), out, out)}
    end
  end

  @tag rfc: ["5280#A.1", "5280#A.2", "5652#12.1", "3779#A", "9582#4", "9286#A"]
  test "every patched module compiles with asn1ct (DER)", %{tmp_dir: tmp} do
    for {name, result} <- compile_build(tmp) do
      assert result == :ok, "#{name}: #{inspect(result)}"
    end
  end

  @tag doc:
         "Documents F-005, F-006 and F-007 in doc/rfc-findings.md as observed compiler behaviour."
  test "each published module that has a patch fails to compile as is", %{tmp_dir: tmp} do
    deps = Path.join(tmp, "deps")
    compile_build(deps)

    patched = for path <- Path.wildcard("asn1/patches/*.patch"), do: Path.basename(path, ".patch")
    assert patched != []

    for name <- patched do
      source = Path.join(ASN1.output_dir(), name <> ".asn1")

      assert {:error, _} = compile(source, Path.join(tmp, name), deps),
             "#{name} now compiles unpatched; its patch may be unnecessary"
    end
  end

  test "modules without a patch compile as published" do
    patched = for path <- Path.wildcard("asn1/patches/*.patch"), do: Path.basename(path, ".patch")

    for spec <- ASN1.modules(), spec.name not in patched do
      assert File.read!(Path.join(ASN1.build_dir(), ASN1.file_name(spec))) ==
               File.read!(Path.join(ASN1.output_dir(), ASN1.file_name(spec))),
             "#{spec.name} has no patch, so its build file must equal the extracted module"
    end
  end
end
