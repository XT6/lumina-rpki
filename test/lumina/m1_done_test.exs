defmodule Lumina.M1DoneTest do
  @moduledoc """
  The end-to-end check that closes M1 (#33): every object in every Barry
  fixture decodes through `Lumina.Object`, including the fixtures whose
  objects break the RPKI profile (decoding is structural), and every
  malformed variant built by `Lumina.Test.Mutate` is rejected at the DER
  layer with the expected rule.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, CRL, Manifest, Object, ROA}
  alias Lumina.Test.Mutate

  @structs %{".cer" => Certificate, ".crl" => CRL, ".mft" => Manifest, ".roa" => ROA}

  defp fixture_objects do
    for dir <- Mix.Lumina.Fixtures.case_dirs(),
        path <- Path.wildcard(Path.join([dir, "rsync", "**", "*"])),
        File.regular?(path),
        do: path
  end

  @tag rfc: ["6481#2.2", "6488#3", "6487#4", "9582#4", "9286#4"]
  test "every object in every fixture decodes as its type, including profile violations" do
    paths = fixture_objects()
    fixtures = paths |> Enum.map(&(&1 |> Path.split() |> Enum.at(3))) |> Enum.uniq()

    assert length(fixtures) == length(Mix.Lumina.Fixtures.case_dirs())
    assert length(paths) >= 40

    for path <- paths do
      assert {:ok, %Object{value: value}} = Object.decode_file(path), path
      assert value.__struct__ == @structs[Path.extname(path)], path
    end
  end

  @tag rfc: ["6488#3", "6481#2.2"],
       doc: """
       Each mutation in Lumina.Test.Mutate breaks one DER rule. It's applied to
       every object it fits; certificates and CRLs have no signed attributes,
       so the signed-attribute mutation only applies to manifests and ROAs.
       """
  test "every malformed variant of every fixture object is rejected at the DER layer" do
    results =
      for path <- fixture_objects(),
          der = File.read!(path),
          {name, mutate, rule} <- Mutate.all(),
          {:ok, mutated} <- [mutate.(der)] do
        result = Object.decode(Path.basename(path), mutated)

        assert {:error, {:der, %{rule: ^rule}} = reason} = result,
               "#{name} on #{path}: #{inspect(result)}"

        assert Object.layer(reason) == :der
        {name, Path.extname(path)}
      end

    # Every mutation was exercised, and on more than one object type.
    by_mutation = Enum.group_by(results, &elem(&1, 0), &elem(&1, 1))

    assert Map.keys(by_mutation) |> Enum.sort() ==
             Mutate.all() |> Enum.map(&elem(&1, 0)) |> Enum.sort()

    assert by_mutation.trailing_byte |> Enum.uniq() |> Enum.sort() == [
             ".cer",
             ".crl",
             ".mft",
             ".roa"
           ]

    assert by_mutation.unsorted_signed_attrs |> Enum.uniq() |> Enum.sort() == [".mft", ".roa"]
  end

  @tag rfc: ["3779#2.2.3.5", "3779#3.2.3.3"]
  test "inherited resources decode as :inherit, not as empty lists" do
    fixture = Lumina.Test.Fixture.load!("m1-resources-inherit")
    {:ok, ca2} = Certificate.decode(File.read!(Path.join(fixture.rsync_root, "ca1/ca2.cer")))

    assert Enum.map(Certificate.extension_value(ca2, :ip_resources), &{&1.afi, &1.resources}) ==
             [ipv4: :inherit, ipv6: :inherit]

    assert Certificate.extension_value(ca2, :as_resources).asnum == :inherit
  end
end
