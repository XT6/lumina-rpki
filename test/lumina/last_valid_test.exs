defmodule Lumina.LastValidTest do
  @moduledoc """
  Tests the last valid copy of publication points (#135, D-023):
  `Lumina.LastValid` keeps an accepted point's manifest and listed files,
  and `Lumina.Validate.point/5` falls back to that copy when the point
  later fails, as long as its manifest is still current (RFC 9286 §6.6).

  The publication points are fixture copies on disk (ca1's, caRepository
  `rsync://localhost:8873/rpki/ca1`), changed between runs, at 2026-11-13
  unless a test says otherwise.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, LastValid, Validate}
  alias Lumina.Test.Fixture

  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]
  @key "rsync://localhost:8873/rpki/ca1"
  @manifest @key <> "/ca1.mft"

  defp copy(tmp, id) do
    dir = Path.join(tmp, id)
    File.cp_r!(Fixture.load!(id).rsync_root, dir)
    dir
  end

  defp ca1(dir) do
    {:ok, cert} = Certificate.decode(File.read!(Path.join(dir, "ta/ca1.cer")))
    cert
  end

  defp point(dir, cache, opts, now \\ @now),
    do:
      Validate.point(
        ca1(dir),
        Path.join(dir, "ca1"),
        @key,
        now,
        [objects: true, last_valid: cache] ++ opts
      )

  defp break_roa(dir), do: File.write!(Path.join(dir, "ca1/roa1.roa"), "changed", [:append])

  describe "LastValid" do
    @tag rfc: "9286#6.6"
    test "an accepted point is saved as its manifest and listed files, once per manifest", %{
      tmp_dir: tmp
    } do
      dir = copy(tmp, "m0-minimal-valid")
      cache = Path.join(tmp, "cache")
      File.write!(Path.join(dir, "ca1/extra.roa"), "not listed")

      assert %{point: %{status: :accepted}} = point(dir, cache, save: true)

      saved = LastValid.load(cache, @manifest)
      assert saved == Path.join(cache, ".valid/rsync/localhost:8873/rpki/ca1/ca1.mft")
      assert saved |> File.ls!() |> Enum.sort() == ["ca1.crl", "ca1.mft", "roa1.roa"]

      for file <- ["ca1.crl", "ca1.mft", "roa1.roa"],
          do:
            assert(
              File.read!(Path.join(saved, file)) == File.read!(Path.join([dir, "ca1", file]))
            )
    end

    @tag doc: "Same manifest bytes, same files: nothing is copied again."
    test "saving the same manifest again leaves the copy alone; a new manifest replaces it", %{
      tmp_dir: tmp
    } do
      cache = Path.join(tmp, "cache")
      first = copy(tmp, "m0-minimal-valid")
      %{point: point} = point(first, cache, [])

      assert LastValid.save(cache, point, Path.join(first, "ca1")) == :ok
      assert LastValid.save(cache, point, Path.join(first, "ca1")) == :unchanged

      second = copy(tmp, "m1-roa-prefixes")
      %{point: newer} = point(second, cache, [])
      assert LastValid.save(cache, newer, Path.join(second, "ca1")) == :ok

      saved = LastValid.load(cache, @manifest)

      assert File.read!(Path.join(saved, "ca1.mft")) ==
               File.read!(Path.join(second, "ca1/ca1.mft"))

      refute Enum.any?(File.ls!(Path.dirname(saved)), &String.starts_with?(&1, ".ca1.mft"))
    end

    test "a point never accepted has no copy" do
      assert LastValid.load("/nonexistent", @manifest) == nil
      assert LastValid.dir("/c", "not a uri") == nil
    end
  end

  describe "falling back (D-023)" do
    @tag rfc: "9286#6.6",
         doc: "roa1.roa changes, so its hash doesn't match: the saved copy is used instead."
    test "a point that fails uses its last valid copy, with a warning saying why", %{tmp_dir: tmp} do
      dir = copy(tmp, "m0-minimal-valid")
      cache = Path.join(tmp, "cache")
      point(dir, cache, save: true)
      break_roa(dir)

      %{point: point, entries: [manifest | entries]} = point(dir, cache, save: true)

      assert point.status == :fallback
      assert [%{rule: :hash_mismatch}] = point.failed
      assert manifest.valid

      assert [%{rule: :last_valid_copy, severity: :warning, message: message} | _] =
               manifest.problems

      assert message =~ "hash_mismatch"

      assert [%{uri: @key <> "/roa1.roa", valid: true}] = entries
      assert point.files["roa1.roa"] == Path.join(LastValid.load(cache, @manifest), "roa1.roa")
    end

    @tag rfc: ["9286#6.6", "9286#6.3"],
         doc: "At 2036-06-01 the saved manifest is past its nextUpdate (2036-01-01)."
    test "a last valid copy whose manifest is stale isn't used", %{tmp_dir: tmp} do
      dir = copy(tmp, "m0-minimal-valid")
      cache = Path.join(tmp, "cache")
      point(dir, cache, save: true)
      break_roa(dir)

      %{point: point, entries: [manifest]} = point(dir, cache, [], ~U[2036-06-01 00:00:00Z])

      assert point.status == :failed
      refute manifest.valid
      assert %{rule: :last_valid_copy_unusable, severity: :warning} = List.last(manifest.problems)
    end

    @tag rfc: "9286#6.6"
    test "a point that never validated has no fallback", %{tmp_dir: tmp} do
      dir = copy(tmp, "m0-minimal-valid")
      cache = Path.join(tmp, "cache")
      break_roa(dir)

      %{point: point} = point(dir, cache, save: true)
      assert point.status == :failed

      refute Enum.any?(
               point.problems,
               &(&1.rule in [:last_valid_copy, :last_valid_copy_unusable])
             )

      assert LastValid.load(cache, @manifest) == nil
    end

    @tag doc: "lumina validate reads the copies but never writes them (D-024's rule for state)."
    test "without :save nothing is kept", %{tmp_dir: tmp} do
      dir = copy(tmp, "m0-minimal-valid")
      cache = Path.join(tmp, "cache")

      assert %{point: %{status: :accepted}} = point(dir, cache, [])
      assert LastValid.load(cache, @manifest) == nil
    end
  end
end
