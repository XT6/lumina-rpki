defmodule Lumina.ManifestStateTest do
  @moduledoc """
  Tests manifest replay protection across runs (#136, D-024):
  `Lumina.ManifestState` and its use in `Lumina.Validate.point/5`.

  RFC 9286 §4.2.1 requires a new manifest to have a higher number and a
  more recent thisUpdate than the last one validated; RFC 9981 §2-3 resets
  the number check when the manifest's file name changes. Barry generates
  fresh keys for every fixture, so two fixtures never share a CA; instead,
  the record of "the last manifest validated" is written ahead of
  m0-minimal-valid's ca1 manifest (number 1, thisUpdate 2026-01-01),
  which then plays the replayed, older manifest.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, ManifestState, Validate}
  alias Lumina.Test.Fixture

  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]
  @key "rsync://localhost:8873/rpki/ca1"
  @manifest @key <> "/ca1.mft"

  setup %{tmp_dir: tmp} do
    dir = Path.join(tmp, "m0")
    File.cp_r!(Fixture.load!("m0-minimal-valid").rsync_root, dir)
    {:ok, ca} = Certificate.decode(File.read!(Path.join(dir, "ta/ca1.cer")))
    %{dir: dir, cache: Path.join(tmp, "cache"), ca: ca}
  end

  defp point(%{dir: dir, cache: cache, ca: ca}, opts \\ []),
    do: Validate.point(ca, Path.join(dir, "ca1"), @key, @now, [last_valid: cache] ++ opts).point

  # Records a manifest validated before, as a sync would have.
  defp prior(%{cache: cache, ca: ca}, uri, number, this_update) do
    :ok =
      ManifestState.record(cache, ca, %{
        status: :accepted,
        manifest: uri,
        number: number,
        this_update: this_update
      })
  end

  defp rules(point, severity),
    do: for(%{severity: ^severity, rule: rule} <- point.problems, do: rule)

  describe "recording" do
    @tag rfc: "9286#4.2.1"
    test "a sync records the accepted manifest; seeing the same one again is fine", ctx do
      assert ManifestState.load(ctx.cache, ctx.ca) == nil
      assert point(ctx, save: true).status == :accepted

      assert ManifestState.load(ctx.cache, ctx.ca) ==
               %{manifest: @manifest, number: 1, this_update: ~U[2026-01-01 00:00:00Z]}

      point = point(ctx, save: true)
      assert point.status == :accepted
      assert rules(point, :error) == []
    end

    @tag doc: "Numbers up to 20 octets survive the JSON record."
    test "a 20-octet manifest number round-trips", ctx do
      big = Integer.pow(2, 159) - 1
      prior(ctx, @manifest, big, ~U[2026-01-01 00:00:00Z])
      assert %{number: ^big} = ManifestState.load(ctx.cache, ctx.ca)
    end

    @tag doc: "lumina validate (no :save) and a fallback point never move the record (D-024)."
    test "only an accepted point with :save is recorded", ctx do
      assert point(ctx).status == :accepted
      assert ManifestState.load(ctx.cache, ctx.ca) == nil
    end
  end

  describe "replays (RFC 9286 §4.2.1)" do
    @tag rfc: "9286#4.2.1"
    test "a manifest number lower than the last one validated fails the point", ctx do
      prior(ctx, @manifest, 2, ~U[2025-06-01 00:00:00Z])

      point = point(ctx)
      assert point.status == :failed
      assert rules(point, :error) == [:manifest_number_replay]
    end

    @tag rfc: "9286#4.2.1", doc: "Same number, another thisUpdate: a different manifest."
    test "an equal manifest number on a different manifest fails the point", ctx do
      prior(ctx, @manifest, 1, ~U[2025-12-01 00:00:00Z])
      assert rules(point(ctx), :error) == [:manifest_number_replay]
    end

    @tag rfc: "9286#4.2.1"
    test "a higher number with an older thisUpdate fails the point", ctx do
      prior(ctx, @manifest, 0, ~U[2027-01-01 00:00:00Z])
      assert rules(point(ctx), :error) == [:manifest_this_update_replay]
    end

    @tag rfc: ["9286#4.2.1", "9286#6.6"],
         doc:
           "The replayed manifest is a failed fetch, so the copy the sync kept stands in (D-023)."
    test "a replayed manifest falls back to the last valid copy, and the record stays", ctx do
      assert point(ctx, save: true).status == :accepted
      prior(ctx, @manifest, 2, ~U[2025-06-01 00:00:00Z])

      point = point(ctx, save: true)
      assert point.status == :fallback
      assert [%{rule: :manifest_number_replay}] = point.failed
      assert %{number: 2} = ManifestState.load(ctx.cache, ctx.ca)
    end
  end

  describe "file name changes (RFC 9981)" do
    @tag rfc: ["9981#2", "9981#3"],
         doc: "The number check is reset; operators are alerted with a warning."
    test "a new manifest file name skips the number check, with a warning", ctx do
      prior(ctx, @key <> "/old.mft", 9, ~U[2025-01-01 00:00:00Z])

      point = point(ctx)
      assert point.status == :accepted
      assert rules(point, :warning) |> Enum.member?(:manifest_name_changed)
      assert rules(point, :error) == []
    end

    @tag rfc: ["9981#2", "9286#4.2.1"],
         doc: "RFC 9981 §2: with the number check reset, the thisUpdate check still protects."
    test "a new manifest file name with an older thisUpdate still fails", ctx do
      prior(ctx, @key <> "/old.mft", 0, ~U[2027-01-01 00:00:00Z])

      point = point(ctx)
      assert point.status == :failed
      assert rules(point, :error) == [:manifest_this_update_replay]
      assert :manifest_name_changed in rules(point, :warning)
    end
  end
end
