defmodule Lumina.ManifestCheckTest do
  @moduledoc """
  Tests the manifest content checks (#132): `Lumina.Manifest.check/1`
  against RFC 9286 §4.2.1, §4.2.2 and §4.4. An invalid manifest is
  treated as though no manifest were present (§4.4), which makes its
  publication point fail (#133), so a false positive here would throw
  away a whole publication point.

  Every manifest of the positive fixtures must pass, and each `m5-mft-*`
  fixture must fail with exactly its one rule. The edge cases (boundaries,
  case sensitivity, registered extensions) are tested on a decoded
  m0-minimal-valid manifest changed in memory.
  """
  use ExUnit.Case, async: true

  alias Lumina.Manifest
  alias Lumina.Test.Fixture
  alias Mix.Lumina.Fixtures

  defp manifest(id \\ "m0-minimal-valid") do
    {:ok, manifest} =
      Manifest.decode(File.read!(Path.join(Fixture.load!(id).rsync_root, "ca1/ca1.mft")))

    manifest
  end

  defp rules(manifest), do: Enum.map(Manifest.check(manifest), & &1.rule)

  defp named(names),
    do: %{manifest() | files: for(name <- names, do: %{name: name, hash: <<0::256>>})}

  defp at(iso) do
    {:ok, time, 0} = DateTime.from_iso8601(iso)
    %{at: time, format: :generalized_time, raw: Calendar.strftime(time, "%Y%m%d%H%M%SZ")}
  end

  # m0-minimal-valid's ca1.mft eContent, re-encoded with `changes`: a
  # hand-built object, for what Barry can't write (doc/barry.md).
  defp reencoded(changes) do
    {:ok, value} = Lumina.ASN1.decode(:manifest, :Manifest, manifest().object.econtent)
    {:ok, der} = Lumina.ASN1.encode(:manifest, :Manifest, Map.merge(value, changes))
    der
  end

  describe "fixtures" do
    @tag rfc: ["9286#4.2.1", "9286#4.2.2", "9286#4.4"]
    test "every manifest of the positive Barry fixtures passes" do
      for dir <- Fixtures.case_dirs(),
          Fixture.load!(Path.basename(dir)).expected == :valid,
          path <- Path.wildcard(Path.join(dir, "rsync/**/*.mft")) do
        {:ok, manifest} = Manifest.decode(File.read!(path))
        assert Manifest.check(manifest) == [], path
      end
    end

    @tag rfc: ["9286#4.2.1", "9286#4.4"]
    test "m5-mft-version-1: a manifest version other than 0 is rejected" do
      assert rules(manifest("m5-mft-version-1")) == [:manifest_version]
    end

    @tag rfc: "9286#4.4"
    test "m5-mft-dates-reversed: thisUpdate after nextUpdate is rejected" do
      assert rules(manifest("m5-mft-dates-reversed")) == [:manifest_dates]
    end

    @tag rfc: "9286#4.2.1"
    test "m5-mft-number-too-large: a manifest number of 21 octets is rejected" do
      assert rules(manifest("m5-mft-number-too-large")) == [:manifest_number_range]
    end

    @tag rfc: ["9286#4.2.1", "7935#2"]
    test "m5-mft-hash-sha1: a file hash algorithm other than SHA-256 is rejected" do
      assert rules(manifest("m5-mft-hash-sha1")) == [:manifest_hash_algorithm]
    end

    @tag rfc: "9286#4.2.2"
    test "m5-mft-name-bad-character: a file name with a character outside a-z A-Z 0-9 - _ is rejected" do
      assert rules(manifest("m5-mft-name-bad-character")) == [:manifest_file_name]
    end

    @tag rfc: ["9286#4.2.2", "6481#7.2"]
    test "m5-mft-name-unregistered-extension: an extension outside the IANA registry is rejected" do
      assert rules(manifest("m5-mft-name-unregistered-extension")) == [:manifest_file_extension]
    end

    @tag rfc: ["9286#4.2.1", "9286#4.2.2"]
    test "m5-mft-name-duplicate: a file name listed twice is rejected" do
      assert rules(manifest("m5-mft-name-duplicate")) == [:manifest_duplicate_name]
    end
  end

  describe "empty file list (#37)" do
    @tag rfc: "9286#7",
         doc: """
         Verified erratum 7118 corrects the module's SIZE (0..MAX) to
         SIZE (1..MAX). The module is kept as published (F-001), so the
         manifest decodes, as a file and as a repository object.
         """
    test "m5-mft-empty-file-list decodes but is rejected as empty" do
      path =
        Path.join(Fixture.load!("m5-mft-empty-file-list").rsync_root, "ca1/ca1.mft")

      assert {:ok, %Lumina.Object{type: :manifest, value: %Manifest{files: []}}} =
               Lumina.Object.decode_file(path)

      assert [%{rule: :manifest_empty, rfc: "9286#7", field: :file_list, message: message}] =
               Manifest.check(manifest("m5-mft-empty-file-list"))

      assert message == "manifest has no entries (RFC 9286 section 7, erratum 7118)"
    end

    @tag rfc: "9286#7", doc: "Erratum 7118: SIZE (1..MAX), so one entry is enough."
    test "a manifest listing a single file is not empty" do
      assert rules(named(["a.roa"])) == []
      assert rules(named([])) == [:manifest_empty]
    end
  end

  describe "time formats (#48)" do
    @tag rfc: ["9286#4.2.1", "5280#4.1.2.5.2"],
         doc: """
         F-019: RFC 9286 §4.2.1 imports the CRL field's constraints; for a
         GeneralizedTime field that means RFC 5280 §4.1.2.5.2, which forbids
         fractional seconds although DER allows them. Barry can't write a
         fraction, so the manifest is m0-minimal-valid's re-encoded.
         """
    test "a fractional-second thisUpdate decodes but is rejected" do
      der = reencoded(%{thisUpdate: ~c"20260101000000.5Z"})

      assert {:ok, manifest} = Manifest.decode_econtent(der)
      assert manifest.this_update.raw == "20260101000000.5Z"

      assert [%{rule: :manifest_time_format, rfc: "9286#4.2.1", field: :this_update} = problem] =
               Manifest.check(manifest)

      assert problem.message ==
               "thisUpdate 20260101000000.5Z is not YYYYMMDDHHMMSSZ: GeneralizedTime with " <>
                 "seconds and no fractional seconds (RFC 5280 section 4.1.2.5.2, F-019)"
    end

    @tag rfc: ["9286#4.2.1", "5280#4.1.2.5.2"]
    test "a fractional-second nextUpdate is rejected" do
      {:ok, manifest} = Manifest.decode_econtent(reencoded(%{nextUpdate: ~c"20360101000000.25Z"}))
      assert [%{rule: :manifest_time_format, field: :next_update}] = Manifest.check(manifest)
    end

    @tag rfc: ["9286#4.2.1", "5280#5.1.2.4"],
         doc: """
         F-019: RFC 5280 §5.1.2.4 wants a CRL's thisUpdate as UTCTime through
         2049; a manifest's can only be GeneralizedTime, so that rule isn't
         applied.
         """
    test "a GeneralizedTime dated before 2050 is not rejected" do
      {:ok, manifest} =
        Manifest.decode_econtent(
          reencoded(%{thisUpdate: ~c"20490101000000Z", nextUpdate: ~c"20490102000000Z"})
        )

      assert manifest.this_update.at.year == 2049
      assert rules(manifest) == []
    end
  end

  describe "dates and numbers" do
    @tag rfc: "9286#4.4", doc: "\"thisUpdate precedes nextUpdate\": equal times don't."
    test "thisUpdate equal to nextUpdate is rejected" do
      time = at("2030-01-01T00:00:00Z")
      assert rules(%{manifest() | this_update: time, next_update: time}) == [:manifest_dates]
    end

    @tag rfc: "9286#4.2.1",
         doc: "20 octets hold 0..2^159-1 as a DER INTEGER, the CRLNumber range §4.2.1 points to."
    test "manifest numbers 0 and 2^159-1 pass; -1 and 2^159 are rejected" do
      assert rules(%{manifest() | number: 0}) == []
      assert rules(%{manifest() | number: Integer.pow(2, 159) - 1}) == []
      assert rules(%{manifest() | number: -1}) == [:manifest_number_range]
      assert rules(%{manifest() | number: Integer.pow(2, 159)}) == [:manifest_number_range]
    end
  end

  describe "file names" do
    @tag rfc: ["9286#4.2.2", "6481#7.2"],
         doc: """
         F-032: the IANA registry as of 2026-11-14, temporary (.asa, .cdr)
         and deprecated (.gbr) entries included. LACNIC's manifests list
         .asa files.
         """
    test "every extension in the IANA registry is accepted" do
      names = for ext <- ~w(asa ccr cdr cer crl gbr mft roa sig tak), do: "a-B_9." <> ext
      assert rules(named(names)) == []
    end

    @tag rfc: "9286#4.2.2",
         doc:
           "Case-sensitive (§4.2.2): .ROA is not a registered extension, and A.roa is not a.roa."
    test "names are case-sensitive" do
      assert rules(named(["a.ROA"])) == [:manifest_file_extension]
      assert rules(named(["A.roa", "a.roa"])) == []
    end

    @tag rfc: "9286#4.2.2"
    test "names without a base, with two dots, a path, or a long extension are rejected" do
      for name <- [".roa", "a.b.roa", "ca1/a.roa", "a.roas", "a.ro", "a roa.roa", "a"] do
        assert rules(named([name])) == [:manifest_file_name], name
      end
    end

    @tag rfc: "9286#4.2.1"
    test "a name listed three times is one problem" do
      assert [%{rule: :manifest_duplicate_name, message: message}] =
               Manifest.check(named(["a.roa", "a.roa", "a.roa"]))

      assert message =~ "3 times"
    end
  end
end
