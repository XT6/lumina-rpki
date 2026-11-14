defmodule Lumina.PublicationPointTest do
  @moduledoc """
  Tests publication point processing (#133): `Lumina.PublicationPoint.process/4`
  decides from a fixture's files whether a CA's publication point can be
  used (RFC 9286 §6, RFC 9981 §4).

  A point is ca1's (`rsync/ca1`, caRepository
  `rsync://localhost:8873/rpki/ca1`) unless a test says otherwise, at
  2030-01-01, inside the fixtures' validity. Every positive fixture's
  points must be accepted with exactly the manifest's files, and each
  `m5-pp-*` fixture must fail with exactly its reasons. Cases Barry can't
  publish (a missing or undecodable manifest, an extra file) work on a
  copy of m0-minimal-valid changed on disk.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, Manifest, PublicationPoint}
  alias Lumina.Test.Fixture
  alias Mix.Lumina.Fixtures

  @moduletag :tmp_dir
  @now ~U[2030-01-01 00:00:00Z]
  @key "rsync://localhost:8873/rpki/ca1"

  defp root(id), do: Fixture.load!(id).rsync_root

  defp certificate(path) do
    {:ok, cert} = Certificate.decode(File.read!(path))
    cert
  end

  defp process(root, ca \\ "ta/ca1.cer", dir \\ "ca1", key \\ @key),
    do:
      PublicationPoint.process(certificate(Path.join(root, ca)), Path.join(root, dir), key, @now)

  defp errors(result), do: for(%{severity: :error, rule: rule} <- result.problems, do: rule)

  # A writable copy of a fixture's rsync tree.
  defp copy(tmp, id) do
    dir = Path.join(tmp, id)
    File.cp_r!(root(id), dir)
    dir
  end

  describe "fixtures" do
    @tag rfc: ["9286#6", "9286#6.2", "9286#6.3", "9286#6.4", "9286#6.5"],
         doc: "The TA's point and ca1's (where it exists); warnings are allowed."
    test "every positive Barry fixture's publication points are accepted with exactly the manifest's files" do
      for dir <- Fixtures.case_dirs(),
          id = Path.basename(dir),
          Fixture.load!(id).expected == :valid,
          {ca, point, key} <- [
            {"ta.cer", "ta", "rsync://localhost:8873/rpki/ta"},
            {"ta/ca1.cer", "ca1", @key}
          ],
          File.dir?(Path.join(root(id), point)) do
        result = process(root(id), ca, point, key)

        assert result.status == :accepted, "#{id} #{point}: #{inspect(result.problems)}"

        {:ok, manifest} =
          Manifest.decode(File.read!(Path.join([root(id), point, "#{point}.mft"])))

        assert Map.keys(result.files) |> Enum.sort() == Enum.sort(Manifest.names(manifest))
        assert result.manifest == "#{key}/#{point}.mft"
      end
    end

    @tag rfc: ["9286#6.3", "9286#6.6"]
    test "m5-pp-manifest-stale: a manifest past its nextUpdate fails the point" do
      result = process(root("m5-pp-manifest-stale"))
      assert {result.status, errors(result)} == {:failed, [:manifest_stale]}
      assert result.files == %{}
    end

    @tag rfc: ["9286#6.3", "9286#6.6"]
    test "m5-pp-manifest-premature: a manifest before its thisUpdate fails the point" do
      result = process(root("m5-pp-manifest-premature"))
      assert {result.status, errors(result)} == {:failed, [:manifest_premature]}
    end

    @tag rfc: ["9286#6.4", "9286#6.6"]
    test "m5-pp-file-missing: a listed file that isn't published fails the point" do
      result = process(root("m5-pp-file-missing"))
      assert {result.status, errors(result)} == {:failed, [:file_missing]}

      assert [%{message: "roa2.roa is listed but not published"}] =
               result.problems -- warnings(result)
    end

    @tag rfc: ["9286#6.5", "9286#6.6"]
    test "m5-pp-hash-mismatch: a file whose hash differs from the manifest's fails the point" do
      result = process(root("m5-pp-hash-mismatch"))
      assert {result.status, errors(result)} == {:failed, [:hash_mismatch]}
    end

    @tag rfc: ["9286#6", "9286#6.4"]
    test "m5-pp-crl-renamed: the CA's CRL not on the manifest, and a listed file missing, fail the point" do
      result = process(root("m5-pp-crl-renamed"))

      assert {result.status, Enum.sort(errors(result))} ==
               {:failed, [:crl_not_listed, :file_missing]}
    end

    @tag rfc: ["9286#6", "9829#3.2"],
         doc: """
         With ca2.crl published, the CRL rule stays: the CRL the CRLDP names
         (ca1.crl) isn't listed. The hash mismatch is Barry's: it writes an
         empty hash for a renamed entry (doc/barry.md).
         """
    test "the CRL the manifest's EE certificate names must be on the manifest", %{tmp_dir: tmp} do
      dir = copy(tmp, "m5-pp-crl-renamed")
      File.cp!(Path.join(dir, "ca1/ca1.crl"), Path.join(dir, "ca1/ca2.crl"))

      result = process(dir)

      assert {result.status, Enum.sort(errors(result))} ==
               {:failed, [:crl_not_listed, :hash_mismatch]}

      assert Enum.any?(result.problems, &(&1.message == "the CRL ca1.crl is not on the manifest"))

      assert Enum.any?(
               result.problems,
               &(&1.message == "the hash of ca2.crl doesn't match the manifest")
             )
    end

    @tag rfc: ["9286#6", "9286#6.2", "6488#3"]
    test "m5-pp-manifest-revoked: a manifest whose EE certificate is revoked fails the point" do
      result = process(root("m5-pp-manifest-revoked"))
      assert {result.status, errors(result)} == {:failed, [:revoked]}
    end

    @tag rfc: ["9981#4", "9286#6.6"]
    test "m5-pp-manifest-sia-mismatch: a manifest whose signedObject URI isn't its own fails the point" do
      result = process(root("m5-pp-manifest-sia-mismatch"))
      assert {result.status, errors(result)} == {:failed, [:manifest_uri_mismatch]}
    end

    @tag rfc: ["9286#6.2", "9286#4.4"],
         doc: "An invalid manifest is treated as though no manifest were present (§4.4)."
    test "m5-mft-version-1: an invalid manifest fails the point with the manifest's own rule" do
      result = process(root("m5-mft-version-1"))
      assert {result.status, errors(result)} == {:failed, [:manifest_version]}
    end

    @tag rfc: ["9286#6.2", "6487#7.2"],
         doc: "The manifest's EE certificate can't validate without a valid CRL."
    test "m4-crl-version-1: an invalid CRL fails the point" do
      result = process(root("m4-crl-version-1"))
      assert {result.status, errors(result)} == {:failed, [:crl_invalid]}
    end

    @tag rfc: "9286#6", doc: "D-016: a stale CRL on a current manifest only warns."
    test "m4-crl-stale: a stale CRL is accepted with a warning" do
      result = process(root("m4-crl-stale"))
      assert result.status == :accepted
      assert :stale_crl in Enum.map(result.problems, & &1.rule)
    end
  end

  describe "on disk" do
    @tag rfc: "9286#6.2"
    test "a missing manifest fails the point", %{tmp_dir: tmp} do
      dir = copy(tmp, "m0-minimal-valid")
      File.rm!(Path.join(dir, "ca1/ca1.mft"))

      result = process(dir)
      assert {result.status, errors(result)} == {:failed, [:manifest_missing]}
      assert result.manifest == @key <> "/ca1.mft"
    end

    @tag rfc: "9286#6.2"
    test "a manifest that doesn't decode fails the point", %{tmp_dir: tmp} do
      dir = copy(tmp, "m0-minimal-valid")
      File.write!(Path.join(dir, "ca1/ca1.mft"), "not DER")

      result = process(dir)
      assert {result.status, errors(result)} == {:failed, [:manifest_decode]}
    end

    @tag rfc: "9286#6.1",
         doc: "The CA's caRepository is taken to be elsewhere, so its manifest URI is outside it."
    test "a manifest outside the CA's publication point fails it" do
      result =
        process(
          root("m0-minimal-valid"),
          "ta/ca1.cer",
          "ca1",
          "rsync://localhost:8873/rpki/other"
        )

      assert {result.status, errors(result)} == {:failed, [:manifest_outside]}
    end

    @tag rfc: "9286#6",
         doc: "Files not on the manifest \"MUST NOT be used\": they aren't in the result."
    test "a file not on the manifest is left out of an accepted point", %{tmp_dir: tmp} do
      dir = copy(tmp, "m0-minimal-valid")
      File.cp!(Path.join(dir, "ca1/roa1.roa"), Path.join(dir, "ca1/extra.roa"))

      result = process(dir)
      assert result.status == :accepted
      refute Map.has_key?(result.files, "extra.roa")
      assert result.unlisted == ["extra.roa"]
      assert result.files["roa1.roa"] == Path.join(dir, "ca1/roa1.roa")
    end
  end

  describe "read_crl/3" do
    @tag rfc: "6487#7.2", doc: "D-015: only the publication point's own CRL is read."
    test "reads the CRL a URI names in the point, and nothing outside it" do
      root = root("m0-minimal-valid")

      assert %Lumina.CRL{} =
               PublicationPoint.read_crl(@key <> "/ca1.crl", Path.join(root, "ca1"), @key)

      assert PublicationPoint.read_crl(
               "rsync://localhost:8873/rpki/ta/ta.crl",
               Path.join(root, "ca1"),
               @key
             ) ==
               nil

      assert PublicationPoint.read_crl(@key <> "/roa1.roa", Path.join(root, "ca1"), @key) == nil
      assert PublicationPoint.read_crl(nil, Path.join(root, "ca1"), @key) == nil
    end
  end

  defp warnings(result), do: Enum.filter(result.problems, &(&1.severity == :warning))
end
