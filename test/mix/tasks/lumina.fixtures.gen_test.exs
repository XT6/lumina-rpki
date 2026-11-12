defmodule Mix.Tasks.Lumina.Fixtures.GenTest do
  @moduledoc """
  Tests fixture generation with the real Barry binary: output layout,
  removal of stale files, the fixed validity period, and that regenerating
  gives the same file list and check result. Tagged :barry, so it is
  excluded unless Barry is installed; CI runs it in the barry job.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.Fixtures
  alias Mix.Tasks.Lumina.Fixtures.Gen

  @moduletag :barry
  @moduletag :tmp_dir

  @meta """
  %{
    id: "m0-gen-sample",
    title: "Generator sample",
    milestone: "M0",
    rationale: "Exercises the generator.",
    rfc: ["6487#4"],
    expected: :valid
  }
  """

  defp make_case(tmp_dir, descriptor) do
    case_dir = Path.join(tmp_dir, "m0-gen-sample")
    File.mkdir_p!(case_dir)
    File.write!(Path.join(case_dir, "case.exs"), @meta)
    File.write!(Path.join(case_dir, "case.repo"), descriptor)
    case_dir
  end

  defp files(case_dir) do
    ["case.tal", "rsync/**/*"]
    |> Enum.flat_map(&Path.wildcard(Path.join(case_dir, &1)))
    |> Enum.filter(&File.regular?/1)
    |> Enum.map(&Path.relative_to(&1, case_dir))
    |> Enum.sort()
  end

  test "generates the TAL and rsync tree, and the fixture passes its check", %{tmp_dir: tmp_dir} do
    case_dir = make_case(tmp_dir, "ta.cer\n\tca1.cer\n\t\troa1.roa\n")

    assert :ok = Gen.generate!(case_dir, Gen.barry_path())

    assert files(case_dir) == [
             "case.tal",
             "rsync/ca1/ca1.crl",
             "rsync/ca1/ca1.mft",
             "rsync/ca1/roa1.roa",
             "rsync/ta.cer",
             "rsync/ta/ca1.cer",
             "rsync/ta/ta.crl",
             "rsync/ta/ta.mft"
           ]

    assert {:ok, _} = Fixtures.load(case_dir)
  end

  test "regenerating gives the same files and the same check result", %{tmp_dir: tmp_dir} do
    case_dir = make_case(tmp_dir, "ta.cer\n\troa.roa\n")

    Gen.generate!(case_dir, Gen.barry_path())
    first = {files(case_dir), Fixtures.load(case_dir) |> elem(0)}
    ta_cert = File.read!(Path.join([case_dir, "rsync", "ta.cer"]))

    Gen.generate!(case_dir, Gen.barry_path())
    assert {files(case_dir), Fixtures.load(case_dir) |> elem(0)} == first

    # Fresh keys on every run, so the bytes differ.
    refute File.read!(Path.join([case_dir, "rsync", "ta.cer"])) == ta_cert
  end

  test "removes output that the descriptor no longer produces", %{tmp_dir: tmp_dir} do
    case_dir = make_case(tmp_dir, "ta.cer\n\troa.roa\n")
    Gen.generate!(case_dir, Gen.barry_path())
    assert "rsync/ta/roa.roa" in files(case_dir)

    File.write!(Path.join(case_dir, "case.repo"), "ta.cer\n")
    Gen.generate!(case_dir, Gen.barry_path())
    refute "rsync/ta/roa.roa" in files(case_dir)
  end

  test "uses the fixed validity period, so fixtures don't expire", %{tmp_dir: tmp_dir} do
    case_dir = make_case(tmp_dir, "ta.cer\n")
    Gen.generate!(case_dir, Gen.barry_path())

    # The TA certificate's Validity: UTCTime 260101000000Z and
    # GeneralizedTime 20360101000000Z (X.690 encodings of the defaults).
    ta_cert = File.read!(Path.join([case_dir, "rsync", "ta.cer"]))
    assert :binary.match(ta_cert, "260101000000Z") != :nomatch
    assert :binary.match(ta_cert, "360101000000Z") != :nomatch
  end
end
