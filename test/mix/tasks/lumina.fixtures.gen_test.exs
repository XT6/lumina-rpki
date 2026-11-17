defmodule Mix.Tasks.Lumina.Fixtures.GenTest do
  @moduledoc """
  Tests fixture generation with the real Barry binary: output layout,
  removal of stale files, the fixed validity period, that regenerating
  gives the same file list and check result, the RRDP session made from
  the fixture's id (Barry's default isn't a UUID, F-038), and fixtures
  with several versions and the deltas between them (#202). Tagged :barry, so it is
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
    expected: :valid,
    vrps: []
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

  describe "RRDP (#202)" do
    @tag rfc: "8182#3.5.1.3"
    test "the notification and snapshot carry the session made from the fixture's id, run after run",
         %{tmp_dir: tmp_dir} do
      case_dir = make_case(tmp_dir, "ta.cer\n\troa.roa\n")
      session = Fixtures.session_id("m0-gen-sample")

      for _run <- 1..2 do
        Gen.generate!(case_dir, Gen.barry_path())

        for file <- ["notification.xml", "snapshot.xml"] do
          assert File.read!(Path.join([case_dir, "rrdp", file])) =~ ~s(session_id="#{session}")
        end
      end

      refute File.exists?(Path.join(case_dir, ".gen"))
    end

    test "a descriptor with its own notification section is refused", %{tmp_dir: tmp_dir} do
      case_dir =
        make_case(
          tmp_dir,
          "ta.cer\n\n[notification: https://localhost:8443/rrdp/notification.xml]\n"
        )

      assert_raise Mix.Error, ~r/declares a \[notification: \.\.\.\] section/, fn ->
        Gen.generate!(case_dir, Gen.barry_path())
      end
    end

    @tag rfc: "8182#3.5.3.3",
         doc: """
         case.v2.repo keeps the TA, its CA and one ROA (shield marker) and
         replaces the other ROA. Serial 1's notification and snapshot, the
         delta, and serial 2's chained notification are written; rsync/
         holds version 2.
         """
    test "a fixture with case.v2.repo gets a snapshot per serial and the delta between them",
         %{tmp_dir: tmp_dir} do
      shield = "\u{1F6E1}\u{FE0F}"
      case_dir = make_case(tmp_dir, "ta.cer\n\tca1.cer\n\t\troa1.roa\n\t\troa2.roa\n")

      File.write!(
        Path.join(case_dir, "case.v2.repo"),
        "ta.cer #{shield}\n\tca1.cer #{shield}\n\t\troa1.roa #{shield}\n\t\troa3.roa\n" <>
          "\t\tca1.mft\n\t\tca1.crl #{shield}\n\tta.mft #{shield}\n\tta.crl #{shield}\n"
      )

      File.write!(
        Path.join(case_dir, "case.exs"),
        String.replace(@meta, "vrps: []", ~s(vrps: [], rrdp_versions: %{1 => "a", 2 => "b"}))
      )

      assert :ok = Gen.generate!(case_dir, Gen.barry_path())

      assert case_dir |> Path.join("rrdp") |> File.ls!() |> Enum.sort() == [
               "delta-2.xml",
               "notification-1.xml",
               "notification.xml",
               "snapshot-1.xml",
               "snapshot.xml",
               "ta.cer"
             ]

      notification = File.read!(Path.join([case_dir, "rrdp", "notification.xml"]))
      assert notification =~ ~s(serial="2")
      assert notification =~ "https://localhost:8443/rrdp/delta-2.xml"
      assert File.read!(Path.join([case_dir, "rrdp", "notification-1.xml"])) =~ "snapshot-1.xml"
      assert "rsync/ca1/roa3.roa" in files(case_dir)
      refute "rsync/ca1/roa2.roa" in files(case_dir)
      assert {:ok, _} = Fixtures.load(case_dir)
      refute File.exists?(Path.join(case_dir, ".gen"))
    end
  end
end
