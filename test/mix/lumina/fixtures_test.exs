defmodule Mix.Lumina.FixturesTest do
  @moduledoc """
  Tests the fixture metadata check: every way a fixture can be incomplete
  or wrong must be reported, and case.exs must be read as data without
  running any code in it. Fixtures are built in temporary directories.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.{Fixtures, RFC}

  @moduletag :tmp_dir
  @library RFC.load_library("doc/rfc")

  @complete """
  %{
    id: "m4-sample-case",
    title: "Sample case",
    milestone: "M4",
    rationale: \"""
    Exists to exercise the metadata check.
    \""",
    rfc: ["6487#4.8.9"],
    expected: {:invalid, [%{object: "ta.cer", reason: "sample reason"}]}
  }
  """

  # Writes a fixture folder. `meta` is the case.exs source; `files` lists
  # which other files to create.
  defp make_case(tmp_dir, meta, opts \\ []) do
    id = Keyword.get(opts, :id, "m4-sample-case")
    files = Keyword.get(opts, :files, [:repo, :tal, :rsync])
    case_dir = Path.join(tmp_dir, id)
    File.mkdir_p!(case_dir)
    if meta, do: File.write!(Path.join(case_dir, "case.exs"), meta)
    if :repo in files, do: File.write!(Path.join(case_dir, "case.repo"), "ta.cer\n")

    if :tal in files,
      do: File.write!(Path.join(case_dir, "case.tal"), "rsync://localhost/ta.cer\n")

    if :rsync in files do
      File.mkdir_p!(Path.join(case_dir, "rsync"))
      File.write!(Path.join([case_dir, "rsync", "ta.cer"]), "not a real certificate")
    end

    case_dir
  end

  defp messages(case_dir) do
    {:error, problems} = Fixtures.load(case_dir, @library)
    Enum.map(problems, & &1.message)
  end

  defp edit(source, from, to) do
    replaced = String.replace(source, from, to)
    refute replaced == source, "edit did not apply: #{inspect(from)}"
    replaced
  end

  test "a complete fixture passes", %{tmp_dir: tmp_dir} do
    case_dir = make_case(tmp_dir, @complete)

    assert {:ok, fixture} = Fixtures.load(case_dir, @library)
    assert fixture.id == "m4-sample-case"
    assert fixture.dir == case_dir
    assert fixture.rationale =~ "metadata check"
    assert fixture.expected == {:invalid, [%{object: "ta.cer", reason: "sample reason"}]}
  end

  test "a valid fixture with Barry overrides passes", %{tmp_dir: tmp_dir} do
    meta =
      @complete
      |> edit(
        ~s/expected: {:invalid, [%{object: "ta.cer", reason: "sample reason"}]}/,
        "expected: :valid"
      )
      |> edit(
        ~s/rfc: ["6487#4.8.9"],/,
        ~s/rfc: ["6487#4.8.9"],\n  barry: [now: "2020-01-01T00:00:00Z"],/
      )

    assert {:ok, fixture} = Fixtures.load(make_case(tmp_dir, meta), @library)

    assert Fixtures.barry_opts(fixture) == [
             later: "2036-01-01T00:00:00Z",
             now: "2020-01-01T00:00:00Z"
           ]
  end

  describe "required metadata" do
    test "a missing rationale fails", %{tmp_dir: tmp_dir} do
      meta =
        edit(
          @complete,
          ~s/  rationale: \"""\n  Exists to exercise the metadata check.\n  \""",\n/,
          ""
        )

      assert "missing required key :rationale" in messages(make_case(tmp_dir, meta))
    end

    test "a blank rationale fails", %{tmp_dir: tmp_dir} do
      meta = edit(@complete, "Exists to exercise the metadata check.", "   ")
      assert "rationale must be a non-blank string" in messages(make_case(tmp_dir, meta))
    end

    test "a missing RFC reference fails", %{tmp_dir: tmp_dir} do
      meta = edit(@complete, ~s/  rfc: ["6487#4.8.9"],\n/, "")
      assert "missing required key :rfc" in messages(make_case(tmp_dir, meta))
    end

    test "an empty RFC list fails", %{tmp_dir: tmp_dir} do
      meta = edit(@complete, ~s/["6487#4.8.9"]/, "[]")
      assert [message] = messages(make_case(tmp_dir, meta))
      assert message =~ "rfc must be a non-empty list"
    end

    test "an invalid RFC reference fails", %{tmp_dir: tmp_dir} do
      meta = edit(@complete, "6487#4.8.9", "6487#4.8.99")

      assert ["rfc: \"6487#4.8.99\": RFC 6487 has no section 4.8.99"] =
               messages(make_case(tmp_dir, meta))
    end

    test "a missing expected outcome fails", %{tmp_dir: tmp_dir} do
      meta =
        edit(
          @complete,
          ~s/  expected: {:invalid, [%{object: "ta.cer", reason: "sample reason"}]}\n/,
          ""
        )

      assert "missing required key :expected" in messages(make_case(tmp_dir, meta))
    end

    test "a malformed expected outcome fails", %{tmp_dir: tmp_dir} do
      for {bad, fragment} <- [
            {":invalid", "expected must be :valid or {:invalid"},
            {"{:invalid, []}", "expected must be :valid or {:invalid"},
            {~s/{:invalid, [%{object: "ta.cer"}]}/, "expected reject 1 must be"},
            {~s/{:invalid, [%{object: "ta.cer", reason: " "}]}/,
             "reason must be a non-blank string"},
            {~s/{:invalid, [%{object: "ta.cer", reason: "r", rule: "expired"}]}/,
             "rule must be an atom"},
            {~s/{:invalid, [%{object: "ta.cer", reason: "r", extra: :x}]}/,
             "expected reject 1 must be"}
          ] do
        meta =
          edit(@complete, ~s/{:invalid, [%{object: "ta.cer", reason: "sample reason"}]}/, bad)

        case_dir = make_case(tmp_dir, meta)

        assert Enum.any?(messages(case_dir), &(&1 =~ fragment)),
               "#{bad} should fail with #{fragment}"

        File.rm_rf!(case_dir)
      end
    end

    @tag doc: "The rule names the verdict the M4 done test checks (#115)."
    test "a reject may name the rule that rejects it", %{tmp_dir: tmp_dir} do
      meta =
        edit(
          @complete,
          ~s/reason: "sample reason"}/,
          ~s/reason: "sample reason", rule: :expired}/
        )

      assert {:ok, %{expected: {:invalid, [%{rule: :expired}]}}} =
               Fixtures.load(make_case(tmp_dir, meta), @library)
    end

    test "a rejected object that isn't in the rsync tree fails", %{tmp_dir: tmp_dir} do
      meta = edit(@complete, ~s/object: "ta.cer"/, ~s/object: "ta\/missing.roa"/)

      assert ["expected reject object \"ta/missing.roa\" is not in rsync/"] =
               messages(make_case(tmp_dir, meta))
    end

    test "an id that doesn't match the folder fails", %{tmp_dir: tmp_dir} do
      case_dir = make_case(tmp_dir, @complete, id: "m4-other-name")
      assert [message] = messages(case_dir)
      assert message =~ "must match the folder name \"m4-other-name\""
    end

    test "an id that doesn't start with the milestone fails", %{tmp_dir: tmp_dir} do
      meta = edit(@complete, ~s/milestone: "M4"/, ~s/milestone: "M5"/)

      assert ["id \"m4-sample-case\" must start with \"m5-\""] =
               messages(make_case(tmp_dir, meta))
    end

    test "an unknown milestone fails", %{tmp_dir: tmp_dir} do
      meta = edit(@complete, ~s/milestone: "M4"/, ~s/milestone: "Backlog"/)
      assert [message] = messages(make_case(tmp_dir, meta))
      assert message =~ "milestone must be one of M0..M9"
    end

    test "an unknown key fails", %{tmp_dir: tmp_dir} do
      meta = edit(@complete, "  title:", "  owner: \"someone\",\n  title:")
      assert ["unknown key :owner"] = messages(make_case(tmp_dir, meta))
    end

    test "bad Barry options fail", %{tmp_dir: tmp_dir} do
      meta =
        edit(
          @complete,
          ~s/rfc: ["6487#4.8.9"],/,
          ~s/rfc: ["6487#4.8.9"],\n  barry: [now: "2026-13-01T00:00:00Z", keys: "x"],/
        )

      assert [now, keys] = messages(make_case(tmp_dir, meta))
      assert now =~ "barry now: must be a UTC timestamp"
      assert keys =~ "barry: unknown option :keys"
    end
  end

  describe "vrps (#170)" do
    # A ROA in the fixture's tree makes `vrps` required.
    defp with_roa(case_dir) do
      File.mkdir_p!(Path.join([case_dir, "rsync", "ta"]))
      File.write!(Path.join([case_dir, "rsync", "ta", "roa1.roa"]), "not a real ROA")
      case_dir
    end

    test "a fixture with a ROA and no vrps fails", %{tmp_dir: tmp_dir} do
      assert ["missing key :vrps (required: rsync/ holds a ROA; [] if none is valid)"] =
               messages(with_roa(make_case(tmp_dir, @complete)))
    end

    test "a fixture with a ROA passes with its VRPs, or with none", %{tmp_dir: tmp_dir} do
      for {id, vrps} <- [
            {"m4-sample-full", ~s/["AS64496,1.1.0.0\/16,24", "AS64496,101::\/16,48"]/},
            {"m4-sample-empty", "[]"}
          ] do
        meta =
          @complete
          |> edit(~s/id: "m4-sample-case"/, ~s/id: "#{id}"/)
          |> edit(~s/rfc: ["6487#4.8.9"],/, ~s/rfc: ["6487#4.8.9"],\n  vrps: #{vrps},/)

        assert {:ok, %{vrps: _}} =
                 Fixtures.load(with_roa(make_case(tmp_dir, meta, id: id)), @library)
      end
    end

    test "a malformed or repeated VRP fails", %{tmp_dir: tmp_dir} do
      meta =
        edit(
          @complete,
          ~s/rfc: ["6487#4.8.9"],/,
          ~s/rfc: ["6487#4.8.9"],\n  vrps: ["1.1.0.0\/16 => AS64496", "AS1,1.0.0.0\/8,8", "AS1,1.0.0.0\/8,8"],/
        )

      assert [malformed, repeated] = messages(make_case(tmp_dir, meta))
      assert malformed =~ ~s/vrps: "1.1.0.0\/16 => AS64496" must look like/
      assert repeated == ~s/vrps: "AS1,1.0.0.0\/8,8" is listed twice/
    end
  end

  describe "case.exs is data, not code" do
    test "function calls are rejected without being run", %{tmp_dir: tmp_dir} do
      marker = Path.join(tmp_dir, "ran")

      meta =
        edit(@complete, ~s/title: "Sample case"/, ~s/title: File.write!(#{inspect(marker)}, "x")/)

      assert [message] = messages(make_case(tmp_dir, meta))
      assert message =~ "case.exs must contain only literal values"
      refute File.exists?(marker)
    end

    test "string interpolation is rejected", %{tmp_dir: tmp_dir} do
      meta = edit(@complete, ~s/title: "Sample case"/, ~S/title: "Sample #{1 + 1}"/)
      assert [message] = messages(make_case(tmp_dir, meta))
      assert message =~ "only literal values"
    end

    test "metadata that is not a map is rejected", %{tmp_dir: tmp_dir} do
      assert ["metadata must be a map"] = messages(make_case(tmp_dir, "[id: \"m4-sample-case\"]"))
    end

    test "unparseable metadata is rejected", %{tmp_dir: tmp_dir} do
      assert [message] = messages(make_case(tmp_dir, "%{id: "))
      assert message =~ "cannot parse case.exs"
    end
  end

  describe "files" do
    test "a missing case.exs fails", %{tmp_dir: tmp_dir} do
      assert ["missing case.exs"] = messages(make_case(tmp_dir, nil))
    end

    test "a missing descriptor fails", %{tmp_dir: tmp_dir} do
      case_dir = make_case(tmp_dir, @complete, files: [:tal, :rsync])
      assert ["missing case.repo"] = messages(case_dir)
    end

    test "missing generated output fails and says how to fix it", %{tmp_dir: tmp_dir} do
      case_dir = make_case(tmp_dir, @complete, files: [:repo])

      assert [
               "missing case.tal",
               "missing generated rsync/ tree",
               "run `mix lumina.fixtures.gen m4-sample-case`",
               "expected reject object \"ta.cer\" is not in rsync/"
             ] = messages(case_dir)
    end
  end

  test "load_all/2 returns passing fixtures and every problem", %{tmp_dir: tmp_dir} do
    make_case(tmp_dir, @complete)
    make_case(tmp_dir, nil, id: "m4-broken")
    File.write!(Path.join(tmp_dir, "README.md"), "not a fixture")

    assert {[%{id: "m4-sample-case"}], [%{message: "missing case.exs", file: file}]} =
             Fixtures.load_all(tmp_dir, @library)

    assert file == Path.join([tmp_dir, "m4-broken", "case.exs"])
  end
end
