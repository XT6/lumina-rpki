defmodule Lumina.ProgressTest do
  @moduledoc """
  Tests progress reporting (`Lumina.Progress`, #96): the events a walk
  emits, the status text built from a scripted event sequence, and
  `lumina sync --progress` / `--quiet`. Validation reports progress too
  (#180): `Lumina.Validate.run/3`'s events and `lumina validate` /
  `lumina vrps` with `--progress` / `--quiet`. Every long-running
  operation reports progress (D-036).

  Progress goes to stderr and never changes stdout. It is on by default
  (D-036): tests run with StringIO devices, which aren't terminals, so
  the commands report timestamped lines unless given `--quiet`. Other
  test modules add `--quiet` (`Lumina.Test.Quiet`); these run the
  commands as given.
  """
  use ExUnit.Case, async: true

  doctest Lumina.Test.Quiet

  alias Lumina.{CLI, Object, Progress, TAL, Validate, Walk}
  alias Lumina.Test.{Fixture, RsyncDaemon}

  @moduletag :tmp_dir

  # Events received by this process from a `:progress` function.
  defp listener do
    me = self()
    &send(me, {:progress, &1})
  end

  defp received do
    receive do
      {:progress, event} -> [event | received()]
    after
      0 -> []
    end
  end

  defp served_tal(tmp) do
    fixture = Fixture.load!("m0-minimal-valid")
    daemon = RsyncDaemon.start!(tmp, %{"rpki" => fixture.rsync_root})
    authority = "127.0.0.1:#{daemon.port}"
    tal = Path.join(tmp, "m0.tal")

    File.write!(
      tal,
      fixture.tal_path
      |> File.read!()
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(&1, "https://"))
      |> Enum.map_join(
        "\n",
        &String.replace(&1, "rsync://localhost:8873", "rsync://" <> authority)
      )
    )

    {tal, %{"localhost:8873" => authority}}
  end

  defp run(args, internal) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(args, out, err, internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  describe "events" do
    @tag :rsync
    @tag doc: """
         m0-minimal-valid: the TA's level fetches the module rpki (all 7
         files), which already holds ca1's publication point, so the next
         level fetches nothing. Each level is started, its fetches run, and
         it is finished, with the running totals of the walk.
         """
    test "a walk emits level and fetch events, in order, with outcomes and file counts", %{
      tmp_dir: tmp
    } do
      fixture = Fixture.load!("m0-minimal-valid")
      {:ok, %Object{value: ta}} = Object.decode_file(Path.join(fixture.rsync_root, "ta.cer"))
      daemon = RsyncDaemon.start!(tmp, %{"rpki" => fixture.rsync_root})

      Walk.run(ta, Path.join(tmp, "cache"),
        remap: %{"localhost:8873" => "127.0.0.1:#{daemon.port}"},
        progress: listener()
      )

      module = "rsync://localhost:8873/rpki"

      assert received() == [
               {:level_started, 0, %{points: 1, fetches: 1}},
               {:fetch_started, module, "localhost"},
               {:fetch_finished, module, "localhost", :ok, 7},
               {:level_finished, 0, %{points: 1, issues: 0}},
               {:level_started, 1, %{points: 1, fetches: 0}},
               {:level_finished, 1, %{points: 2, issues: 0}}
             ]
    end

    test "emit/2 without a listener does nothing" do
      assert Progress.emit([], {:level_started, 0, %{points: 1, fetches: 1}}) == :ok
    end
  end

  describe "status text" do
    # A scripted sync: one TAL of two, a TA attempt, a level of three
    # points with two fetches, one finished and one failed, and a third
    # still running since time 1_000.
    defp scripted do
      [
        {0, {:tal_started, "tals/lacnic.tal", 1, 2}},
        {100, {:ta_trying, "https://rrdp.lacnic.net/ta/rta-lacnic-rpki.cer"}},
        {500, {:level_started, 1, %{points: 3, fetches: 3}}},
        {600, {:fetch_started, "rsync://a.example/repo/x", "a.example"}},
        {700, {:fetch_started, "rsync://b.example/repo/y", "b.example"}},
        {1_000, {:fetch_started, "rsync://c.example/repo/z", "c.example"}},
        {2_000, {:fetch_finished, "rsync://a.example/repo/x", "a.example", :ok, 120}},
        {3_000, {:fetch_finished, "rsync://b.example/repo/y", "b.example", :error, 0}},
        {3_500, {:level_finished, 0, %{points: 4, issues: 1}}}
      ]
      |> Enum.reduce(Progress.new(0), fn {at, event}, state ->
        Progress.update(state, event, at)
      end)
    end

    test "the TA being tried shows before the walk starts" do
      state =
        Progress.new(0)
        |> Progress.update({:tal_started, "tals/arin.tal", 2, 5}, 0)
        |> Progress.update({:ta_trying, "https://rrdp.arin.net/arin-rpki-ta.cer"}, 10)

      assert Progress.render(state, 2_500) ==
               "2s  arin.tal (2/5)  ta: https://rrdp.arin.net/arin-rpki-ta.cer"
    end

    test "a walk in progress shows its level, points, rsync runs and files" do
      assert Progress.render(scripted(), 4_000) ==
               "4s  lacnic.tal (1/2)  level 1 (3 points)  points 4  " <>
                 "rsync 2 done, 1 running, 1 failed  files 120"
    end

    @tag doc: "A stuck host (like krill.dacs.utwente.nl in the live LACNIC run) becomes visible."
    test "a fetch running for more than 5 s is shown as the slowest, with its host" do
      assert Progress.render(scripted(), 7_000) =~ "  slowest: c.example 6s"
      refute Progress.render(scripted(), 5_500) =~ "slowest"
    end

    @tag doc: """
         A transient failure (D-039, #193) ends the first run without
         counting it done or failed; the retry is a fetch of its own.
         """
    test "a fetch being retried leaves the running ones and is counted as retried" do
      state =
        scripted()
        |> Progress.update(
          {:fetch_retrying, "rsync://c.example/repo/z", "c.example", %{reason: :protocol_error}},
          4_000
        )

      assert Progress.render(state, 4_500) ==
               "4s  lacnic.tal (1/2)  level 1 (3 points)  points 4  " <>
                 "rsync 2 done, 0 running, 1 failed, 1 retried  files 120"
    end

    test "on a terminal, the status line is cut to the terminal width" do
      assert Progress.render(scripted(), 4_000, columns: 30) == "4s  lacnic.tal (1/2)  level 1"
    end
  end

  describe "validation (#180)" do
    @tag :rsync
    @tag doc: """
         m0-minimal-valid, synced then validated: a level event pair per
         level, and one point_validated per publication point whose
         objects and invalid counts add up to the result's.
         """
    test "Validate.run/3 reports each level and each point validated, with counts matching the result",
         %{tmp_dir: tmp} do
      {tal_path, remap} = served_tal(tmp)
      cache = Path.join(tmp, "cache")
      {0, _, ""} = run(["sync", "--cache", cache, "--tal", tal_path, "--quiet"], remap: remap)
      {:ok, tal} = TAL.decode_file(tal_path)

      {:ok, result} =
        Validate.run(tal, cache, now: ~U[2030-01-01 00:00:00Z], progress: listener())

      events = received()

      assert [
               {:validation_level_started, 0, %{points: 1}},
               {:point_validated, _},
               {:validation_level_finished, 0, %{points: 1}},
               {:validation_level_started, 1, %{points: 1}},
               {:point_validated, _},
               {:validation_level_finished, 1, %{points: 1}}
             ] = events

      counts = for {:point_validated, c} <- events, do: c
      assert Enum.sum_by(counts, & &1.objects) == length(result.objects)

      assert Enum.sum_by(counts, & &1.invalid) ==
               Enum.count(result.objects, &(&1[:valid] != true))
    end

    test "a validation in progress shows its level, points, objects and invalid ones" do
      state =
        [
          {0, {:tal_started, "tals/lacnic.tal", 1, 1}},
          {100, {:validation_level_started, 3, %{points: 3516}}},
          {200, {:point_validated, %{objects: 10, invalid: 0}}},
          {300, {:point_validated, %{objects: 5, invalid: 2}}}
        ]
        |> Enum.reduce(Progress.new(0), fn {at, event}, st -> Progress.update(st, event, at) end)

      assert Progress.render(state, 4_000) ==
               "4s  lacnic.tal (1/1)  level 3 (3516 points)  points 2  objects 15  invalid 2"

      refute Progress.render(%{state | invalid: 0}, 4_000) =~ "invalid"
    end

    @tag :rsync
    @tag doc: """
         Without any flag, and with --progress, the same timestamped lines
         (StringIO isn't a terminal); stdout is what --quiet gives.
         """
    test "lumina validate and lumina vrps report progress on stderr by default, and stdout is unchanged",
         %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp)
      cache = Path.join(tmp, "cache")
      {0, _, ""} = run(["sync", "--cache", cache, "--tal", tal, "--quiet"], remap: remap)
      base = ["--cache", cache, "--tal", tal, "--now", "2030-01-01"]

      for command <- ["validate", "vrps"], flags <- [[], ["--progress"]] do
        {0, quiet_out, quiet_err} = run([command | base] ++ ["--quiet"], [])
        assert {0, out, err} = run([command | base] ++ flags, [])

        assert out == quiet_out, command
        refute err =~ "\e"
        progress = String.replace(err, quiet_err, "")
        lines = String.split(progress, "\n", trim: true)
        assert length(lines) >= 2, command

        assert Enum.all?(
                 lines,
                 &(&1 =~ ~r/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ \d+s  m0\.tal \(1\/1\)/)
               )

        assert List.last(lines) =~ "points 2  objects 4", command
      end
    end

    @tag :rsync
    test "--quiet reports no progress for lumina validate and lumina vrps", %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp)
      cache = Path.join(tmp, "cache")
      {0, _, ""} = run(["sync", "--cache", cache, "--tal", tal, "--quiet"], remap: remap)
      base = ["--cache", cache, "--tal", tal, "--now", "2030-01-01", "--quiet"]

      assert {0, _out, ""} = run(["validate" | base], [])
      assert {0, _out, "m0: 2 VRPs\n"} = run(["vrps" | base], [])
    end

    test "lumina help validate and lumina help vrps list --progress and --quiet" do
      for command <- ["validate", "vrps"] do
        assert {0, out, ""} = run(["help", command], [])
        assert out =~ "--progress", command
        assert out =~ "--quiet", command
      end
    end
  end

  describe "lumina sync" do
    @tag :rsync
    @tag doc: """
         StringIO isn't a terminal, so these are the plain lines a log or a
         pipe gets: a timestamp, no control characters, one line per TAL
         and per finished level.
         """
    test "progress is reported by default, as plain timestamped lines, and stdout is unchanged",
         %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp)
      cache = Path.join(tmp, "cache")

      assert {0, quiet_out, ""} =
               run(["sync", "--cache", cache, "--tal", tal, "--quiet"], remap: remap)

      assert {0, out, err} = run(["sync", "--cache", cache, "--tal", tal], remap: remap)

      assert out == quiet_out
      refute err =~ "\e"
      lines = String.split(err, "\n", trim: true)
      assert length(lines) >= 3

      assert Enum.all?(
               lines,
               &(&1 =~ ~r/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ \d+s  m0\.tal \(1\/1\)/)
             )

      assert List.last(lines) =~ "level 1 (1 point)  points 2  rsync 1 done, 0 running  files 7"
    end

    @tag :rsync
    test "--quiet reports no progress", %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp)

      assert {0, _out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal, "--quiet"],
                 remap: remap
               )
    end

    test "lumina help sync lists --progress and --quiet" do
      assert {0, out, ""} = run(["help", "sync"], [])
      assert out =~ "--progress"
      assert out =~ "--quiet"
    end
  end
end
