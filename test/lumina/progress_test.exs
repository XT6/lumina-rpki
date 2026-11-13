defmodule Lumina.ProgressTest do
  @moduledoc """
  Tests progress reporting (`Lumina.Progress`, #96): the events a walk
  emits, the status text built from a scripted event sequence, and
  `lumina sync --progress` / `--quiet`.

  Progress goes to stderr and never changes stdout. Tests run with
  StringIO devices, which aren't terminals, so `lumina sync` shows
  progress only with `--progress`, as timestamped lines.
  """
  use ExUnit.Case, async: true

  alias Lumina.{CLI, Object, Progress, Walk}
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
         m0-minimal-valid: the TA's level fetches its publication point, the
         next level ca1's. Each level is started, its fetches run, and it is
         finished, with the running totals of the walk.
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

      base = "rsync://localhost:8873/rpki"

      assert received() == [
               {:level_started, 0, %{points: 1, fetches: 1}},
               {:fetch_started, base <> "/ta", "localhost"},
               {:fetch_finished, base <> "/ta", "localhost", :ok, 3},
               {:level_finished, 0, %{points: 1, issues: 0}},
               {:level_started, 1, %{points: 1, fetches: 1}},
               {:fetch_started, base <> "/ca1", "localhost"},
               {:fetch_finished, base <> "/ca1", "localhost", :ok, 3},
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

    test "on a terminal, the status line is cut to the terminal width" do
      assert Progress.render(scripted(), 4_000, columns: 30) == "4s  lacnic.tal (1/2)  level 1"
    end
  end

  describe "lumina sync" do
    @tag :rsync
    @tag doc: """
         StringIO isn't a terminal, so these are the plain lines a log or a
         pipe gets: a timestamp, no control characters, one line per TAL
         and per finished level.
         """
    test "--progress reports on stderr as plain timestamped lines, and stdout is unchanged", %{
      tmp_dir: tmp
    } do
      {tal, remap} = served_tal(tmp)
      cache = Path.join(tmp, "cache")

      assert {0, quiet_out, ""} = run(["sync", "--cache", cache, "--tal", tal], remap: remap)

      assert {0, out, err} =
               run(["sync", "--cache", cache, "--tal", tal, "--progress"], remap: remap)

      assert out == quiet_out
      refute err =~ "\e"
      lines = String.split(err, "\n", trim: true)
      assert length(lines) >= 3

      assert Enum.all?(
               lines,
               &(&1 =~ ~r/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ \d+s  m0\.tal \(1\/1\)/)
             )

      assert List.last(lines) =~ "level 1 (1 point)  points 2  rsync 2 done, 0 running  files 6"
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
