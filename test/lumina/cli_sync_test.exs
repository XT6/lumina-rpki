defmodule Lumina.CLISyncTest do
  @moduledoc """
  Tests `lumina sync` (#76) through `Lumina.CLI.run/4`, against real rsync
  daemons serving Barry fixtures: the summary, `--tal` picking TALs,
  exit codes (0 everything fetched, 1 a fetch failed, 2 usage error), the
  cache lock and `lumina help sync`. Output goes to StringIO devices.

  The fixture TALs name `https://localhost:8443` and
  `rsync://localhost:8873`. Each test writes a copy of the TAL whose rsync
  URI points at its own daemon, and remaps `localhost:8873` in the
  repository's certificates to it (`:remap`, see `Lumina.Walk`).
  """
  use ExUnit.Case, async: true

  alias Lumina.CLI
  alias Lumina.Test.{Fixture, RsyncDaemon}

  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]

  defp run(args, internal \\ []) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(args, out, err, [now: @now] ++ internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  # Serves fixture `id` and writes a TAL for it into `dir`, with only an
  # rsync URI, at the daemon. Returns the TAL's path and the remap entry.
  defp served_tal(tmp, id, dir) do
    fixture = Fixture.load!(id)
    daemon = RsyncDaemon.start!(Path.join(tmp, "daemon-" <> id), %{"rpki" => fixture.rsync_root})
    authority = "127.0.0.1:#{daemon.port}"

    text =
      fixture.tal_path
      |> File.read!()
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(&1, "https://"))
      |> Enum.map_join(
        "\n",
        &String.replace(&1, "rsync://localhost:8873", "rsync://" <> authority)
      )

    path = Path.join(dir, id <> ".tal")
    File.mkdir_p!(dir)
    File.write!(path, text)
    {path, %{"localhost:8873" => authority}}
  end

  # A TAL with the key of fixture `id` whose only URI can't be reached.
  defp dead_tal(id, dir) do
    text =
      Fixture.load!(id).tal_path
      |> File.read!()
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(&1, ["https://", "rsync://"]))
      |> then(&["rsync://127.0.0.1:#{RsyncDaemon.closed_port()}/rpki/ta.cer" | &1])
      |> Enum.join("\n")

    path = Path.join(dir, "dead-" <> id <> ".tal")
    File.mkdir_p!(dir)
    File.write!(path, text)
    path
  end

  describe "syncing" do
    @tag :rsync
    @tag rfc: ["8630#3", "6481#5"]
    test "a full sync exits 0 and prints the TA URI, publication points and fetches", %{
      tmp_dir: tmp
    } do
      {tal, remap} = served_tal(tmp, "m0-minimal-valid", Path.join(tmp, "tals"))
      cache = Path.join(tmp, "cache")

      assert {0, out, ""} = run(["sync", "--cache", cache, "--tal", tal], remap: remap)

      assert out =~ "#{tal}\n  ta: rsync://127.0.0.1:"
      assert out =~ "  publication points: 2\n  rsync fetches: 2, 0 failed\n"
      assert out =~ "1 TAL(s), 2 rsync fetch(es), 0 TAL(s) with failures"
      assert File.exists?(Path.join(cache, "rsync/localhost:8873/rpki/ca1/roa1.roa"))
    end

    @tag :rsync
    @tag doc: """
         Requested by the maintainer: --tal syncs that TAL only. The tals
         folder also holds a TAL that can't be reached; it must not be tried.
         """
    test "--tal syncs only the TAL it names", %{tmp_dir: tmp} do
      tals = Path.join(tmp, "tals")
      {tal, remap} = served_tal(tmp, "m0-minimal-valid", tals)
      dead = dead_tal("m1-roa-prefixes", tals)

      assert {0, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal],
                 remap: remap,
                 tal_dir: tals
               )

      assert out =~ tal
      refute out =~ dead
      assert [_one] = Path.wildcard(Path.join(tmp, "cache/.ta/*.cer"))
    end

    @tag :rsync
    test "without --tal, every TAL in the TAL folder is synced", %{tmp_dir: tmp} do
      tals = Path.join(tmp, "tals")
      {tal, remap} = served_tal(tmp, "m0-minimal-valid", tals)
      dead = dead_tal("m1-roa-prefixes", tals)

      assert {1, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache")], remap: remap, tal_dir: tals)

      assert out =~ tal and out =~ dead
      assert out =~ "2 TAL(s)"
    end

    @tag :rsync
    @tag rfc: "6481#5"
    test "a partial failure exits 1 and names the failure and its reason", %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp, "m3-walk-unreachable", Path.join(tmp, "tals"))

      assert {1, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal], remap: remap)

      assert out =~ "fetch_failed: rsync://unreachable.invalid/repo/ca1 (unknown_host)"
      assert out =~ "rsync fetches: 3, 1 failed"
      assert out =~ "1 TAL(s) with failures"
    end

    @tag :rsync
    @tag rfc: "8630#3"
    test "a TAL whose TA can't be fetched exits 1, with each attempt listed", %{tmp_dir: tmp} do
      dead = dead_tal("m0-minimal-valid", Path.join(tmp, "tals"))

      assert {1, out, ""} = run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", dead])

      assert out =~ "ta: FAILED, every URI"
      assert out =~ "fetch_failed (connection_refused)"
      assert out =~ "no earlier copy; repository not walked"
    end
  end

  describe "the cache lock" do
    @tag :rsync
    test "a cache held by a running process isn't touched, and the sync exits 1", %{
      tmp_dir: tmp
    } do
      cache = Path.join(tmp, "cache")
      File.mkdir_p!(cache)
      File.write!(Path.join(cache, ".lock"), System.pid())
      dead = dead_tal("m0-minimal-valid", Path.join(tmp, "tals"))

      assert {1, "", err} = run(["sync", "--cache", cache, "--tal", dead])
      assert err =~ "is in use by another sync (process #{System.pid()})"
      assert File.read!(Path.join(cache, ".lock")) == System.pid()
    end

    @tag :rsync
    @tag doc: "A lock left by a crashed run (its process is gone) is taken over and released."
    test "a lock whose process is gone is taken over", %{tmp_dir: tmp} do
      cache = Path.join(tmp, "cache")
      File.mkdir_p!(cache)
      File.write!(Path.join(cache, ".lock"), "99999999")
      dead = dead_tal("m0-minimal-valid", Path.join(tmp, "tals"))

      assert {1, out, ""} = run(["sync", "--cache", cache, "--tal", dead])
      assert out =~ "ta: FAILED"
      refute File.exists?(Path.join(cache, ".lock"))
    end
  end

  describe "rsync (#89)" do
    # A fake rsync: prints `version_text` for --version, otherwise writes
    # `message` to stderr and exits `status`.
    defp fake_rsync(tmp, version_text, status \\ 0, message \\ "") do
      path = Path.join(tmp, "fake-rsync")

      File.write!(path, """
      #!/bin/sh
      if [ "$1" = "--version" ]; then printf '%s\\n' '#{version_text}'; exit 0; fi
      printf '%s\\n' '#{message}' >&2
      exit #{status}
      """)

      File.chmod!(path, 0o755)
      path
    end

    @tag doc: "The cache isn't created: nothing is fetched and no lock is taken."
    test "an rsync older than 3.1.0 stops the sync before anything is fetched, exit 1", %{
      tmp_dir: tmp
    } do
      rsync = fake_rsync(tmp, "rsync  version 2.6.9  protocol version 29")
      dead = dead_tal("m0-minimal-valid", Path.join(tmp, "tals"))
      cache = Path.join(tmp, "cache")

      assert {1, "", err} = run(["sync", "--cache", cache, "--tal", dead], rsync: [rsync: rsync])
      assert err =~ "lumina sync: #{rsync} is rsync 2.6.9; Lumina needs 3.1.0 or later"
      assert err =~ "openrsync"
      refute File.exists?(cache)
    end

    @tag doc: "macOS's /usr/bin/rsync is openrsync, which reports itself as 2.6.9 compatible."
    test "openrsync is recognised as too old", %{tmp_dir: tmp} do
      rsync = fake_rsync(tmp, "openrsync: protocol version 29\nrsync version 2.6.9 compatible")
      dead = dead_tal("m0-minimal-valid", Path.join(tmp, "tals"))

      assert {1, "", err} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", dead],
                 rsync: [rsync: rsync]
               )

      assert err =~ "is rsync 2.6.9; Lumina needs 3.1.0 or later"
    end

    test "a missing rsync stops the sync before anything is fetched, exit 1", %{tmp_dir: tmp} do
      dead = dead_tal("m0-minimal-valid", Path.join(tmp, "tals"))
      cache = Path.join(tmp, "cache")

      assert {1, "", err} =
               run(["sync", "--cache", cache, "--tal", dead],
                 rsync: [rsync: Path.join(tmp, "no-such-rsync")]
               )

      assert err =~ "lumina sync: rsync not found; Lumina needs rsync 3.1.0 or later"
      refute File.exists?(cache)
    end

    @tag doc: """
         An rsync that passes the version check but rejects an argument
         (exit 1): the fetch fails as usage_error, and rsync's own message
         is in the summary.
         """
    test "an rsync that rejects its arguments is reported with rsync's message", %{
      tmp_dir: tmp
    } do
      rsync =
        fake_rsync(
          tmp,
          "rsync  version 3.2.7  protocol version 31",
          1,
          "rsync: unrecognized option `--info=skip1`"
        )

      dead = dead_tal("m0-minimal-valid", Path.join(tmp, "tals"))

      assert {1, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", dead],
                 rsync: [rsync: rsync]
               )

      assert out =~ "fetch_failed (usage_error: rsync: unrecognized option `--info=skip1`)"
    end
  end

  describe "usage" do
    test "--tal on a missing file is a usage error", %{tmp_dir: tmp} do
      missing = Path.join(tmp, "nope.tal")

      assert {2, "", err} = run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", missing])
      assert err =~ "lumina sync: #{missing}:"
      refute File.exists?(Path.join(tmp, "cache"))
    end

    @tag rfc: "8630#2.2"
    test "--tal on a file that isn't a TAL is a usage error", %{tmp_dir: tmp} do
      bad = Path.join(tmp, "bad.tal")
      File.write!(bad, "not a TAL\n")

      assert {2, "", err} = run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", bad])
      assert err =~ "lumina sync: #{bad}: TAL line"
    end

    test "an unknown flag, a stray argument or a bad number is a usage error", %{tmp_dir: tmp} do
      cache = Path.join(tmp, "cache")

      assert {2, "", err} = run(["sync", "--bogus"])
      assert err =~ "unknown or invalid flag --bogus"
      assert {2, "", err} = run(["sync", "extra"])
      assert err =~ "unexpected argument extra"
      assert {2, "", _} = run(["sync", "--cache", cache, "--timeout", "soon"])
      assert {2, "", err} = run(["sync", "--cache", cache, "--timeout", "0"])
      assert err =~ "--timeout must be at least 1"
    end

    test "an empty TAL folder without --tal is a usage error", %{tmp_dir: tmp} do
      assert {2, "", err} =
               run(["sync", "--cache", Path.join(tmp, "cache")], tal_dir: Path.join(tmp, "none"))

      assert err =~ "no .tal files in"
    end

    test "lumina help sync describes the flags and exit codes" do
      assert {0, out, ""} = run(["help", "sync"])
      assert out =~ "Usage: lumina sync [--cache DIR] [--tal FILE]..."

      for flag <- ["--cache DIR", "--tal FILE", "--timeout SECONDS", "--max-depth N"],
          do: assert(out =~ flag)

      assert out =~ "Exit codes: 0 everything fetched, 1 some fetch failed"
      assert {0, ^out, ""} = run(["sync", "--help"])
    end

    test "lumina help lists sync" do
      assert {0, out, ""} = run(["help"])
      assert out =~ "sync    fetch the trust anchors and repositories"
    end
  end
end
