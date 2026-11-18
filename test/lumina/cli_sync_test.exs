defmodule Lumina.CLISyncTest do
  @moduledoc """
  Tests `lumina sync` (#76) through `Lumina.CLI.run/4`, against real rsync
  daemons serving Barry fixtures: the summary, `--tal` picking TALs,
  exit codes (0 everything fetched, 1 a fetch failed, 2 usage error), the
  cache lock and `lumina help sync`, and how invalid TAs and CAs are
  reported (#113). Output goes to StringIO devices.

  The fixture TALs name `https://localhost:8443` and
  `rsync://localhost:8873`. Each test writes a copy of the TAL whose rsync
  URI points at its own daemon, and remaps `localhost:8873` in the
  repository's certificates to it (`:remap`, see `Lumina.Walk`).

  RRDP (#208): `--no-rrdp`, the RRDP limits and the summary's `rrdp:`
  line, against `Lumina.Test.RRDPServer`, which serves the fixture's
  `rrdp/` files (the TA certificate too) at `https://localhost:8443`.
  RRDP is off by default in tests (`test/test_helper.exs`), so these
  runs turn it on through the internal options, as the real default.
  """
  use ExUnit.Case, async: true

  alias Lumina.CLI
  alias Lumina.Test.{Fixture, RRDPServer, RsyncDaemon}

  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]

  defp run(args, internal \\ []) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(Lumina.Test.Quiet.args(args), out, err, [now: @now] ++ internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  # Serves fixture `id` and writes a TAL for it into `dir`, with only an
  # rsync URI, at the daemon. Returns the TAL's path and the remap entry.
  defp served_tal(tmp, id, dir, daemon_opts \\ []) do
    fixture = Fixture.load!(id)

    daemon =
      RsyncDaemon.start!(
        Path.join(tmp, "daemon-" <> id),
        fixture.modules,
        daemon_opts
      )

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

  # Serves `fixture` over RRDP (its notification of `serial`, by default
  # the last) and from an rsync daemon. Returns the server and the
  # internal options of a sync that uses RRDP, as lumina does by default.
  defp rrdp_served(tmp, fixture, serial \\ nil) do
    server = RRDPServer.start!(RRDPServer.routes(fixture, serial))
    daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), fixture.modules)

    internal = [
      rrdp: true,
      rrdp_opts: [cacerts: server.opts[:cacerts], min_interval: 0],
      remap: Map.put(server.opts[:remap], "localhost:8873", "127.0.0.1:#{daemon.port}"),
      https: [cacerts: server.opts[:cacerts], remap: server.opts[:remap]]
    ]

    {server, internal}
  end

  defp rrdp_sync(fixture, cache, internal, flags \\ []),
    do: run(["sync", "--cache", cache, "--tal", fixture.tal_path] ++ flags, internal)

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
      assert out =~ "  publication points: 2\n  rsync fetches: 1, 0 failed\n"
      assert out =~ "1 TAL(s), 1 rsync fetch(es), 0 TAL(s) with failures"
      assert File.exists?(Path.join(cache, "rsync/localhost:8873/rpki/ca1/roa1.roa"))
    end

    @tag :rsync
    @tag rfc: ["6481#5", "6487#7.2"],
         doc: "D-014: an invalid CA isn't a fetch failure; the sync exits 0."
    test "an invalid CA is listed with its reasons, and isn't walked", %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp, "m4-chain-ca-bad-signature", Path.join(tmp, "tals"))

      assert {0, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal], remap: remap)

      assert out =~ "  publication points: 1\n"
      assert out =~ "    invalid: rsync://localhost:8873/rpki/ta/ca1.cer (bad_signature)\n"
    end

    @tag :rsync
    @tag rfc: ["9286#6.5", "9286#6.6"],
         doc: "Like an invalid CA, a failed publication point isn't a fetch failure: exit 0."
    test "a publication point that fails is counted and listed with its reasons", %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp, "m5-pp-hash-mismatch", Path.join(tmp, "tals"))

      assert {0, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal], remap: remap)

      assert out =~ "  publication points: 2 (1 failed)\n"
      assert out =~ "    point_failed: rsync://localhost:8873/rpki/ca1/ca1.mft (hash_mismatch)\n"

      assert out =~
               "    refetched: rsync://localhost:8873/rpki " <>
                 "(rsync://localhost:8873/rpki/ca1/ca1.mft: hash_mismatch; fetched again)\n"
    end

    @tag :rsync
    @tag rfc: "9286#6.6",
         doc: "D-023: served from a copy whose ROA changes between two syncs."
    test "a point that fails after a good sync is counted as served from its last valid copy", %{
      tmp_dir: tmp
    } do
      copy = Path.join(tmp, "copy")
      File.cp_r!(Fixture.load!("m0-minimal-valid").rsync_root, copy)
      daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), %{"rpki" => copy})
      authority = "127.0.0.1:#{daemon.port}"
      tal = Path.join(tmp, "copy.tal")

      File.write!(
        tal,
        Fixture.load!("m0-minimal-valid").tal_path
        |> File.read!()
        |> String.split("\n")
        |> Enum.reject(&String.starts_with?(&1, "https://"))
        |> Enum.map_join(
          "\n",
          &String.replace(&1, "rsync://localhost:8873", "rsync://" <> authority)
        )
      )

      args = ["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal]
      remap = %{"localhost:8873" => authority}
      assert {0, _out, ""} = run(args, remap: remap)
      File.write!(Path.join(copy, "ca1/roa1.roa"), "changed", [:append])

      assert {0, out, ""} = run(args, remap: remap)
      assert out =~ "  publication points: 2 (1 from the last valid copy)\n"

      assert out =~
               "    point_fallback: rsync://localhost:8873/rpki/ca1/ca1.mft (hash_mismatch)\n"
    end

    @tag :rsync
    @tag rfc: ["8630#3", "6487#7.2"]
    test "a TA that doesn't validate is rejected with its reasons, exit 1", %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp, "m4-chain-ta-expired", Path.join(tmp, "tals"))
      cache = Path.join(tmp, "cache")

      assert {1, out, ""} = run(["sync", "--cache", cache, "--tal", tal], remap: remap)

      assert out =~
               ~r"    tried rsync://127\.0\.0\.1:\d+/rpki/ta\.cer: check_failed \(expired\)\n"

      assert out =~ "  ta: no earlier copy; repository not walked\n"
      refute File.exists?(Path.join(cache, "rsync"))
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
    @tag rfc: "6481#5",
         doc: """
         m3-walk-unreachable: the delegated CA's host doesn't resolve. The
         trust anchor and its own publication point synced, so the exit code
         is 0 (D-037, #187), with the failure listed and a warning.
         """
    test "a failure below the trust anchor's publication point exits 0 with a warning, named",
         %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp, "m3-walk-unreachable", Path.join(tmp, "tals"))

      assert {0, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal], remap: remap)

      assert out =~ "fetch_failed: rsync://unreachable.invalid/repo (unknown_host)"
      assert out =~ "rsync fetches: 2, 1 failed"
      assert out =~ "1 TAL(s) with failures"

      assert String.ends_with?(
               out,
               "warning: some fetches below the trust anchors failed (above)\n"
             )
    end

    @tag :rsync
    @tag doc: """
         The TA is retrieved from the daemon, but the repository host in its
         certificate points at a closed port: its own publication point is
         never fetched (#187).
         """
    test "a trust anchor whose own publication point can't be fetched exits 1", %{tmp_dir: tmp} do
      {tal, _remap} = served_tal(tmp, "m0-minimal-valid", Path.join(tmp, "tals"))
      closed = %{"localhost:8873" => "127.0.0.1:#{RsyncDaemon.closed_port()}"}

      assert {1, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal], remap: closed)

      assert out =~ ~r"  ta: rsync://127\.0\.0\.1:\d+/rpki/ta\.cer\n"
      assert out =~ "fetch_failed: rsync://localhost:8873/rpki"
      refute out =~ "warning: some fetches below"
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

  describe "sync times (#185)" do
    @describetag :rsync

    @tag doc: """
         lumina vrps --sync measures a TAL's age from this record. A TAL
         whose TA can't be retrieved, with none stored, gets none.
         """
    test "each TAL whose tree was walked gets its sync time recorded", %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp, "m0-minimal-valid", Path.join(tmp, "tals"))
      dead = dead_tal("m1-roa-prefixes", Path.join(tmp, "tals"))
      cache = Path.join(tmp, "cache")

      assert {1, _, _} =
               run(["sync", "--cache", cache, "--tal", tal, "--tal", dead, "--timeout", "5"],
                 remap: remap
               )

      assert Lumina.Sync.last_synced(cache, elem(Lumina.TAL.decode_file(tal), 1)) == @now
      assert Lumina.Sync.last_synced(cache, elem(Lumina.TAL.decode_file(dead), 1)) == nil
    end
  end

  describe "overclaims (#155)" do
    @tag :rsync
    @tag rfc: ["6487#7.2", "3779#2.3"],
         doc: """
         m6-overclaim-ipv4: ca2 claims 2.0.0.0/16, outside ca1's. Like any
         invalid CA it isn't a fetch failure (exit 0), and it isn't
         walked.
         """
    test "an overclaiming CA certificate is listed with the resources outside its issuer's, and counted",
         %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp, "m6-overclaim-ipv4", Path.join(tmp, "tals"))

      assert {0, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal], remap: remap)

      assert out =~
               "    invalid: rsync://localhost:8873/rpki/ca1/ca2.cer " <>
                 "(resources_not_encompassed: 2.0.0.0/16)\n"

      assert out =~ "  overclaims: 1 (resources outside the issuer's, RFC 6487 section 7.2)\n"
      # ta and ca1; ca2's point isn't walked.
      assert out =~ "  publication points: 2\n"
    end

    @tag :rsync
    @tag rfc: "6488#3",
         doc: """
         The walk validates CA certificates only, so a ROA whose EE
         certificate overclaims (m6-overclaim-roa-ee) is lumina
         validate's to report.
         """
    test "a signed object's overclaim is not reported by sync", %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp, "m6-overclaim-roa-ee", Path.join(tmp, "tals"))

      assert {0, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal], remap: remap)

      refute out =~ "  overclaims:"
      refute out =~ "resources_not_encompassed"
    end

    @tag :rsync
    test "a sync without overclaims prints no overclaims line", %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp, "m0-minimal-valid", Path.join(tmp, "tals"))

      assert {0, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal], remap: remap)

      refute out =~ "  overclaims:"
    end
  end

  describe "--per-host (#98)" do
    @tag :rsync
    @tag doc: """
         m3-walk-siblings (eight sibling publication points) from a daemon
         that refuses a second connection: with --per-host 1 every fetch
         gets through, so the flag reaches the walk.
         """
    test "--per-host 1 makes at most one rsync run at a time per host", %{tmp_dir: tmp} do
      {tal, remap} =
        served_tal(tmp, "m3-walk-siblings", Path.join(tmp, "tals"), max_connections: 1)

      assert {0, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal, "--per-host", "1"],
                 remap: remap
               )

      assert out =~ ", 0 failed\n"
    end

    @tag :rsync
    @tag doc: "The converse: with --per-host 8 the same daemon refuses some fetches."
    test "--per-host above what the server accepts gets fetches refused", %{tmp_dir: tmp} do
      {tal, remap} =
        served_tal(tmp, "m3-walk-siblings", Path.join(tmp, "tals"), max_connections: 1)

      assert {0, out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal, "--per-host", "8"],
                 remap: remap
               )

      assert out =~ "fetch_failed"
      assert out =~ "warning: some fetches below the trust anchors failed"
    end

    test "--per-host must be a number of at least 1", %{tmp_dir: tmp} do
      cache = Path.join(tmp, "cache")

      assert {2, "", err} = run(["sync", "--cache", cache, "--per-host", "0"])
      assert err =~ "--per-host must be at least 1"
      assert {2, "", err} = run(["sync", "--cache", cache, "--per-host", "x"])
      assert err =~ "unknown or invalid flag --per-host"
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

  describe "rsync (#89, #93)" do
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

      assert {1, "", err} = run(["sync", "--cache", cache, "--tal", dead, "--rsync", rsync])
      assert err =~ "lumina sync: #{rsync} is rsync 2.6.9; Lumina needs 3.1.0 or later"
      assert err =~ "openrsync"
      refute File.exists?(cache)
    end

    @tag doc: "macOS's /usr/bin/rsync is openrsync, which reports itself as 2.6.9 compatible."
    test "openrsync is recognised as too old", %{tmp_dir: tmp} do
      rsync = fake_rsync(tmp, "openrsync: protocol version 29\nrsync version 2.6.9 compatible")
      dead = dead_tal("m0-minimal-valid", Path.join(tmp, "tals"))

      assert {1, "", err} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", dead, "--rsync", rsync])

      assert err =~ "is rsync 2.6.9; Lumina needs 3.1.0 or later"
    end

    test "--rsync naming a missing file stops the sync, naming the path, exit 1", %{
      tmp_dir: tmp
    } do
      dead = dead_tal("m0-minimal-valid", Path.join(tmp, "tals"))
      cache = Path.join(tmp, "cache")
      missing = Path.join(tmp, "no-such-rsync")

      assert {1, "", err} = run(["sync", "--cache", cache, "--tal", dead, "--rsync", missing])
      assert err =~ "lumina sync: #{missing} not found or not executable"
      refute File.exists?(cache)
    end

    test "--rsync naming a file that isn't executable stops the sync, exit 1", %{tmp_dir: tmp} do
      dead = dead_tal("m0-minimal-valid", Path.join(tmp, "tals"))
      plain = Path.join(tmp, "plain-file")
      File.write!(plain, "#!/bin/sh\n")

      assert {1, "", err} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", dead, "--rsync", plain])

      assert err =~ "#{plain} not found or not executable"
    end

    @tag :rsync
    @tag rfc: ["8630#3", "6481#5"],
         doc: """
         The binary given is a wrapper that logs each call and runs the real
         rsync. The sync must succeed, and every rsync run (version check,
         TA retrieval and walk) must have gone through the wrapper.
         """
    test "--rsync is the binary used for every rsync run", %{tmp_dir: tmp} do
      {tal, remap} = served_tal(tmp, "m0-minimal-valid", Path.join(tmp, "tals"))
      log = Path.join(tmp, "calls.log")
      wrapper = Path.join(tmp, "logging-rsync")

      File.write!(wrapper, """
      #!/bin/sh
      echo "$*" >> '#{log}'
      exec '#{System.find_executable("rsync")}' "$@"
      """)

      File.chmod!(wrapper, 0o755)

      assert {0, _out, ""} =
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", tal, "--rsync", wrapper],
                 remap: remap
               )

      calls = log |> File.read!() |> String.split("\n", trim: true)
      assert ["--version" | fetches] = calls
      assert Enum.any?(fetches, &(&1 =~ "/rpki/ta.cer "))
      assert Enum.count(fetches, &(&1 =~ ~r"/rpki/ ")) == 1
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
               run(["sync", "--cache", Path.join(tmp, "cache"), "--tal", dead, "--rsync", rsync])

      assert out =~ "fetch_failed (usage_error: rsync: unrecognized option `--info=skip1`)"
    end
  end

  describe "RRDP" do
    @describetag :rsync

    @tag rfc: "8182#3.4.5",
         doc: """
         m0-minimal-valid is served over RRDP and rsync. With --no-rrdp the
         only HTTPS request is the TA certificate's (the TAL's HTTPS URI
         comes first, RFC 8630 section 3); the repository comes from rsync
         and the summary has no rrdp line. The same sync without the flag
         reads the notification.
         """
    test "--no-rrdp fetches nothing over HTTPS but the TA certificate", %{tmp_dir: tmp} do
      fixture = Fixture.load!("m0-minimal-valid")
      {server, internal} = rrdp_served(tmp, fixture)
      cache = Path.join(tmp, "cache")

      assert {0, out, ""} = rrdp_sync(fixture, cache, internal, ["--no-rrdp"])
      assert RRDPServer.requested(server) == ["/rrdp/ta.cer"]
      assert out =~ "  rsync fetches: 1, 0 failed\n"
      refute out =~ "rrdp:"

      RRDPServer.serve(server, RRDPServer.routes(fixture))
      assert {0, out, ""} = rrdp_sync(fixture, Path.join(tmp, "other"), internal)
      assert "/rrdp/notification.xml" in RRDPServer.requested(server)
      assert out =~ "  rsync fetches: 0, 0 failed\n  rrdp: 1 repository: 1 snapshot\n"
    end

    @tag rfc: ["8182#3.4.1", "8182#3.4.5"],
         doc: """
         m8-rrdp-three synced four times into one cache: at serial 2 (the
         snapshot), at serial 3 (one delta), again (unchanged), and with the
         notification gone (failed; the point fetched with rsync, D-040).
         Each summary counts its repository under the right outcome and
         gives its line (#233: session, serials, download, bytes), and the
         failure is listed with its reason, as is the rsync fallback.
         """
    test "the summary counts RRDP repositories by outcome, and lists a failure with its reason",
         %{tmp_dir: tmp} do
      fixture = Fixture.load!("m8-rrdp-three")
      {server, internal} = rrdp_served(tmp, fixture, 2)
      cache = Path.join(tmp, "cache")
      notify = "https://localhost:8443/rrdp/notification.xml"

      assert {0, out, ""} = rrdp_sync(fixture, cache, internal)
      assert out =~ "  rrdp: 1 repository: 1 snapshot\n"
      line = "    #{notify}: session #{fixture.session_id}, serial"
      assert out =~ ~r/#{Regex.escape(line)} 2, snapshot \(first sync\), \d+(\.\d)? KiB\n/

      RRDPServer.serve(server, RRDPServer.routes(fixture))
      assert {0, out, ""} = rrdp_sync(fixture, cache, internal)
      assert out =~ "  rrdp: 1 repository: 1 deltas\n"
      assert out =~ ~r/#{Regex.escape(line)} 2 → 3, 1 delta, \d+ (B|KiB)\n/

      assert {0, out, ""} = rrdp_sync(fixture, cache, internal)
      assert out =~ "  rrdp: 1 repository: 1 unchanged\n"
      assert out =~ ~r/#{Regex.escape(line)} 3, unchanged, \d+ (B|KiB)\n/

      RRDPServer.serve(server, Map.delete(RRDPServer.routes(fixture), "/rrdp/notification.xml"))
      assert {0, out, ""} = rrdp_sync(fixture, cache, internal)

      assert out =~
               "  rsync fetches: 1, 0 failed\n  rrdp: 1 repository: 1 failed (rsync fallback)\n"

      assert out =~ "    rrdp_failed: #{notify} (notification_failed: http_status: 404)\n"
      assert out =~ "#{line} 3 kept, failed (notification_failed)\n"

      assert out =~
               "    rrdp_fallback: rsync://localhost:8873/rpki (RRDP #{notify} failed; fetched over rsync (D-040))\n"
    end

    @tag rfc: "8182#3.4.5",
         doc: """
         --rrdp-max-size 1K is smaller than m0-minimal-valid's snapshot: the
         RRDP sync fails as too large and the point comes from rsync.
         """
    test "--rrdp-max-size limits the snapshot downloaded", %{tmp_dir: tmp} do
      fixture = Fixture.load!("m0-minimal-valid")
      {_server, internal} = rrdp_served(tmp, fixture)

      assert {0, out, ""} =
               rrdp_sync(fixture, Path.join(tmp, "cache"), internal, ["--rrdp-max-size", "1K"])

      assert out =~ "  rrdp: 1 repository: 1 failed (rsync fallback)\n"
      assert out =~ "(snapshot_failed: too_large: 1024)\n"
    end

    @tag doc: """
         The notification is sent only after 2 s of silence; with
         --rrdp-idle-timeout 1 the RRDP sync gives up and rsync is used.
         """
    test "--rrdp-idle-timeout limits how long an RRDP download may go without data",
         %{tmp_dir: tmp} do
      fixture = Fixture.load!("m0-minimal-valid")
      {server, internal} = rrdp_served(tmp, fixture)
      notification = File.read!(Path.join(fixture.rrdp_root, "notification.xml"))

      silent =
        {:script,
         [
           {:sleep, 2_000},
           "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(notification)}\r\n\r\n",
           notification
         ]}

      RRDPServer.serve(
        server,
        Map.put(RRDPServer.routes(fixture), "/rrdp/notification.xml", silent)
      )

      assert {0, out, ""} =
               rrdp_sync(fixture, Path.join(tmp, "cache"), internal, ["--rrdp-idle-timeout", "1"])

      assert out =~ "  rrdp: 1 repository: 1 failed (rsync fallback)\n"
      assert out =~ "(notification_failed: timeout"
    end

    @tag rfc: ["8182#3.5.1.3", "9697#4"],
         doc: """
         Lumina.Sync.summary/1 on one walk that synced five repositories, one
         per outcome: the rrdp line counts each, in a fixed order, and each
         warning and failure is listed with its reason (D-042's session,
         RFC 9697's desync, a rejected delta, a cross-origin redirect).
         """
    test "the summary's rrdp line counts every outcome, and names each warning" do
      sync = fn outcome, host ->
        {:ok, notify} = Lumina.URI.parse("https://#{host}/n.xml")

        %{
          notify: notify,
          outcome: outcome,
          session_id: "s",
          serial: 2,
          previous: %{session_id: "s", serial: 1},
          bytes: 0,
          warnings: [],
          fallback: nil
        }
      end

      walk = %{
        fetches: [],
        points: [],
        rrdp: [
          sync.(:snapshot, "r0.example"),
          sync.({:deltas, 3}, "r1.example"),
          sync.(:unchanged, "r2.example"),
          sync.(:recent, "r3.example"),
          sync.({:failed, :cross_origin}, "r4.example")
        ],
        issues: [
          %{
            kind: :rrdp_warning,
            uri: "https://a.example/n.xml",
            detail: %{
              warnings: [
                %{rule: :session_not_v4, rfc: "8182#3.5.1.3", message: "not v4 (D-042)"},
                %{rule: :rrdp_desync, rfc: "9697#4", message: "delta 2 changed", serials: [2]}
              ],
              fallback: %{
                reason: :delta_rejected,
                error: %{rule: :withdraw_not_held, rfc: "8182#3.4.2", message: "no such object"}
              }
            }
          },
          %{
            kind: :rrdp_failed,
            uri: "https://b.example/n.xml",
            detail: %{
              reason: :cross_origin,
              error: %{
                reason: :cross_origin_redirect,
                uri: "https://b.example/s.xml",
                detail: "https://c.example/s.xml"
              }
            }
          }
        ]
      }

      summary =
        Lumina.Sync.summary([
          %{
            tal: "x.tal",
            ta: {:ok, %{uri: "https://t.example/ta.cer", attempts: []}},
            walk: walk,
            failed?: false
          }
        ])

      assert summary =~
               "  rrdp: 5 repositories: 1 snapshot, 1 deltas, 1 unchanged, 1 recent, 1 failed (rsync fallback)\n"

      assert summary =~
               "    rrdp_warning: https://a.example/n.xml (session_not_v4: not v4 (D-042); " <>
                 "rrdp_desync: delta 2 changed; delta_rejected: withdraw_not_held: no such object; snapshot used)\n"

      assert summary =~
               "    rrdp_failed: https://b.example/n.xml (cross_origin: cross_origin_redirect: https://c.example/s.xml)\n"

      assert summary =~ "5 RRDP repositories"
    end

    @tag rfc: ["8182#3.4.1", "8182#3.4.2", "8182#3.4.3", "9697#4"],
         doc: """
         Lumina.Sync.summary/1 on one walk that synced a repository per case
         (#233, D-048): each gets a line, sorted by notification URI, with
         its session_id, the serial before and after, the deltas applied or
         the snapshot and why it was used (first sync, a new session, deltas
         not listed, an RFC 9697 desync, a rejected delta), and the bytes
         received; unchanged and recent ones too, and a failed one with the
         serial its store keeps, if any.
         """
    test "the summary has a line per RRDP repository with its session, serials and download" do
      a = "5d8a3f0e-6b1c-4e2a-9f7d-2c4b8e1a0d93"
      b = "0b7e2c91-4f3a-4d6b-8e15-9a2f6c3d7e48"

      sync = fn host, outcome, previous, serial, more ->
        {:ok, notify} = Lumina.URI.parse("https://#{host}/n.xml")

        Map.merge(
          %{
            notify: notify,
            outcome: outcome,
            session_id: a,
            serial: serial,
            previous: previous && %{session_id: a, serial: previous},
            bytes: 0,
            warnings: [],
            fallback: nil
          },
          more
        )
      end

      desync = %{rule: :rrdp_desync, rfc: "9697#4", message: "delta 2 changed", serials: [2]}
      rejected = %{reason: :delta_hash_mismatch, error: %{rule: :delta_hash_mismatch}}

      rrdp = [
        sync.("r9.example", {:failed, :notification_failed}, nil, nil, %{}),
        sync.("r0.example", :snapshot, nil, 812, %{bytes: 37_119_590}),
        sync.("r1.example", {:deltas, 6}, 41_230, 41_236, %{bytes: 1_258_291}),
        sync.("r2.example", {:deltas, 1}, 7, 8, %{bytes: 900}),
        sync.("r3.example", :snapshot, 5, 1, %{
          session_id: b,
          previous: %{session_id: a, serial: 5},
          bytes: 4096
        }),
        sync.("r4.example", :snapshot, 10, 20, %{bytes: 2048}),
        sync.("r5.example", :snapshot, 10, 11, %{bytes: 2048, warnings: [desync]}),
        sync.("r6.example", :snapshot, 10, 11, %{bytes: 2048, fallback: rejected}),
        sync.("r7.example", :unchanged, 77, 77, %{bytes: 512}),
        sync.("r8.example", :recent, 77, 77, %{}),
        sync.("r8b.example", {:failed, :serial_not_greater}, 9, 9, %{bytes: 300})
      ]

      summary =
        Lumina.Sync.summary([
          %{
            tal: "x.tal",
            ta: {:ok, %{uri: "https://t.example/ta.cer", attempts: []}},
            walk: %{fetches: [], points: [], rrdp: rrdp, issues: []},
            failed?: false
          }
        ])

      assert summary =~
               """
                 rrdp: 11 repositories: 5 snapshot, 2 deltas, 1 unchanged, 1 recent, 2 failed (rsync fallback)
                   https://r0.example/n.xml: session #{a}, serial 812, snapshot (first sync), 35.4 MiB
                   https://r1.example/n.xml: session #{a}, serial 41230 → 41236, 6 deltas, 1.2 MiB
                   https://r2.example/n.xml: session #{a}, serial 7 → 8, 1 delta, 900 B
                   https://r3.example/n.xml: session #{b} (new session), serial 1, snapshot, 4 KiB
                   https://r4.example/n.xml: session #{a}, serial 10 → 20, snapshot (deltas not listed), 2 KiB
                   https://r5.example/n.xml: session #{a}, serial 10 → 11, snapshot (RFC 9697 desync), 2 KiB
                   https://r6.example/n.xml: session #{a}, serial 10 → 11, snapshot (delta_hash_mismatch, deltas not used), 2 KiB
                   https://r7.example/n.xml: session #{a}, serial 77, unchanged, 512 B
                   https://r8.example/n.xml: session #{a}, serial 77, recent
                   https://r8b.example/n.xml: session #{a}, serial 9 kept, failed (serial_not_greater), 300 B
                   https://r9.example/n.xml: failed (notification_failed)
               """
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

    test "a bad --rrdp-max-size or --rrdp-idle-timeout is a usage error", %{tmp_dir: tmp} do
      cache = Path.join(tmp, "cache")

      for bad <- ["0", "-1", "2T", "1.5G", "lots", "M"] do
        assert {2, "", err} = run(["sync", "--cache", cache, "--rrdp-max-size", bad])
        assert err =~ "--rrdp-max-size must be a size such as 500M, 2G or a number of bytes", bad
      end

      assert {2, "", err} = run(["sync", "--cache", cache, "--rrdp-idle-timeout", "0"])
      assert err =~ "--rrdp-idle-timeout must be at least 1"
      assert {2, "", err} = run(["sync", "--cache", cache, "--rrdp-idle-timeout", "soon"])
      assert err =~ "unknown or invalid flag --rrdp-idle-timeout"
      refute File.exists?(cache)
    end

    test "an empty TAL folder without --tal is a usage error", %{tmp_dir: tmp} do
      assert {2, "", err} =
               run(["sync", "--cache", Path.join(tmp, "cache")], tal_dir: Path.join(tmp, "none"))

      assert err =~ "no .tal files in"
    end

    test "lumina help sync describes the flags and exit codes" do
      assert {0, out, ""} = run(["help", "sync"])
      assert out =~ "Usage: lumina sync [--cache DIR] [--tal FILE]..."

      for flag <- [
            "--cache DIR",
            "--tal FILE",
            "--timeout SECONDS",
            "--max-depth N",
            "--per-host N",
            "--rsync PATH",
            "--no-rrdp",
            "--rrdp-max-size SIZE",
            "--rrdp-idle-timeout SECONDS"
          ],
          do: assert(out =~ flag)

      assert out =~
               "Exit codes: 0 each trust anchor and its own publication point fetched"

      assert {0, ^out, ""} = run(["sync", "--help"])
    end

    test "lumina help lists sync" do
      assert {0, out, ""} = run(["help"])
      assert out =~ "sync      fetch the trust anchors and repositories"
    end
  end
end
