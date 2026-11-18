defmodule Lumina.M8DoneTest do
  @moduledoc """
  The end-to-end check that closes M8, RRDP (#209): "results match rsync
  on the same repository, and desync fixtures pass". It checks the
  decisions D-040 (rsync fallback in the same run), D-041 (the strict
  streaming parser), D-042 (a session that isn't a version 4 UUID only
  warns), D-043 (download limits) and D-046 (a snapshot publishing a URI
  twice is rejected) together.

    * Every Barry fixture is synced twice with `lumina sync`: over RRDP
      only (`Lumina.Test.RRDPServer`, every rsync host unreachable) and
      over rsync only (`--no-rrdp`, rsync daemons). `lumina validate` and
      `lumina vrps` give the same output and exit code for both caches,
      apart from the transport counts.
    * The RRDP sync cases in `test/fixtures/rrdp/sync/` (the RFC 9697
      desync, a new session, a serial gap, each snapshot and delta
      rejection, the cross-origin cases of RFC 9674) each give the
      outcome their metadata states.
    * RFC 8182 §3.4 and §3.5, RFC 9674 §3 and RFC 9697 §3 to §5 are
      covered by tests other than this one.
    * Tagged `:network`, run by hand only (`mix test --only network`): the
      five RIR TALs synced over RRDP and with `--no-rrdp`, their VRPs
      compared per trust anchor and with Routinator's live CSV (D-035),
      and a second RRDP sync right after the first, which should download
      little.

  The pieces are tested in detail elsewhere (`Lumina.RRDP.SyncTest`,
  `SyncDeltasTest`, `SyncPollingTest`, `WalkRRDPTest`,
  `ValidateSourceTest`, `CLISyncTest`). This module checks that they hold
  together, over all the data at once, and against the live repositories.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Lumina.{CLI, VRPCompare}
  alias Lumina.RRDP.{Snapshot, State}
  alias Lumina.Test.{Fixture, RRDPServer, RsyncDaemon}
  alias Mix.Lumina.{Fixtures, RFC, TestScanner}

  @moduletag :tmp_dir
  @now "2030-01-01T00:00:00Z"
  @base "https://localhost:8443/rrdp/"
  @cases "test/fixtures/rrdp/sync"

  # Fixture directories published on a second rsync host (as in
  # M7DoneTest): the directory under rsync/ and the authority the
  # certificates name, module "repo". Their RRDP repository holds them too.
  @elsewhere %{
    "m3-walk-delegation" => {"other", "other.example:8873"},
    "m3-walk-unreachable" => {"unreachable", "unreachable.invalid"},
    "m3-walk-silent-branch" => {"silent", "silent.example:8873"}
  }

  # The one fixture whose RRDP files aren't its rsync tree: Barry publishes
  # its overridden CRL URI (ta/missing.crl) in the snapshot but writes the
  # file as ta/ta.crl in rsync/ (F-043).
  @transports_differ ["m4-chain-crl-missing"]

  # The trust anchors of tals/, as the reference names them.
  @rirs ["afrinic", "apnic", "arin", "lacnic", "ripe"]

  defp run(args, internal) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(Lumina.Test.Quiet.args(args), out, err, internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  defp closed, do: "127.0.0.1:#{RsyncDaemon.closed_port()}"

  # The internal options of a sync of `fixture` with RRDP on, as outside
  # tests: its RRDP server, and its rsync hosts at `rsync` (host => authority).
  defp internal(server, rsync) do
    {:ok, now, 0} = DateTime.from_iso8601(@now)

    [
      now: now,
      rrdp: true,
      rrdp_opts: [cacerts: server.opts[:cacerts], min_interval: 0],
      remap: Map.merge(server.opts[:remap], rsync),
      https: [cacerts: server.opts[:cacerts], remap: server.opts[:remap]]
    ]
  end

  # Every rsync host `fixture` names, served by daemons.
  defp daemons(work, fixture) do
    main = RsyncDaemon.start!(Path.join(work, "daemon"), fixture.modules)

    case @elsewhere[fixture.id] do
      {dir, other} ->
        served = %{"repo" => Path.join(fixture.rsync_root, dir)}
        port = RsyncDaemon.start!(Path.join(work, dir), served).port
        %{"localhost:8873" => "127.0.0.1:#{main.port}", other => "127.0.0.1:#{port}"}

      nil ->
        %{"localhost:8873" => "127.0.0.1:#{main.port}"}
    end
  end

  # Every rsync host `fixture` names, unreachable.
  defp unreachable(fixture) do
    case @elsewhere[fixture.id] do
      {_dir, other} -> %{"localhost:8873" => closed(), other => closed()}
      nil -> %{"localhost:8873" => closed()}
    end
  end

  # lumina validate and lumina vrps on `cache`: the exit codes and outputs,
  # and the counts of points read from RRDP and from rsync.
  defp results(fixture, cache) do
    args = ["--cache", cache, "--tal", fixture.tal_path, "--now", @now]
    {validate_code, validate, _} = run(["validate" | args], [])
    {vrps_code, vrps, _} = run(["vrps" | args], [])

    counts =
      Regex.scan(~r/publication points: \d+: (\d+) from RRDP, (\d+) from rsync/, validate)
      |> Enum.map(fn [_, rrdp, rsync] -> {String.to_integer(rrdp), String.to_integer(rsync)} end)

    without_counts =
      String.replace(
        validate,
        ~r/(publication points: \d+): \d+ from RRDP, \d+ from rsync/,
        "\\1"
      )

    {{validate_code, without_counts, vrps_code, vrps}, counts}
  end

  @tag :rsync
  @tag rfc: ["8182#3.4.3", "8182#3.4.5", "6481#5"],
       doc: """
       Driven by the fixture metadata, at 2030-01-01: every fixture synced
       with lumina sync into two caches, over RRDP only (each rsync host it
       names at a closed port) and over rsync only (--no-rrdp; a daemon per
       host). lumina validate and lumina vrps give the same exit codes and
       output for both, but for the line counting points by transport:
       every point of the first cache read from RRDP, of the second from
       rsync. m4-chain-crl-missing is left out: Barry publishes its CRL at
       another URI over RRDP than in rsync (F-043).
       """
  # Syncs every fixture twice; the done tests run at the same time (async).
  @tag timeout: :timer.minutes(10)
  test "every fixture validates the same over RRDP and over rsync", %{tmp_dir: tmp} do
    {fixtures, []} = Fixtures.load_all()

    points =
      for %{id: id} <- fixtures, id not in @transports_differ, fixture = Fixture.load!(id) do
        work = Path.join(tmp, id)
        server = RRDPServer.start!(RRDPServer.routes(fixture))
        sync = ["sync", "--tal", fixture.tal_path, "--cache"]

        rrdp = Path.join(work, "rrdp")
        _ = run(sync ++ [rrdp], internal(server, unreachable(fixture)))
        rsync = Path.join(work, "rsync")
        _ = run(sync ++ [rsync, "--no-rrdp"], internal(server, daemons(work, fixture)))

        {over_rrdp, rrdp_counts} = results(fixture, rrdp)
        {over_rsync, rsync_counts} = results(fixture, rsync)

        assert over_rrdp == over_rsync, id
        assert Enum.all?(rrdp_counts, &match?({_, 0}, &1)), "#{id}: #{inspect(rrdp_counts)}"
        assert Enum.all?(rsync_counts, &match?({0, _}, &1)), "#{id}: #{inspect(rsync_counts)}"

        rrdp_counts |> Enum.map(&elem(&1, 0)) |> Enum.sum()
      end

    assert length(points) >= 90
    # Most fixtures have a valid trust anchor, so points to read.
    assert Enum.count(points, &(&1 > 0)) >= 80
  end

  # The RRDP sync cases.

  defp three, do: Fixture.load!("m8-rrdp-three")
  defp read(fixture, name), do: File.read!(Path.join(fixture.rrdp_root, name))

  defp notification_route(xml), do: {200, [], xml}

  # The notification at serial 3, with its real snapshot and `deltas`
  # (`{serial, bytes}`), from `routes`, under `session`.
  defp at_three(fixture, routes, deltas, snapshot \\ nil, session \\ nil) do
    snapshot = snapshot || read(fixture, "snapshot.xml")

    xml =
      RRDPServer.notification(
        session || fixture.session_id,
        3,
        {@base <> "snapshot.xml", snapshot},
        for({k, bytes} <- deltas, do: {k, @base <> "delta-#{k}.xml", bytes})
      )

    routes
    |> Map.put("/rrdp/notification.xml", notification_route(xml))
    |> Map.put("/rrdp/snapshot.xml", {200, [], snapshot})
  end

  # The fixture's notification at 3 listing deltas 2 and 3, with delta 3
  # replaced by `delta`.
  defp with_delta(fixture, delta) do
    fixture
    |> at_three(RRDPServer.routes(fixture), [{2, read(fixture, "delta-2.xml")}, {3, delta}])
    |> Map.put("/rrdp/delta-3.xml", {200, [], delta})
  end

  defp elsewhere, do: {302, [{"location", "https://other.example/rrdp/file.xml"}], ""}

  # The objects of the fixture's snapshot at serial 2, which the store
  # holds before a case's sync: `[{uri, bytes}]`.
  defp held(fixture) do
    path = Path.join(fixture.rrdp_root, "snapshot-2.xml")
    expected = %{session_id: fixture.session_id, serial: 2}
    collect = fn {:publish, uri, bytes}, acc -> {:cont, [{to_string(uri), bytes} | acc]} end
    {:ok, objects} = Snapshot.stream(path, expected, collect, [])
    Enum.reverse(objects)
  end

  @absent "rsync://localhost:8873/rpki/absent.roa"

  # The files each case serves, from the fixture's own with one change
  # (see cases.exs).
  defp serve("mutated-delta-hash", f) do
    deltas = [{2, "mutated " <> read(f, "delta-2.xml")}, {3, read(f, "delta-3.xml")}]
    at_three(f, RRDPServer.routes(f), deltas)
  end

  defp serve("unchanged-hashes", f), do: RRDPServer.routes(f)

  defp serve("new-session", f) do
    session = "4f6c1b6e-2b8a-4c3e-9d2f-1a2b3c4d5e6f"

    snapshot =
      f
      |> read("snapshot.xml")
      |> String.replace(f.session_id, session)
      |> String.replace(~s(serial="3"), ~s(serial="1"))

    xml = RRDPServer.notification(session, 1, {@base <> "snapshot-new.xml", snapshot})

    RRDPServer.routes(f)
    |> Map.put("/rrdp/notification.xml", notification_route(xml))
    |> Map.put("/rrdp/snapshot-new.xml", {200, [], snapshot})
  end

  defp serve("serial-gap", f),
    do: at_three(f, RRDPServer.routes(f), [{3, read(f, "delta-3.xml")}])

  defp serve("serial-lower", f), do: RRDPServer.routes(f, 2)
  defp serve("serial-same", f), do: RRDPServer.routes(f)

  defp serve("notification-missing", f),
    do: Map.delete(RRDPServer.routes(f), "/rrdp/notification.xml")

  defp serve("notification-invalid", f) do
    xml = String.replace(read(f, "notification.xml"), ~s(version="1"), ~s(version="2"))
    Map.put(RRDPServer.routes(f), "/rrdp/notification.xml", notification_route(xml))
  end

  defp serve("snapshot-hash-mismatch", f) do
    xml = RRDPServer.notification(f.session_id, 3, {@base <> "snapshot.xml", "another file"})
    Map.put(RRDPServer.routes(f), "/rrdp/notification.xml", notification_route(xml))
  end

  defp serve("snapshot-session-mismatch", f) do
    other = "0b5c6e1a-7d2f-4e3b-8a9c-1d2e3f4a5b6c"

    at_three(
      f,
      RRDPServer.routes(f),
      [],
      String.replace(read(f, "snapshot.xml"), f.session_id, other)
    )
  end

  defp serve("snapshot-serial-mismatch", f),
    do:
      at_three(
        f,
        RRDPServer.routes(f),
        [],
        String.replace(read(f, "snapshot.xml"), ~s(serial="3"), ~s(serial="4"))
      )

  defp serve("snapshot-duplicate-publish", f) do
    snapshot = read(f, "snapshot.xml")
    [_, uri] = Regex.run(~r/<publish uri="([^"]+)"/, snapshot)
    again = ~s(<publish uri="#{uri}">#{Base.encode64("other content")}</publish>\n</snapshot>)
    at_three(f, RRDPServer.routes(f), [], String.replace(snapshot, "</snapshot>", again))
  end

  defp serve("delta-hash-mismatch", f) do
    f
    |> with_delta(read(f, "delta-3.xml"))
    |> Map.put("/rrdp/delta-3.xml", {200, [], "another file"})
  end

  defp serve("delta-session-mismatch", f) do
    other = "0b5c6e1a-7d2f-4e3b-8a9c-1d2e3f4a5b6c"
    with_delta(f, String.replace(read(f, "delta-3.xml"), f.session_id, other))
  end

  defp serve("delta-serial-mismatch", f),
    do: with_delta(f, String.replace(read(f, "delta-3.xml"), ~s(serial="3"), ~s(serial="4")))

  defp serve("delta-withdraw-not-held", f),
    do: with_delta(f, RRDPServer.delta(f.session_id, 3, [{:withdraw, @absent, "anything"}]))

  defp serve("delta-withdraw-hash-mismatch", f) do
    [{uri, _}, {_, other} | _] = held(f)
    with_delta(f, RRDPServer.delta(f.session_id, 3, [{:withdraw, uri, other}]))
  end

  defp serve("delta-replace-not-held", f),
    do: with_delta(f, RRDPServer.delta(f.session_id, 3, [{:publish, @absent, "new", "old"}]))

  defp serve("delta-replace-hash-mismatch", f) do
    [{uri, _}, {_, other} | _] = held(f)
    with_delta(f, RRDPServer.delta(f.session_id, 3, [{:publish, uri, "new", other}]))
  end

  defp serve("delta-publish-without-hash", f) do
    [{uri, _} | _] = held(f)
    with_delta(f, RRDPServer.delta(f.session_id, 3, [{:publish, uri, "new"}]))
  end

  defp serve("notification-cross-origin-uri", f) do
    xml =
      String.replace(
        read(f, "notification.xml"),
        ~s(uri="https://localhost:8443/rrdp/snapshot.xml"),
        ~s(uri="https://other.example/rrdp/snapshot.xml")
      )

    Map.put(RRDPServer.routes(f), "/rrdp/notification.xml", notification_route(xml))
  end

  defp serve("notification-cross-origin-redirect", f),
    do: Map.put(RRDPServer.routes(f), "/rrdp/notification.xml", elsewhere())

  defp serve("snapshot-cross-origin-redirect", f),
    do: f |> at_three(RRDPServer.routes(f), []) |> Map.put("/rrdp/snapshot.xml", elsewhere())

  defp serve("delta-cross-origin-redirect", f),
    do: Map.put(RRDPServer.routes(f), "/rrdp/delta-3.xml", elsewhere())

  # The rule or reason of an RRDP or HTTPS error.
  defp rule(%{rule: rule}), do: rule
  defp rule(%{reason: reason}), do: reason
  defp rule(other), do: other

  @tag rfc: ["8182#3.4.1", "8182#3.4.2", "8182#3.4.3", "9674#3.2", "9697#4"],
       doc: """
       Driven by test/fixtures/rrdp/sync/cases.exs: for each case, the store
       is synced to its `from` serial of m8-rrdp-three from the fixture's
       own files, then the case's files are served and synced. The outcome,
       the reason a delta gave way to the snapshot, the rule of the error
       behind a failure, the warning, and the store afterwards (the final
       snapshot's files, or as it was) are those the metadata states.
       """
  test "every RRDP sync case gives the outcome its metadata states", %{tmp_dir: tmp} do
    {cases, []} = Code.eval_file(Path.join(@cases, "cases.exs"))
    fixture = three()

    for %{id: id, from: from, expected: expected} = c <- cases do
      assert c.rationale != "" and c.rfc != [], id
      server = RRDPServer.start!(RRDPServer.routes(fixture, from))
      root = Path.join(tmp, id)

      assert %{outcome: :snapshot, serial: ^from} =
               Lumina.RRDP.sync(fixture.notification_uri, root, server.opts)

      before = RRDPServer.store_files(root, fixture.notification_uri)
      RRDPServer.serve(server, serve(id, fixture))

      {result, _log} =
        with_log(fn -> Lumina.RRDP.sync(fixture.notification_uri, root, server.opts) end)

      assert result.outcome == expected.outcome, "#{id}: #{inspect(result)}"
      assert (result.fallback && result.fallback.reason) == expected[:fallback], id

      if error = expected[:error] do
        behind = if result.fallback, do: result.fallback.error, else: result.error
        assert rule(behind) == error, "#{id}: #{inspect(behind)}"
      end

      if warning = expected[:warning],
        do: assert(Enum.any?(result.warnings, &(&1[:rule] == warning)), id)

      after_sync = RRDPServer.store_files(root, fixture.notification_uri)

      case expected.store do
        :snapshot -> assert after_sync == RRDPServer.snapshot_files(fixture), id
        :kept -> assert after_sync == before, id
      end

      # A failure keeps the state too, but for the attempt.
      if match?({:failed, _}, result.outcome),
        do: assert(State.load(root, fixture.notification_uri).serial == from, id)
    end

    ids = Enum.map(cases, & &1.id)
    assert ids == Enum.uniq(ids)
    assert length(cases) >= 20
  end

  @tag doc: """
       The coverage mix lumina.rfc_coverage reports, computed the same way,
       ignoring this module's own tags. A section counts as covered by a
       test of it or of one of its subsections.
       """
  test "RFC 8182 §3.4 and §3.5, RFC 9674 §3 and RFC 9697 §3 to §5 are covered by other tests" do
    {modules, []} = TestScanner.scan_dir("test")

    covered =
      for test <- TestScanner.tests(modules),
          test.module != inspect(__MODULE__),
          string <- test.refs,
          {:ok, %{rfc: rfc, section: section}} <- [RFC.parse(string)],
          do: {rfc, section}

    sections = [
      {8182, "3.4"},
      {8182, "3.4.1"},
      {8182, "3.4.2"},
      {8182, "3.4.3"},
      {8182, "3.4.4"},
      {8182, "3.4.5"},
      {8182, "3.5"},
      {8182, "3.5.1"},
      {8182, "3.5.2"},
      {8182, "3.5.3"},
      {8182, "3.5.4"},
      {9674, "3"},
      {9697, "3"},
      {9697, "4"},
      {9697, "5"}
    ]

    for {rfc, section} <- sections do
      assert Enum.any?(covered, fn {r, s} ->
               r == rfc and (s == section or String.starts_with?(s, section <> "."))
             end),
             "RFC #{rfc} §#{section} isn't covered"
    end
  end

  describe "the five RIRs" do
    @describetag :network
    @describetag timeout: :timer.minutes(180)

    @tag rfc: ["8182#3.4.1", "8182#3.4.5", "6481#5"],
         doc: """
         Run by hand: mix test --only network. Needs the Internet; takes
         many minutes. Syncs every TAL in tals/ into an empty cache over
         RRDP, as lumina does by default, and into another with --no-rrdp;
         writes both caches' VRPs; and compares them per trust anchor, and
         the RRDP ones with Routinator's live CSV, each within D-035's 1%.
         Then syncs the RRDP cache again right away: most repositories must
         need no snapshot (deltas, unchanged, or recent). Prints the run
         times, the RRDP repositories by outcome, the fallbacks, and any
         snapshot rejected for publishing a URI twice (D-046, F-041), which
         the maintainer wants to hear of.
         """
    test "the five RIRs over RRDP agree with rsync and with Routinator, and resync cheaply", %{
      tmp_dir: tmp
    } do
      rrdp = Path.join(tmp, "rrdp")
      rsync = Path.join(tmp, "rsync")
      on = [rrdp: true]

      {rrdp_time, {code, first, _}} = timed(fn -> run(["sync", "--cache", rrdp], on) end)
      File.write!(Path.join(tmp, "sync-rrdp.txt"), first)
      assert code == 0, first

      {rsync_time, {code, rsync_out, _}} =
        timed(fn -> run(["sync", "--cache", rsync, "--no-rrdp"], []) end)

      File.write!(Path.join(tmp, "sync-rsync.txt"), rsync_out)
      assert code == 0, rsync_out

      {again_time, {code, again, _}} = timed(fn -> run(["sync", "--cache", rrdp], on) end)
      File.write!(Path.join(tmp, "sync-rrdp-again.txt"), again)
      assert code == 0, again

      over_rrdp = vrps!(rrdp, Path.join(tmp, "rrdp.csv"))
      over_rsync = vrps!(rsync, Path.join(tmp, "rsync.csv"))

      # compare/2 renames the first side's trust anchors as Routinator
      # names them (ripe-ncc is ripe); the second side needs it too here.
      over_rsync = %{
        over_rsync
        | vrps: Map.new(over_rsync.vrps, fn {ta, set} -> {VRPCompare.reference_name(ta), set} end)
      }

      transports =
        over_rrdp |> VRPCompare.compare(over_rsync) |> Enum.filter(&(&1.ta in @rirs))

      reference = compare(over_rrdp)

      reference =
        if Enum.all?(reference, &within?/1) do
          reference
        else
          IO.puts("Outside the 1% bound; downloading the reference again:\n" <> report(reference))
          compare(over_rrdp)
        end

      first_outcomes = outcomes(first)
      again_outcomes = outcomes(again)

      duplicates =
        for line <- String.split(first <> again, "\n"), line =~ "duplicate_publish", do: line

      IO.puts("""

      sync over RRDP: #{rrdp_time} s, with --no-rrdp: #{rsync_time} s, RRDP again: #{again_time} s
      RRDP repositories, first sync: #{inspect(first_outcomes)}
      RRDP repositories, again: #{inspect(again_outcomes)}
      fallbacks (first sync): #{count(first, "    rrdp_fallback: ")} publication points, \
      #{count(first, "    rrdp_failed: ")} repositories failed
      #{Enum.join(lines(first, "    rrdp_failed: "), "\n")}
      D-046 (a snapshot publishing a URI twice): \
      #{if duplicates == [], do: "none", else: "\n" <> Enum.join(duplicates, "\n")}

      RRDP against --no-rrdp:
      #{report(transports)}

      RRDP against Routinator:
      #{report(reference)}\
      """)

      assert Enum.map(transports, & &1.ta) == @rirs
      assert Enum.map(reference, & &1.ta) == @rirs

      for r <- transports ++ reference do
        assert r.lumina > 0 and r.reference > 0, r.ta
        assert within?(r), report([r])
      end

      total = again_outcomes |> Map.values() |> Enum.sum()

      cheap =
        Map.take(again_outcomes, ["deltas", "unchanged", "recent"]) |> Map.values() |> Enum.sum()

      assert total > 0
      assert cheap * 2 > total, inspect(again_outcomes)
    end
  end

  defp timed(fun) do
    started = System.monotonic_time(:second)
    result = fun.()
    {System.monotonic_time(:second) - started, result}
  end

  defp vrps!(cache, csv) do
    {code, _out, err} = run(["vrps", "--cache", cache, "--output", csv], [])
    assert code == 0, err
    {:ok, vrps} = VRPCompare.parse(File.read!(csv))
    assert vrps.malformed == []
    vrps
  end

  # The RRDP repositories of a sync summary by outcome, over every TAL.
  defp outcomes(summary) do
    for [_, list] <- Regex.scan(~r/  rrdp: \d+ repositor(?:y|ies): (.*)\n/, summary),
        part <- String.split(list, ", "),
        [n, outcome] = String.split(part, " ", parts: 2),
        reduce: %{} do
      acc ->
        outcome = String.replace_suffix(outcome, " (rsync fallback)", "")
        Map.update(acc, outcome, String.to_integer(n), &(&1 + String.to_integer(n)))
    end
  end

  defp lines(summary, prefix),
    do: summary |> String.split("\n") |> Enum.filter(&String.starts_with?(&1, prefix))

  defp count(summary, prefix), do: length(lines(summary, prefix))

  # The comparison with a fresh download of the reference, for the five
  # RIRs.
  defp compare(ours) do
    {:ok, text} = VRPCompare.fetch()
    {:ok, reference} = VRPCompare.parse(text)
    ours |> VRPCompare.compare(reference) |> Enum.filter(&(&1.ta in @rirs))
  end

  # At most 1% of each side's VRPs only on that side (D-035).
  defp within?(%{lumina: ours, reference: theirs} = r)
       when is_integer(ours) and is_integer(theirs),
       do: length(r.only_lumina) * 100 <= ours and length(r.only_reference) * 100 <= theirs

  defp within?(_result), do: false

  defp report(results), do: VRPCompare.report(results, 20)
end
