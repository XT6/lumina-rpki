defmodule Lumina.CLICleanTest do
  @moduledoc """
  Tests `lumina clean` (#226, D-047) through `Lumina.CLI.run/4`, on caches
  filled by real syncs of Barry fixtures (rsync daemons, and
  `Lumina.Test.RRDPServer` for RRDP): without `--tal` the whole cache is
  emptied; with `--tal` only what that TAL's tree used goes, and what
  another TAL's tree also uses stays; a TAL never synced only warns; it
  asks before removing anything, `--force` doesn't, and without a
  terminal to ask on nothing is removed; a locked cache is left alone.

  The answer is read from the `:input` device and whether it is a
  terminal comes from `:interactive`, both internal options, so the
  question can be tested without one.
  """
  use ExUnit.Case, async: true

  alias Lumina.CLI
  alias Lumina.Test.{Fixture, RRDPServer, RsyncDaemon}

  @moduletag :tmp_dir
  @now ~U[2026-11-13 12:00:00Z]

  defp run(args, internal \\ []) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(args, out, err, [now: @now] ++ internal)
    {code, elem(StringIO.contents(out), 1), elem(StringIO.contents(err), 1)}
  end

  defp clean(cache, flags, internal \\ []),
    do: run(["clean", "--cache", cache] ++ flags, internal)

  # Fixture `id` served by its own rsync daemon, with a TAL in `dir` whose
  # only URI is at that daemon; synced into `cache` with rsync only.
  defp rsync_synced(tmp, id, cache) do
    fixture = Fixture.load!(id)
    daemon = RsyncDaemon.start!(Path.join(tmp, "daemon-" <> id), fixture.modules)
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

    tal = Path.join([tmp, "tals", id <> ".tal"])
    File.mkdir_p!(Path.dirname(tal))
    File.write!(tal, text)

    internal = [remap: %{"localhost:8873" => authority}]
    assert {0, _, _} = run(["sync", "--quiet", "--cache", cache, "--tal", tal], internal)
    tal
  end

  # Fixture `id` served over RRDP and rsync, synced into `cache` with RRDP.
  defp rrdp_synced(tmp, id, cache) do
    fixture = Fixture.load!(id)
    server = RRDPServer.start!(RRDPServer.routes(fixture))
    daemon = RsyncDaemon.start!(Path.join(tmp, "daemon-" <> id), fixture.modules)

    internal = [
      rrdp: true,
      rrdp_opts: [cacerts: server.opts[:cacerts], min_interval: 0],
      remap: Map.put(server.opts[:remap], "localhost:8873", "127.0.0.1:#{daemon.port}"),
      https: [cacerts: server.opts[:cacerts], remap: server.opts[:remap]]
    ]

    assert {0, out, _} =
             run(["sync", "--quiet", "--cache", cache, "--tal", fixture.tal_path], internal)

    assert out =~ "rrdp: 1 repository: 1 snapshot\n"
    fixture.tal_path
  end

  defp validate(cache, tal),
    do:
      run([
        "validate",
        "--quiet",
        "--cache",
        cache,
        "--tal",
        tal,
        "--now",
        "2030-01-01T00:00:00Z"
      ])

  # Every regular file under `dir`, relative to it, but the lock.
  defp files(dir) do
    dir
    |> Path.join("**")
    |> Path.wildcard(match_dot: true)
    |> Enum.filter(&File.regular?/1)
    |> Enum.map(&Path.relative_to(&1, dir))
    |> Enum.sort()
  end

  @tag :rsync
  @tag doc: """
       m0-minimal-valid synced, plus a directory no TAL uses (as a TAL
       removed from ./tals/ leaves). clean --force empties the cache
       directory but keeps it, and validate then finds no TA.
       """
  test "without --tal, --force empties the whole cache, files no TAL uses included",
       %{tmp_dir: tmp} do
    cache = Path.join(tmp, "cache")
    tal = rsync_synced(tmp, "m0-minimal-valid", cache)
    File.mkdir_p!(Path.join(cache, "rsync/gone.example/old"))
    File.write!(Path.join(cache, "rsync/gone.example/old/x.cer"), "stale")
    count = length(files(cache))

    assert {0, out, ""} = clean(cache, ["--force"])

    assert out =~
             ~r/\A#{Regex.escape(cache)}: removed everything: #{count} files, \d+ (B|KiB)\n\z/

    assert File.ls!(cache) == []

    assert {1, out, _} = validate(cache, tal)
    assert out =~ "  ta: none in the cache; run lumina sync first\n"
  end

  @tag :rsync
  @tag rfc: "8182#3.4.2",
       doc: """
       m8-rrdp-three synced over RRDP alone. clean --tal removes its TA,
       sync record, RRDP store and state, and its points' source, last
       valid and manifest records: nothing is left.
       """
  test "--tal removes the TAL's trust anchor, RRDP repository and point records",
       %{tmp_dir: tmp} do
    cache = Path.join(tmp, "cache")
    tal = rrdp_synced(tmp, "m8-rrdp-three", cache)

    for dir <- ~w(.ta rrdp .state/rrdp .state/sources .state/manifests .state/syncs .valid),
        do: assert(files(Path.join(cache, dir)) != [], dir)

    assert {0, out, ""} = clean(cache, ["--tal", tal, "--force"])
    assert out =~ "  #{tal}: 1 trust anchor, 1 rsync module, 1 RRDP repository, "
    assert files(cache) == []
  end

  @tag :rsync
  @tag doc: """
       m3-walk-siblings (modules rpki and s1 to s8) synced with rsync, then
       m8-rrdp-three over RRDP into the same cache. Both trees have
       points in the module rpki, and its TA's manifest is at the same
       URI. clean --tal m3-walk-siblings removes its TA and s1 to s8,
       keeps rpki, the shared point's records and m8-rrdp-three's RRDP
       repository, and m8-rrdp-three still validates the same.
       """
  test "--tal keeps what another TAL's tree uses, and that TAL still validates the same",
       %{tmp_dir: tmp} do
    cache = Path.join(tmp, "cache")
    siblings = rsync_synced(tmp, "m3-walk-siblings", cache)
    three = rrdp_synced(tmp, "m8-rrdp-three", cache)
    before = validate(cache, three)
    assert {0, _, _} = before
    modules = Path.join(cache, "rsync/localhost:8873")
    assert length(File.ls!(modules)) == 9

    assert {0, out, ""} = clean(cache, ["--tal", siblings, "--force"])
    assert out =~ "  #{siblings}: 1 trust anchor, 8 rsync modules, "
    assert out =~ "; kept 1 repository another TAL uses\n"

    assert File.ls!(modules) == ["rpki"]
    assert {1, out, _} = validate(cache, siblings)
    assert out =~ "  ta: none in the cache; run lumina sync first\n"
    assert validate(cache, three) == before
  end

  @tag :rsync
  test "a TAL never synced warns and exits 0, and the others are cleaned", %{tmp_dir: tmp} do
    cache = Path.join(tmp, "cache")
    synced = rsync_synced(tmp, "m0-minimal-valid", cache)
    never = Fixture.load!("m1-roa-prefixes").tal_path

    assert {0, out, err} = clean(cache, ["--tal", never, "--tal", synced, "--force"])

    assert err ==
             "lumina clean: warning: #{never} was never synced into #{cache}; nothing to remove for it\n"

    assert out =~ "  #{synced}: 1 trust anchor"
    refute out =~ never

    assert {0, out, _} = clean(cache, ["--tal", never, "--force"])
    assert out == "#{cache}: nothing to remove\n"
  end

  @tag :rsync
  @tag doc: """
       A sync record without a tree, as Lumina before 0.8.1 wrote: only
       the TA and the record go, with a warning.
       """
  test "a TAL synced before 0.8.1 loses only its trust anchor and sync record, with a warning",
       %{tmp_dir: tmp} do
    cache = Path.join(tmp, "cache")
    tal = rsync_synced(tmp, "m0-minimal-valid", cache)
    [record] = Path.wildcard(Path.join(cache, ".state/syncs/*.json"))
    File.write!(record, ~s({"synced_at":"2026-11-13T12:00:00Z"}))
    left = files(cache) -- [Path.relative_to(record, cache)]

    assert {0, out, err} = clean(cache, ["--tal", tal, "--force"])
    assert err =~ "#{tal} was synced by lumina before 0.8.1"
    assert out =~ "  #{tal}: 1 trust anchor\n"
    assert files(cache) == Enum.reject(left, &String.starts_with?(&1, ".ta/"))
  end

  @tag :rsync
  @tag doc: """
       D-047: without --force, the plan is listed and the question asked;
       "n" (or no answer) removes nothing and exits 1, "y" removes. With
       standard input not a terminal, nothing is removed, exit 1, and the
       message names --force.
       """
  test "without --force it asks, and removes only on yes; with no terminal it removes nothing",
       %{tmp_dir: tmp} do
    cache = Path.join(tmp, "cache")
    rsync_synced(tmp, "m0-minimal-valid", cache)
    all = files(cache)

    {:ok, no} = StringIO.open("n\n")
    assert {1, "", err} = clean(cache, [], interactive: true, input: no)
    assert err =~ "#{cache}: will remove everything: "
    assert err =~ "Remove? [y/N] nothing removed\n"
    assert files(cache) == all

    {:ok, eof} = StringIO.open("")
    assert {1, "", _} = clean(cache, [], interactive: true, input: eof)
    assert files(cache) == all

    assert {1, "", err} = clean(cache, [], interactive: false)
    assert err =~ "#{cache}: would remove everything: "
    assert err =~ "nothing was removed; give --force to remove without asking\n"
    assert files(cache) == all

    {:ok, yes} = StringIO.open("yes\n")
    assert {0, out, _} = clean(cache, [], interactive: true, input: yes)
    assert out =~ "removed everything"
    assert File.ls!(cache) == []
  end

  @tag :rsync
  test "a cache locked by a running sync exits 1 and is left untouched", %{tmp_dir: tmp} do
    cache = Path.join(tmp, "cache")
    rsync_synced(tmp, "m0-minimal-valid", cache)
    File.write!(Path.join(cache, ".lock"), System.pid())
    all = files(cache)

    assert {1, "", err} = clean(cache, ["--force"])
    assert err == "lumina clean: #{cache} is in use by a sync (process #{System.pid()})\n"
    assert files(cache) == all
  end

  test "a cache that doesn't exist has nothing to remove", %{tmp_dir: tmp} do
    cache = Path.join(tmp, "none")
    assert {0, out, ""} = clean(cache, ["--force"])
    assert out == "#{cache}: nothing to remove\n"
    refute File.exists?(cache)
  end

  test "usage errors exit 2", %{tmp_dir: tmp} do
    cache = Path.join(tmp, "cache")
    missing = Path.join(tmp, "nope.tal")

    assert {2, "", err} = clean(cache, ["--bogus"])
    assert err =~ "lumina clean: unknown or invalid flag --bogus"
    assert {2, "", err} = clean(cache, ["extra"])
    assert err =~ "lumina clean: unexpected argument extra"
    assert {2, "", err} = clean(cache, ["--tal", missing])
    assert err =~ "lumina clean: #{missing}:"
    refute File.exists?(cache)
  end

  test "lumina help clean describes the flags and exit codes" do
    assert {0, help, ""} = run(["help", "clean"])

    for text <- ["--cache DIR", "--tal FILE", "--force", "--quiet", "Exit codes: 0 removed"],
        do: assert(help =~ text)

    assert {0, usage, ""} = run(["help"])
    assert usage =~ "clean     empty the local cache"
  end
end
