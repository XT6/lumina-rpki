defmodule Lumina.RRDP.FixturesTest do
  @moduledoc """
  Checks the RRDP output of every Barry fixture (#202), which the RRDP
  sync tests (#203 to #209) serve over HTTPS.

  Barry's default session_id, "1", isn't a UUID (F-038), so the generator
  gives each fixture a version 4 UUID made from its id. Every fixture's
  notification must decode with that session and the right snapshot
  hash, and every snapshot must decode against it; otherwise an RRDP test
  would fail on the fixture rather than on Lumina. A delta fixture
  (`rrdp_versions`) must be consistent with itself: each serial's files
  decode, and applying delta K to snapshot K-1 gives exactly snapshot
  K's objects, with every withdraw and replace naming the hash of the
  object it removes (RFC 8182 §3.4.2). The test HTTPS server serves a
  fixture's `rrdp/` under the URIs its certificates name, through
  `:remap`.
  """
  use ExUnit.Case, async: true

  alias Lumina.HTTPS
  alias Lumina.RRDP.{Delta, Notification, Snapshot}
  alias Lumina.Test.{Fixture, HTTPSServer}
  alias Mix.Lumina.Fixtures

  @moduletag :tmp_dir

  defp fixtures, do: Enum.map(Fixtures.load_all() |> elem(0), &Fixture.load!(&1.id))

  # The notification of serial `k` (the last one is notification.xml).
  defp notification_file(fixture, k) do
    if k == map_size(fixture.versions), do: "notification.xml", else: "notification-#{k}.xml"
  end

  defp decode!(fixture, file) do
    xml = File.read!(Path.join(fixture.rrdp_root, file))
    {:ok, n} = Notification.decode(xml, fixture.notification_uri)
    n
  end

  # The local file a notification's URI names: its last path segment.
  defp local(fixture, uri), do: Path.join(fixture.rrdp_root, List.last(uri.path))

  # A snapshot's objects as a map, rsync URI text => bytes.
  defp objects(fixture, n) do
    collect = fn {:publish, uri, bytes}, acc -> {:cont, Map.put(acc, to_string(uri), bytes)} end
    expected = %{session_id: n.session_id, serial: n.serial}
    {:ok, objects} = Snapshot.stream(local(fixture, n.snapshot.uri), expected, collect, %{})
    objects
  end

  @tag rfc: ["8182#3.5.1.3", "8182#3.5.2.3"]
  test "every fixture's notifications and snapshots decode, with its UUID session and hashes" do
    for fixture <- fixtures(), k <- Map.keys(fixture.versions) do
      n = decode!(fixture, notification_file(fixture, k))
      label = "#{fixture.id} serial #{k}"

      assert n.session_id == fixture.session_id, label
      assert n.serial == k, label
      assert n.warnings == [], label
      assert Enum.map(n.deltas, & &1.serial) == Enum.to_list(2..k//1), label

      for file <- [n.snapshot | n.deltas] do
        assert :crypto.hash(:sha256, File.read!(local(fixture, file.uri))) == file.hash, label
      end

      assert map_size(objects(fixture, n)) > 0, label
    end
  end

  test "every session is the version 4 UUID made from the fixture's id, distinct per fixture" do
    fixtures = fixtures()

    for fixture <- fixtures do
      assert fixture.session_id == Fixtures.session_id(fixture.id)
      assert {:ok, []} = Lumina.RRDP.session(fixture.session_id, "8182#3.5.1.3")
    end

    assert fixtures |> Enum.map(& &1.session_id) |> Enum.uniq() |> length() == length(fixtures)
  end

  @tag rfc: ["8182#3.4.2", "8182#3.5.3.3"],
       doc: """
       For every delta fixture and every K > 1: delta K applied to snapshot
       K-1 gives snapshot K's objects exactly. A withdraw or replace must
       name the SHA-256 of the object it removes; a publish without a hash
       must be a new object.
       """
  test "each delta applied to the previous snapshot gives exactly the next snapshot" do
    delta_fixtures = Enum.filter(fixtures(), &(map_size(&1.versions) > 1))
    assert "m8-rrdp-delta" in Enum.map(delta_fixtures, & &1.id)

    for fixture <- delta_fixtures, k <- 2..map_size(fixture.versions) do
      previous = objects(fixture, decode!(fixture, notification_file(fixture, k - 1)))
      current = decode!(fixture, notification_file(fixture, k))
      delta = Enum.find(current.deltas, &(&1.serial == k))
      expected = %{session_id: current.session_id, serial: k}
      hash = &:crypto.hash(:sha256, &1)

      apply = fn
        {:publish, uri, bytes}, acc ->
          refute Map.has_key?(acc, to_string(uri)), "#{uri} is replaced without a hash"
          {:cont, Map.put(acc, to_string(uri), bytes)}

        {:publish, uri, bytes, old}, acc ->
          assert hash.(Map.fetch!(acc, to_string(uri))) == old
          {:cont, Map.put(acc, to_string(uri), bytes)}

        {:withdraw, uri, old}, acc ->
          assert hash.(Map.fetch!(acc, to_string(uri))) == old
          {:cont, Map.delete(acc, to_string(uri))}
      end

      assert {:ok, applied} = Delta.stream(local(fixture, delta.uri), expected, apply, previous)
      assert applied == objects(fixture, current), "#{fixture.id} delta #{k}"
    end
  end

  @tag doc: "m8-rrdp-delta's delta holds exactly the three changes its rationale states."
  test "m8-rrdp-delta's delta withdraws roa2, adds roa3 and replaces ca1.mft" do
    fixture = Fixture.load!("m8-rrdp-delta")
    n = decode!(fixture, "notification.xml")
    collect = fn element, acc -> {:cont, [element | acc]} end

    {:ok, elements} =
      Delta.stream(
        local(fixture, hd(n.deltas).uri),
        %{session_id: n.session_id, serial: 2},
        collect,
        []
      )

    assert elements
           |> Enum.map(&{elem(&1, 0), List.last(elem(&1, 1).path), tuple_size(&1)})
           |> Enum.sort() ==
             [{:publish, "ca1.mft", 4}, {:publish, "roa3.roa", 3}, {:withdraw, "roa2.roa", 3}]
  end

  @tag doc: """
       The fixture's rrdp/ served by Lumina.Test.HTTPSServer; :remap sends
       localhost:8443, the port in the fixture's URIs, to the server's.
       """
  test "the test server serves a fixture's RRDP files under the URIs it names", %{tmp_dir: dir} do
    fixture = Fixture.load!("m8-rrdp-delta")
    pki = HTTPSServer.pki()
    port = HTTPSServer.start!(pki, HTTPSServer.dir_routes(fixture.rrdp_root, "/rrdp/"))
    opts = [cacerts: pki.cacerts, remap: %{"localhost:8443" => "localhost:#{port}"}]
    target = Path.join(dir, "notification.xml")

    assert {:ok, %{uri: uri}} = HTTPS.fetch_to_file(fixture.notification_uri, target, opts)
    assert uri == fixture.notification_uri
    assert File.read!(target) == File.read!(Path.join(fixture.rrdp_root, "notification.xml"))

    n = decode!(fixture, "notification.xml")
    snapshot = Path.join(dir, "snapshot.xml")
    assert {:ok, %{sha256: hash}} = HTTPS.fetch_to_file(n.snapshot.uri, snapshot, opts)
    assert hash == n.snapshot.hash
  end
end
