defmodule Lumina.RRDP.StoreTest do
  @moduledoc """
  Tests where RRDP content and state live in the cache (#201):
  `Lumina.RRDP.Store`, one store per repository, and `Lumina.RRDP.State`.

  RFC 8182 §3.4.2 lets a withdraw or a replace touch only objects that
  came from the same server; a store per notification URI makes that
  structural, so the tests check that two repositories publishing the
  same rsync URI keep separate copies. Applying a snapshot or deltas must
  never damage the last good store (RFC 8897 §7, as for rsync in
  `Lumina.Cache`): a failure midway leaves it byte-identical, a crash
  leaves nothing `Lumina.Cache.recover/1` can't clean up, and deltas,
  applied to a hard-linked copy, never write through a link into the
  live store's files. A state file that can't be trusted must read as
  "never synced", so the repository is fetched from its snapshot.
  """
  use ExUnit.Case, async: true

  alias Lumina.Cache
  alias Lumina.RRDP.{State, Store}

  @moduletag :tmp_dir

  defp uri!(text) do
    {:ok, uri} = Lumina.URI.parse(text)
    uri
  end

  @notify "https://rrdp.example.net/notification.xml"

  # Every regular file under `dir`, relative, with its contents.
  defp tree(dir) do
    for path <- Path.wildcard(Path.join(dir, "**/*"), match_dot: true),
        File.regular?(path),
        into: %{},
        do: {Path.relative_to(path, dir), File.read!(path)}
  end

  defp snapshot!(root, notify, objects) do
    {:ok, :done} =
      Store.update(root, uri!(notify), :snapshot, fn tx ->
        for {uri, bytes} <- objects, do: :ok = Store.put(tx, uri!(uri), bytes)
        {:ok, :done}
      end)
  end

  describe "applying a snapshot" do
    @tag rfc: "8182#3.4.3"
    test "a snapshot's objects land at their rsync URI paths inside the store, and nowhere else",
         %{tmp_dir: root} do
      snapshot!(root, @notify, [
        {"rsync://rpki.example.net/repo/ca/one.cer", "one"},
        {"rsync://other.example.org/mod/two.roa", "two"}
      ])

      store = Store.path(root, uri!(@notify))
      id = :crypto.hash(:sha256, @notify) |> Base.encode16(case: :lower)
      assert store == Path.join([root, "rrdp", "rrdp.example.net", id])

      assert tree(root) == %{
               "rrdp/rrdp.example.net/#{id}/rsync/rpki.example.net/repo/ca/one.cer" => "one",
               "rrdp/rrdp.example.net/#{id}/rsync/other.example.org/mod/two.roa" => "two"
             }

      assert File.ls!(Path.join(root, ".staging")) == []

      assert %{path: path, sha256: hash} =
               Store.lookup(store, uri!("rsync://rpki.example.net/repo/ca/one.cer"))

      assert path == Path.join(store, "rsync/rpki.example.net/repo/ca/one.cer")
      assert hash == :crypto.hash(:sha256, "one")
      assert Store.lookup(store, uri!("rsync://rpki.example.net/repo/ca/none.cer")) == nil
    end

    test "a new snapshot replaces the whole store", %{tmp_dir: root} do
      snapshot!(root, @notify, [{"rsync://h.example/m/a.cer", "a"}])
      snapshot!(root, @notify, [{"rsync://h.example/m/b.cer", "b"}])

      assert tree(Store.path(root, uri!(@notify))) == %{"rsync/h.example/m/b.cer" => "b"}
    end

    @tag doc: "The notification URI's port is part of the store's directory and of its id."
    test "a notification URI with a port gets its own store", %{tmp_dir: root} do
      other = "https://rrdp.example.net:8443/notification.xml"
      snapshot!(root, @notify, [{"rsync://h.example/m/a.cer", "a"}])
      snapshot!(root, other, [{"rsync://h.example/m/a.cer", "b"}])

      assert Store.path(root, uri!(other)) =~ "/rrdp/rrdp.example.net:8443/"
      assert tree(Store.path(root, uri!(@notify))) == %{"rsync/h.example/m/a.cer" => "a"}
      assert tree(Store.path(root, uri!(other))) == %{"rsync/h.example/m/a.cer" => "b"}
    end
  end

  describe "failures" do
    test "an error raised midway leaves the previous store byte-identical", %{tmp_dir: root} do
      snapshot!(root, @notify, [
        {"rsync://h.example/m/a.cer", "a"},
        {"rsync://h.example/m/b.cer", "b"}
      ])

      store = Store.path(root, uri!(@notify))
      before = tree(store)

      for mode <- [:snapshot, :deltas] do
        assert_raise RuntimeError, fn ->
          Store.update(root, uri!(@notify), mode, fn tx ->
            :ok = Store.put(tx, uri!("rsync://h.example/m/a.cer"), "changed")
            if mode == :deltas, do: :ok = Store.withdraw(tx, uri!("rsync://h.example/m/b.cer"))
            raise "midway"
          end)
        end

        assert tree(store) == before
      end

      assert File.ls!(Path.join(root, ".staging")) == []
    end

    test "a function returning an error discards its changes", %{tmp_dir: root} do
      snapshot!(root, @notify, [{"rsync://h.example/m/a.cer", "a"}])

      assert {:error, :hash_mismatch} =
               Store.update(root, uri!(@notify), :deltas, fn tx ->
                 :ok = Store.put(tx, uri!("rsync://h.example/m/a.cer"), "changed")
                 {:error, :hash_mismatch}
               end)

      assert tree(Store.path(root, uri!(@notify))) == %{"rsync/h.example/m/a.cer" => "a"}
    end

    @tag doc: "A transaction left open, as by a crash, is a staging directory recover/1 removes."
    test "no staging directory survives Cache.recover/1", %{tmp_dir: root} do
      snapshot!(root, @notify, [{"rsync://h.example/m/a.cer", "a"}])
      {:ok, tx} = Store.begin(root, uri!(@notify), :deltas)
      :ok = Store.put(tx, uri!("rsync://h.example/m/a.cer"), "half")
      assert File.dir?(tx.dir)

      assert {:ok, _} = Cache.recover(root)
      refute File.exists?(Path.join(root, ".staging"))
      assert tree(Store.path(root, uri!(@notify))) == %{"rsync/h.example/m/a.cer" => "a"}
    end

    @tag doc: """
         A crash between the swap's two renames leaves the live store
         aside with a note; recover/1 puts it back (Lumina.Cache.swap/3).
         """
    test "an interrupted swap of a store is repaired by Cache.recover/1", %{tmp_dir: root} do
      snapshot!(root, @notify, [{"rsync://h.example/m/a.cer", "a"}])
      store = Store.path(root, uri!(@notify))
      aside = Path.join([root, ".aside", "crashed"])
      File.mkdir_p!(Path.dirname(aside))
      File.write!(aside <> ".target", Path.relative_to(store, root))
      File.rename!(store, aside)

      assert {:ok, %{restored: [^store]}} = Cache.recover(root)
      assert tree(store) == %{"rsync/h.example/m/a.cer" => "a"}
    end
  end

  describe "applying deltas" do
    @tag rfc: "8182#3.4.2",
         doc: """
         The staged copy's files are hard links to the store's (same
         inode). A replace renames a new file over the link and a
         withdraw unlinks it; the store's files keep their inode and
         contents until the commit.
         """
    test "deltas on the hard-linked copy never change the previous store's files",
         %{tmp_dir: root} do
      snapshot!(root, @notify, [
        {"rsync://h.example/m/a.cer", "a"},
        {"rsync://h.example/m/b.cer", "b"}
      ])

      store = Store.path(root, uri!(@notify))
      a = Path.join(store, "rsync/h.example/m/a.cer")
      a_inode = File.stat!(a).inode

      {:ok, tx} = Store.begin(root, uri!(@notify), :deltas)
      staged = Store.object_path(tx, uri!("rsync://h.example/m/a.cer"))
      assert File.stat!(staged).inode == a_inode

      :ok = Store.put(tx, uri!("rsync://h.example/m/a.cer"), "replaced")
      :ok = Store.withdraw(tx, uri!("rsync://h.example/m/b.cer"))
      :ok = Store.put(tx, uri!("rsync://h.example/m/sub/c.cer"), "new")

      assert File.stat!(staged).inode != a_inode
      assert File.stat!(a).inode == a_inode
      assert tree(store) == %{"rsync/h.example/m/a.cer" => "a", "rsync/h.example/m/b.cer" => "b"}

      assert Store.lookup(tx, uri!("rsync://h.example/m/a.cer")).sha256 ==
               :crypto.hash(:sha256, "replaced")

      assert Store.lookup(tx, uri!("rsync://h.example/m/b.cer")) == nil

      :ok = Store.commit(tx)

      assert tree(store) == %{
               "rsync/h.example/m/a.cer" => "replaced",
               "rsync/h.example/m/sub/c.cer" => "new"
             }
    end

    test "withdrawing an object that isn't there is an error", %{tmp_dir: root} do
      snapshot!(root, @notify, [{"rsync://h.example/m/a.cer", "a"}])
      {:ok, tx} = Store.begin(root, uri!(@notify), :deltas)

      assert {:error, :enoent} = Store.withdraw(tx, uri!("rsync://h.example/m/none.cer"))
      Store.discard(tx)
    end

    @tag doc: "A withdraw removes directories it leaves empty, up to the store's root."
    test "withdrawing the last object of a directory removes the directory", %{tmp_dir: root} do
      snapshot!(root, @notify, [{"rsync://h.example/m/d/a.cer", "a"}])

      {:ok, :ok} =
        Store.update(root, uri!(@notify), :deltas, fn tx ->
          {:ok, Store.withdraw(tx, uri!("rsync://h.example/m/d/a.cer"))}
        end)

      store = Store.path(root, uri!(@notify))
      assert File.dir?(store)
      assert File.ls!(store) == []
    end
  end

  describe "separate stores" do
    @tag rfc: "8182#3.4.2",
         doc: """
         RFC 8182 §3.4.2: a withdraw or replace may touch only objects
         retrieved from the same server. A second repository publishing
         and then withdrawing the same rsync URI leaves the first's copy.
         """
    test "two repositories publishing the same rsync URI keep separate copies", %{tmp_dir: root} do
      other = "https://rrdp.other.example/notification.xml"
      object = "rsync://shared.example/repo/ca.cer"
      snapshot!(root, @notify, [{object, "first"}])
      snapshot!(root, other, [{object, "second"}])

      assert File.read!(Store.lookup(Store.path(root, uri!(@notify)), uri!(object)).path) ==
               "first"

      assert File.read!(Store.lookup(Store.path(root, uri!(other)), uri!(object)).path) ==
               "second"

      {:ok, :ok} =
        Store.update(root, uri!(other), :deltas, fn tx ->
          {:ok, Store.withdraw(tx, uri!(object))}
        end)

      assert Store.lookup(Store.path(root, uri!(other)), uri!(object)) == nil

      assert File.read!(Store.lookup(Store.path(root, uri!(@notify)), uri!(object)).path) ==
               "first"

      refute File.exists?(Cache.path(root, uri!(object)))
    end
  end

  describe "state" do
    @tag rfc: ["8182#3.4.1", "8182#3.4.4"]
    test "a saved state loads back as it was", %{tmp_dir: root} do
      notify = uri!(@notify)

      state = %{
        session_id: "9df4b597-af9e-4dca-bdda-719cce2c4e28",
        serial: 12,
        deltas: %{11 => :binary.copy(<<1>>, 32), 12 => :binary.copy(<<2>>, 32)},
        last_modified: "Tue, 17 Nov 2026 12:00:00 GMT",
        last_attempt: ~U[2026-11-17 12:05:00Z],
        last_success: ~U[2026-11-17 12:00:00Z],
        outcome: {:error, "snapshot hash mismatch"}
      }

      assert :ok = State.save(root, notify, state)
      assert State.load(root, notify) == Map.put(state, :notify, @notify)

      assert State.file(root, notify) ==
               Path.join([root, ".state/rrdp", Store.id(notify) <> ".json"])

      assert File.ls!(Path.dirname(State.file(root, notify))) == [Store.id(notify) <> ".json"]
    end

    test "a repository with no state file reads as never synced", %{tmp_dir: root} do
      assert State.load(root, uri!(@notify)) == nil
    end

    @tag doc:
           "Not JSON, a field of the wrong type, a bad delta hash, or another notification URI."
    test "a corrupt state file reads as never synced", %{tmp_dir: root} do
      notify = uri!(@notify)
      :ok = State.save(root, notify, %{session_id: "s", serial: 3, outcome: :ok})
      assert %{serial: 3, deltas: %{}, last_attempt: nil, outcome: :ok} = State.load(root, notify)

      path = State.file(root, notify)
      valid = JSON.decode!(File.read!(path))

      for bad <- [
            "{not json",
            "[]",
            JSON.encode!(Map.put(valid, "serial", "3")),
            JSON.encode!(Map.put(valid, "serial", 0)),
            JSON.encode!(Map.put(valid, "deltas", %{"3" => "abcd"})),
            JSON.encode!(Map.put(valid, "deltas", %{"x" => String.duplicate("a", 64)})),
            JSON.encode!(Map.put(valid, "last_attempt", "yesterday")),
            JSON.encode!(Map.put(valid, "outcome", "maybe")),
            JSON.encode!(Map.put(valid, "notify", "https://elsewhere.example/n.xml"))
          ] do
        File.write!(path, bad)
        assert State.load(root, notify) == nil, bad
      end
    end
  end
end
