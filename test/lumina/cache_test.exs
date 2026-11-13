defmodule Lumina.CacheTest do
  @moduledoc """
  Tests the local cache (`Lumina.Cache`, #71): the layout, staging and
  swapping a fetch into place, and that a failed fetch or a crash never
  loses the last good copy (RFC 8897 §7). Repository content is untrusted,
  so the tests also check that symlinks and special files never reach the
  cache. The content used is a real Barry fixture tree, compared byte for
  byte. Crashes are simulated by leaving the cache in each state an
  interrupted `commit/3` can leave it in.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Cache, URI}
  alias Lumina.Test.Fixture

  @moduletag :tmp_dir

  @module "rsync://localhost:8873/rpki"

  defp uri!(string) do
    {:ok, uri} = URI.parse(string)
    uri
  end

  # Every regular file under `dir`, relative path => bytes.
  defp tree(dir) do
    for path <- Path.wildcard(Path.join(dir, "**/*"), match_dot: true),
        File.regular?(path),
        into: %{},
        do: {Path.relative_to(path, dir), File.read!(path)}
  end

  defp fixture_tree, do: Fixture.load!("m0-minimal-valid").rsync_root

  # A staging directory holding a copy of `source`.
  defp staged(root, source) do
    {:ok, staging} = Cache.stage(root)
    File.cp_r!(source, staging)
    staging
  end

  defp commit!(root, source) do
    {:ok, _} = Cache.commit(root, uri!(@module), staged(root, source))
  end

  describe "layout and swapping" do
    @tag rfc: "6481#5"
    test "a committed fetch is the live copy, at the module's cache path", %{tmp_dir: root} do
      commit!(root, fixture_tree())

      live = Path.join(root, "rsync/localhost:8873/rpki")
      assert Cache.path(root, uri!(@module)) == live
      assert tree(live) == tree(fixture_tree())
      assert File.ls!(Path.join(root, ".staging")) == []
    end

    @tag doc:
           "Files deleted upstream must disappear from the cache, not linger from the old copy."
    test "a second commit replaces the first completely", %{tmp_dir: root} do
      commit!(root, fixture_tree())

      newer = Path.join(root, "newer")
      File.mkdir_p!(Path.join(newer, "ca1"))
      File.write!(Path.join(newer, "ca1/new.roa"), "new")
      commit!(root, newer)

      assert tree(Cache.path(root, uri!(@module))) == %{"ca1/new.roa" => "new"}
      assert File.ls!(Path.join(root, ".aside")) == []
    end

    @tag rfc: "8897#7"
    test "a failed fetch is discarded and the last good copy stays byte-identical", %{
      tmp_dir: root
    } do
      commit!(root, fixture_tree())
      before = tree(Cache.path(root, uri!(@module)))

      {:ok, staging} = Cache.stage(root)
      File.write!(Path.join(staging, "partial.cer"), "half a file")
      assert Cache.discard(staging) == :ok

      assert tree(Cache.path(root, uri!(@module))) == before
      refute File.exists?(staging)
    end

    @tag rfc: "8897#7",
         doc: """
         The live copy is moved aside, then the staging directory can't be
         renamed into place (its parent is read-only): the live copy must go
         back where it was.
         """
    test "a commit that fails halfway puts the live copy back", %{tmp_dir: root} do
      commit!(root, fixture_tree())
      before = tree(Cache.path(root, uri!(@module)))

      staging = staged(root, fixture_tree())
      File.chmod!(Path.join(root, ".staging"), 0o555)

      try do
        assert {:error, :eacces} = Cache.commit(root, uri!(@module), staging)
      after
        File.chmod!(Path.join(root, ".staging"), 0o755)
      end

      assert tree(Cache.path(root, uri!(@module))) == before
      assert File.ls!(Path.join(root, ".aside")) == []
    end

    test "committing a staging directory that doesn't exist changes nothing", %{tmp_dir: root} do
      commit!(root, fixture_tree())
      before = tree(Cache.path(root, uri!(@module)))

      missing = Path.join(root, ".staging/never-created")
      assert Cache.commit(root, uri!(@module), missing) == {:error, :enoent}
      assert tree(Cache.path(root, uri!(@module))) == before
    end

    test "working directories start with a dot and never collide with repository content", %{
      tmp_dir: root
    } do
      commit!(root, fixture_tree())
      Cache.record(root, uri!(@module), :ok, ~U[2026-11-13 12:00:00Z])

      assert root |> File.ls!() |> Enum.reject(&String.starts_with?(&1, ".")) == ["rsync"]
    end
  end

  describe "untrusted content" do
    @tag doc: """
         A repository could plant a symlink to a file outside the cache. It's
         removed before the swap, never followed, and its target is untouched.
         """
    test "symlinks are removed and reported, and their targets aren't touched", %{
      tmp_dir: root
    } do
      outside = Path.join(root, "outside.txt")
      File.write!(outside, "secret")

      {:ok, staging} = Cache.stage(root)
      File.mkdir_p!(Path.join(staging, "ca1"))
      File.write!(Path.join(staging, "ca1/ok.roa"), "roa")
      File.ln_s!(outside, Path.join(staging, "ca1/link.cer"))
      File.ln_s!(root, Path.join(staging, "dirlink"))

      assert {:ok, %{removed: ["ca1/link.cer", "dirlink"]}} =
               Cache.commit(root, uri!(@module), staging)

      assert tree(Cache.path(root, uri!(@module))) == %{"ca1/ok.roa" => "roa"}
      assert File.read!(outside) == "secret"
    end

    test "FIFOs and other special files are removed and reported", %{tmp_dir: root} do
      {:ok, staging} = Cache.stage(root)
      File.write!(Path.join(staging, "ok.cer"), "cer")
      {_, 0} = System.cmd("mkfifo", [Path.join(staging, "pipe.mft")])

      assert {:ok, %{removed: ["pipe.mft"]}} = Cache.commit(root, uri!(@module), staging)
      assert File.ls!(Cache.path(root, uri!(@module))) == ["ok.cer"]
    end
  end

  describe "recovery after a crash" do
    # The state commit/3 leaves when it stops after moving the live copy
    # aside: the copy and its note in .aside/, nothing at the target.
    defp crash_after_move_aside(root) do
      target = Cache.path(root, uri!(@module))
      aside = Path.join(root, ".aside/crashed")
      File.mkdir_p!(Path.dirname(aside))
      File.write!(aside <> ".target", Path.relative_to(target, root))
      File.rename!(target, aside)
    end

    @tag rfc: "8897#7"
    test "a live copy left aside is put back", %{tmp_dir: root} do
      commit!(root, fixture_tree())
      before = tree(Cache.path(root, uri!(@module)))
      crash_after_move_aside(root)
      refute File.exists?(Cache.path(root, uri!(@module)))

      assert {:ok, %{restored: [restored]}} = Cache.recover(root)

      assert restored == Cache.path(root, uri!(@module))
      assert tree(restored) == before
      assert File.ls!(Path.join(root, ".aside")) == []
    end

    test "after a crash that completed the swap, only the old copy is removed", %{
      tmp_dir: root
    } do
      commit!(root, fixture_tree())
      crash_after_move_aside(root)
      File.mkdir_p!(Cache.path(root, uri!(@module)))
      File.write!(Path.join(Cache.path(root, uri!(@module)), "new.cer"), "new")

      assert {:ok, %{restored: []}} = Cache.recover(root)
      assert tree(Cache.path(root, uri!(@module))) == %{"new.cer" => "new"}
      assert File.ls!(Path.join(root, ".aside")) == []
    end

    test "leftover staging directories are removed", %{tmp_dir: root} do
      {:ok, staging} = Cache.stage(root)
      File.write!(Path.join(staging, "half.cer"), "half")

      assert {:ok, %{restored: []}} = Cache.recover(root)
      refute File.exists?(Path.join(root, ".staging"))
    end

    test "recovering a fresh or clean cache does nothing", %{tmp_dir: root} do
      assert Cache.recover(Path.join(root, "nothing-here")) == {:ok, %{restored: []}}
      commit!(root, fixture_tree())
      assert Cache.recover(root) == {:ok, %{restored: []}}
    end
  end

  describe "single files" do
    @tag rfc: "8630#3"
    test "a TA certificate fetched over HTTPS is written at its cache path, replacing the old one",
         %{tmp_dir: root} do
      uri = uri!("https://rrdp.lacnic.net/ta/rta-lacnic-rpki.cer")

      assert Cache.put_file(root, uri, "old") == :ok
      assert Cache.put_file(root, uri, "new") == :ok

      path = Path.join(root, "https/rrdp.lacnic.net/ta/rta-lacnic-rpki.cer")
      assert Cache.path(root, uri) == path
      assert File.read!(path) == "new"
      assert File.ls!(Path.dirname(path)) == ["rta-lacnic-rpki.cer"]
    end
  end

  describe "fetch status (D-007)" do
    test "a URI never fetched has no status", %{tmp_dir: root} do
      assert Cache.status(root, uri!(@module)) == nil
    end

    test "a success records the attempt and the success", %{tmp_dir: root} do
      Cache.record(root, uri!(@module), :ok, ~U[2026-11-13 12:00:00Z])

      assert Cache.status(root, uri!(@module)) == %{
               uri: @module,
               last_attempt: ~U[2026-11-13 12:00:00Z],
               outcome: :ok,
               last_success: ~U[2026-11-13 12:00:00Z]
             }
    end

    @tag doc: "The time of the last success is what tells a reader how stale the copy is."
    test "a failure after a success keeps the time of the last success", %{tmp_dir: root} do
      Cache.record(root, uri!(@module), :ok, ~U[2026-11-13 12:00:00Z])
      Cache.record(root, uri!(@module), {:error, :timeout}, ~U[2026-11-13 13:00:00Z])

      assert Cache.status(root, uri!(@module)) == %{
               uri: @module,
               last_attempt: ~U[2026-11-13 13:00:00Z],
               outcome: {:error, ":timeout"},
               last_success: ~U[2026-11-13 12:00:00Z]
             }
    end

    test "a failure with no earlier success has no last success", %{tmp_dir: root} do
      Cache.record(root, uri!(@module), {:error, "connection refused"}, ~U[2026-11-13 12:00:00Z])

      assert %{outcome: {:error, "connection refused"}, last_success: nil} =
               Cache.status(root, uri!(@module))
    end

    test "statuses of different URIs are kept apart", %{tmp_dir: root} do
      other = uri!("rsync://rpki.example.net/repo")
      Cache.record(root, uri!(@module), :ok, ~U[2026-11-13 12:00:00Z])
      Cache.record(root, other, {:error, :timeout}, ~U[2026-11-13 12:00:00Z])

      assert Cache.status(root, uri!(@module)).outcome == :ok
      assert Cache.status(root, other).outcome == {:error, ":timeout"}
    end
  end
end
