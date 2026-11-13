defmodule Lumina.RsyncTest do
  @moduledoc """
  Tests the rsync runner (`Lumina.Rsync`, #72) against a real
  `rsync --daemon` (`Lumina.Test.RsyncDaemon`) serving Barry fixture trees
  and hand-made directories on 127.0.0.1. These tests are tagged `:rsync`
  and excluded when no rsync 3.1.0 or later is installed.

  They pin what the cache depends on: a publication point is fetched
  recursively and byte-identical (D-009), files the server no longer has
  are deleted, symlinks on the server never arrive, an oversize file is
  skipped and reported rather than failing the fetch (D-008), and each
  kind of failure gives its typed reason. A repository URI can never be
  read as an rsync option.
  """
  use ExUnit.Case, async: true
  doctest Lumina.Rsync

  alias Lumina.{Rsync, URI}
  alias Lumina.Test.{Fixture, RsyncDaemon}

  @moduletag :rsync
  @moduletag :tmp_dir

  defp uri!(string) do
    {:ok, uri} = URI.parse(string)
    uri
  end

  defp tree(dir) do
    for path <- Path.wildcard(Path.join(dir, "**/*"), match_dot: true),
        File.regular?(path),
        into: %{},
        do: {Path.relative_to(path, dir), File.read!(path)}
  end

  defp fixture_root, do: Fixture.load!("m0-minimal-valid").rsync_root

  defp serve_fixture(tmp_dir) do
    daemon = RsyncDaemon.start!(tmp_dir, %{"rpki" => fixture_root()})
    "rsync://127.0.0.1:#{daemon.port}/rpki"
  end

  describe "fetching" do
    @tag rfc: ["5781#2", "6481#3"],
         doc: "The whole publication point, subdirectories included, byte for byte (D-009)."
    test "a publication point is fetched recursively and byte-identical", %{tmp_dir: tmp} do
      base = serve_fixture(tmp)
      dest = Path.join(tmp, "dest")

      assert {:ok, %{oversize: []}} = Rsync.fetch_dir(uri!(base), dest)
      assert tree(dest) == tree(fixture_root())
    end

    @tag rfc: "6481#2"
    test "a nested publication point brings only its own subtree", %{tmp_dir: tmp} do
      base = serve_fixture(tmp)
      dest = Path.join(tmp, "dest")

      assert {:ok, _} = Rsync.fetch_dir(uri!(base <> "/ca1"), dest)
      assert tree(dest) == tree(Path.join(fixture_root(), "ca1"))
    end

    @tag doc: "An object withdrawn from the repository must not survive in the fetched copy."
    test "files the server no longer has are deleted from the destination", %{tmp_dir: tmp} do
      base = serve_fixture(tmp)
      dest = Path.join(tmp, "dest")
      File.mkdir_p!(Path.join(dest, "ca1"))
      File.write!(Path.join(dest, "ca1/withdrawn.roa"), "old")

      assert {:ok, _} = Rsync.fetch_dir(uri!(base), dest)
      assert tree(dest) == tree(fixture_root())
    end

    @tag doc:
           "With :link_dest, unchanged files are hard links to the previous copy, not new downloads."
    test "a previous copy given as :link_dest is reused for unchanged files", %{tmp_dir: tmp} do
      base = serve_fixture(tmp)
      first = Path.join(tmp, "first")
      second = Path.join(tmp, "second")

      {:ok, _} = Rsync.fetch_dir(uri!(base), first)
      assert {:ok, _} = Rsync.fetch_dir(uri!(base), second, link_dest: first)

      assert tree(second) == tree(first)

      assert File.stat!(Path.join(second, "ta.cer")).inode ==
               File.stat!(Path.join(first, "ta.cer")).inode
    end

    @tag rfc: "8630#3"
    test "a single file, such as a TA certificate, is fetched to a path", %{tmp_dir: tmp} do
      base = serve_fixture(tmp)
      dest = Path.join(tmp, "ta.cer")

      assert {:ok, _} = Rsync.fetch_file(uri!(base <> "/ta.cer"), dest)
      assert File.read!(dest) == File.read!(Path.join(fixture_root(), "ta.cer"))
    end
  end

  describe "untrusted servers" do
    test "symlinks on the server are not created locally", %{tmp_dir: tmp} do
      served = Path.join(tmp, "served")
      File.mkdir_p!(served)
      File.write!(Path.join(served, "ok.cer"), "cer")
      File.ln_s!("/etc/passwd", Path.join(served, "link.cer"))
      daemon = RsyncDaemon.start!(tmp, %{"repo" => served})
      dest = Path.join(tmp, "dest")

      assert {:ok, _} = Rsync.fetch_dir(uri!("rsync://127.0.0.1:#{daemon.port}/repo"), dest)
      assert File.ls!(dest) == ["ok.cer"]
    end

    @tag doc: """
         D-008: an object over the size limit is skipped and reported; the rest
         of the publication point is still fetched. Failing the whole fetch
         would let one oversize file freeze the publication point.
         """
    test "a file over the size limit is skipped and reported, and the rest is fetched", %{
      tmp_dir: tmp
    } do
      served = Path.join(tmp, "served")
      File.mkdir_p!(Path.join(served, "sub"))
      File.write!(Path.join(served, "small.roa"), "roa")
      File.write!(Path.join(served, "sub/big.mft"), :binary.copy("x", 2000))
      daemon = RsyncDaemon.start!(tmp, %{"repo" => served})
      dest = Path.join(tmp, "dest")

      assert {:ok, %{oversize: ["sub/big.mft"]}} =
               Rsync.fetch_dir(uri!("rsync://127.0.0.1:#{daemon.port}/repo"), dest,
                 max_size: 1000
               )

      assert tree(dest) == %{"small.roa" => "roa"}
    end

    @tag doc: """
         F-025: the rsync daemon reads a path starting with "-" as its own
         option. With the ./ the runner inserts, --help is just a missing file.
         """
    test "a URI path that looks like an rsync option is only a path", %{tmp_dir: tmp} do
      base = serve_fixture(tmp)

      assert {:error, %{reason: :not_found}} =
               Rsync.fetch_dir(uri!(base <> "/--help"), Path.join(tmp, "dest"))
    end

    @tag doc: "Base64url names can start with \"-\"; such directories and files must still fetch."
    test "directories and files whose names start with - are fetched", %{tmp_dir: tmp} do
      served = Path.join(tmp, "served")
      File.mkdir_p!(Path.join(served, "-x"))
      File.write!(Path.join(served, "-x/-a.cer"), "cer")
      daemon = RsyncDaemon.start!(tmp, %{"repo" => served})
      base = "rsync://127.0.0.1:#{daemon.port}/repo"

      assert {:ok, _} = Rsync.fetch_dir(uri!(base <> "/-x"), Path.join(tmp, "dir"))
      assert tree(Path.join(tmp, "dir")) == %{"-a.cer" => "cer"}

      assert {:ok, _} = Rsync.fetch_file(uri!(base <> "/-x/-a.cer"), Path.join(tmp, "file.cer"))
      assert File.read!(Path.join(tmp, "file.cer")) == "cer"
    end

    test "a URI with no module can't be fetched", %{tmp_dir: tmp} do
      assert {:error, %{reason: :no_module}} =
               Rsync.fetch_dir(uri!("rsync://127.0.0.1/"), Path.join(tmp, "dest"))
    end
  end

  describe "failures" do
    test "a refused connection is :connection_refused", %{tmp_dir: tmp} do
      uri = uri!("rsync://127.0.0.1:#{RsyncDaemon.closed_port()}/rpki")

      assert {:error, %{reason: :connection_refused, exit_status: 10}} =
               Rsync.fetch_dir(uri, Path.join(tmp, "dest"))
    end

    test "a host that doesn't resolve is :unknown_host", %{tmp_dir: tmp} do
      assert {:error, %{reason: :unknown_host}} =
               Rsync.fetch_dir(uri!("rsync://no-such-host.invalid/rpki"), Path.join(tmp, "dest"))
    end

    test "a module the server doesn't have is :no_such_module", %{tmp_dir: tmp} do
      base = serve_fixture(tmp)
      uri = uri!(String.replace(base, "/rpki", "/nope"))

      assert {:error, %{reason: :no_such_module, exit_status: 5, output: output}} =
               Rsync.fetch_dir(uri, Path.join(tmp, "dest"))

      assert output =~ "Unknown module"
    end

    test "a path the module doesn't have is :not_found", %{tmp_dir: tmp} do
      base = serve_fixture(tmp)

      assert {:error, %{reason: :not_found, exit_status: 23}} =
               Rsync.fetch_dir(uri!(base <> "/missing"), Path.join(tmp, "dest"))
    end

    @tag doc:
           "A server that accepts the connection and then says nothing hits the I/O timeout (D-008)."
    test "a server that never answers times out", %{tmp_dir: tmp} do
      uri = uri!("rsync://127.0.0.1:#{RsyncDaemon.silent_server!()}/rpki")

      assert {:error, %{reason: reason}} =
               Rsync.fetch_dir(uri, Path.join(tmp, "dest"), timeout: 1, contimeout: 1)

      assert reason in [:timeout, :connect_timeout]
    end
  end

  describe "the rsync binary" do
    test "check finds rsync 3.1.0 or later" do
      assert {:ok, %{version: version}} = Rsync.check()
      assert version >= {3, 1, 0}
    end

    test "a missing binary is :rsync_not_found, for check and for a fetch", %{tmp_dir: tmp} do
      missing = Path.join(tmp, "no-rsync-here")

      assert Rsync.check(rsync: missing) == {:error, :rsync_not_found}

      assert {:error, %{reason: :rsync_not_found}} =
               Rsync.fetch_dir(uri!("rsync://h.example/m"), tmp, rsync: missing)
    end

    test "an rsync older than 3.1.0 is rejected", %{tmp_dir: tmp} do
      fake = Path.join(tmp, "rsync")
      File.write!(fake, "#!/bin/sh\necho 'rsync  version 3.0.9  protocol version 30'\n")
      File.chmod!(fake, 0o755)

      assert Rsync.check(rsync: fake) == {:error, {:rsync_too_old, "3.0.9"}}
    end
  end
end
