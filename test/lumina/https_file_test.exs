defmodule Lumina.HTTPSFileTest do
  @moduledoc """
  Tests `Lumina.HTTPS.fetch_to_file/3` (#200), the download RRDP uses for
  notification, snapshot and delta files, against the local TLS server
  (`Lumina.Test.HTTPSServer`).

  Snapshots run to hundreds of megabytes (ARIN's was 760 MB on
  2026-11-16), so the body must go to disk as it arrives, with its
  SHA-256 computed on the way, and a failed download must never replace
  the file a previous run left (D-043). The limits are D-043's: a size
  cap that holds mid-stream, and an idle timeout instead of a total one,
  so a slow server isn't cut off but a stalled one is. RFC 8182 §3.4.4
  requires `If-Modified-Since` when polling, RFC 8182 §3.4.1 recommends a
  `User-Agent` naming the RP and its version, and RFC 9674 §3.2 forbids
  following a redirect to another origin.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Lumina.{HTTPS, URI}
  alias Lumina.Test.HTTPSServer

  @moduletag :tmp_dir

  defp uri!(string) do
    {:ok, uri} = URI.parse(string)
    uri
  end

  defp serve(routes) do
    pki = HTTPSServer.pki()
    port = HTTPSServer.start!(pki, routes)
    {"https://localhost:#{port}", port, pki}
  end

  # A redirect whose target needs the server's port, read from the
  # request's Host header.
  defp redirect(status, location) do
    fn request ->
      {"host", host} = List.keyfind(request.headers, "host", 0)
      [_, port] = String.split(host, ":")
      {status, [{"location", location.(String.to_integer(port))}], ""}
    end
  end

  # What is left in the directory: the target, if written, and no
  # temporary file.
  defp files(dir), do: dir |> File.ls!() |> Enum.sort()

  describe "streaming to a file" do
    @tag doc: """
         The body is a 50 MB file served with a Content-Length. The fetch
         runs in its own process, sampled every 5 ms: its heap plus the
         binaries it holds must stay under 8 MB, so the body never sits in
         memory whole.
         """
    test "a 50 MB body streams to disk with the right hash, and memory stays flat",
         %{tmp_dir: dir} do
      source = Path.join(dir, "source")
      block = :crypto.strong_rand_bytes(1024 * 1024)
      File.write!(source, List.duplicate(block, 50))
      hash = :crypto.hash(:sha256, List.duplicate(block, 50))
      {base, _port, pki} = serve(%{"/snapshot.xml" => {:file, source}})
      target = Path.join(dir, "out/snapshot.xml")

      task =
        Task.async(fn ->
          HTTPS.fetch_to_file(uri!(base <> "/snapshot.xml"), target, cacerts: pki.cacerts)
        end)

      peak = sample(task.pid, 0)

      assert {:ok, %{sha256: ^hash, size: 52_428_800, uri: uri}} = Task.await(task, 60_000)
      assert to_string(uri) == base <> "/snapshot.xml"
      assert File.read!(target) == File.read!(source)
      assert files(Path.join(dir, "out")) == ["snapshot.xml"]
      assert peak < 8 * 1024 * 1024, "peak #{peak} bytes"
    end

    @tag doc: "Close-delimited, so the limit is only found as the bytes arrive."
    test "a body over :max_size fails mid-stream and leaves no file", %{tmp_dir: dir} do
      {base, _port, pki} =
        serve(%{"/s.xml" => {:raw, ["HTTP/1.1 200 OK\r\n\r\n", :binary.copy("x", 50_000)]}})

      target = Path.join(dir, "s.xml")

      assert {:error, %{reason: :too_large, detail: 10_000}} =
               HTTPS.fetch_to_file(uri!(base <> "/s.xml"), target,
                 cacerts: pki.cacerts,
                 max_size: 10_000
               )

      assert files(dir) == []
    end

    test "a failed download leaves the file a previous one wrote", %{tmp_dir: dir} do
      {base, _port, pki} =
        serve(%{"/s.xml" => {:raw, "HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort"}})

      target = Path.join(dir, "s.xml")
      File.write!(target, "previous")

      assert {:error, %{reason: :truncated}} =
               HTTPS.fetch_to_file(uri!(base <> "/s.xml"), target, cacerts: pki.cacerts)

      assert File.read!(target) == "previous"
      assert files(dir) == ["s.xml"]
    end
  end

  describe "truncated bodies" do
    test "a body that ends before its Content-Length fails as :truncated", %{tmp_dir: dir} do
      {base, _port, pki} =
        serve(%{"/s.xml" => {:raw, "HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort"}})

      assert {:error, %{reason: :truncated, detail: 5}} =
               HTTPS.fetch_to_file(uri!(base <> "/s.xml"), Path.join(dir, "s.xml"),
                 cacerts: pki.cacerts
               )

      assert files(dir) == []
    end

    test "a chunked body that ends inside a chunk fails as :truncated", %{tmp_dir: dir} do
      {base, _port, pki} =
        serve(%{
          "/s.xml" =>
            {:raw,
             "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nabcde\r\n64\r\nshort"}
        })

      assert {:error, %{reason: :truncated}} =
               HTTPS.fetch_to_file(uri!(base <> "/s.xml"), Path.join(dir, "s.xml"),
                 cacerts: pki.cacerts
               )

      assert files(dir) == []
    end

    test "a chunked body without its last chunk fails as :truncated", %{tmp_dir: dir} do
      {base, _port, pki} =
        serve(%{
          "/s.xml" =>
            {:raw, "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nabcde\r\n"}
        })

      assert {:error, %{reason: :truncated}} =
               HTTPS.fetch_to_file(uri!(base <> "/s.xml"), Path.join(dir, "s.xml"),
                 cacerts: pki.cacerts
               )

      assert files(dir) == []
    end

    test "a complete chunked body is written whole", %{tmp_dir: dir} do
      {base, _port, pki} =
        serve(%{
          "/s.xml" =>
            {:raw,
             "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nabcde\r\n3\r\nfgh\r\n0\r\n\r\n"}
        })

      target = Path.join(dir, "s.xml")

      assert {:ok, %{size: 8}} =
               HTTPS.fetch_to_file(uri!(base <> "/s.xml"), target, cacerts: pki.cacerts)

      assert File.read!(target) == "abcdefgh"
    end

    @tag doc: "For download progress (D-036, #203): a 1 MB body sent 64 KiB at a time."
    test ":on_data is called with the bytes received so far, up to the whole body",
         %{tmp_dir: dir} do
      source = Path.join(dir, "source")
      File.write!(source, :binary.copy("x", 1_000_000))
      {base, _port, pki} = serve(%{"/s.xml" => {:file, source}})
      test = self()

      assert {:ok, %{size: 1_000_000}} =
               HTTPS.fetch_to_file(uri!(base <> "/s.xml"), Path.join(dir, "s.xml"),
                 cacerts: pki.cacerts,
                 on_data: &send(test, {:bytes, &1})
               )

      sizes = collect_sizes([])
      assert length(sizes) > 1
      assert sizes == Enum.sort(sizes)
      assert List.last(sizes) == 1_000_000
    end
  end

  defp collect_sizes(acc) do
    receive do
      {:bytes, size} -> collect_sizes([size | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  describe "idle timeout (D-043)" do
    @tag doc: "Half the body, then nothing for 3 s; :idle_timeout is 1 s."
    test "a body that stops sending fails after :idle_timeout", %{tmp_dir: dir} do
      {base, _port, pki} =
        serve(%{
          "/s.xml" =>
            {:script, ["HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabcde", {:sleep, 3_000}]}
        })

      started = System.monotonic_time(:millisecond)

      assert {:error, %{reason: :timeout, detail: :idle}} =
               HTTPS.fetch_to_file(uri!(base <> "/s.xml"), Path.join(dir, "s.xml"),
                 cacerts: pki.cacerts,
                 idle_timeout: 1
               )

      assert System.monotonic_time(:millisecond) - started < 2_500
      assert files(dir) == []
    end

    @tag doc: """
         One byte every 400 ms for 2.4 s with a 1 s :idle_timeout: longer
         than the timeout in total, never idle that long. D-043 sets no
         total limit.
         """
    test "a slow but steady body isn't cut off", %{tmp_dir: dir} do
      steps = Enum.flat_map(~w(a b c d e f), &[{:sleep, 400}, &1])

      {base, _port, pki} =
        serve(%{"/s.xml" => {:script, ["HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\n" | steps]}})

      target = Path.join(dir, "s.xml")

      assert {:ok, %{size: 6}} =
               HTTPS.fetch_to_file(uri!(base <> "/s.xml"), target,
                 cacerts: pki.cacerts,
                 idle_timeout: 1
               )

      assert File.read!(target) == "abcdef"
    end
  end

  describe "request headers and conditional requests" do
    @tag rfc: ["8182#3.4.1", "8182#3.4.4"],
         doc: """
         The server answers 304 only to the Last-Modified value it gave.
         The first fetch returns that value; the second sends it as
         If-Modified-Since and leaves the file alone.
         """
    test "Last-Modified is returned, sent back as If-Modified-Since, and a 304 is :not_modified",
         %{tmp_dir: dir} do
      test = self()
      date = "Tue, 17 Nov 2026 12:00:00 GMT"

      {base, _port, pki} =
        serve(%{
          "/notification.xml" => fn request ->
            send(test, {:request, request.headers})

            if List.keyfind(request.headers, "if-modified-since", 0) ==
                 {"if-modified-since", date},
               do: {304, [], ""},
               else: {200, [{"last-modified", date}], "<notification/>"}
          end
        })

      uri = uri!(base <> "/notification.xml")
      target = Path.join(dir, "notification.xml")

      assert {:ok, %{last_modified: ^date, headers: headers}} =
               HTTPS.fetch_to_file(uri, target, cacerts: pki.cacerts)

      assert {"last-modified", date} in headers
      assert_received {:request, first}
      refute List.keymember?(first, "if-modified-since", 0)
      File.write!(target, "kept")

      assert {:ok, :not_modified} =
               HTTPS.fetch_to_file(uri, target, cacerts: pki.cacerts, if_modified_since: date)

      assert_received {:request, second}
      assert {"if-modified-since", date} in second
      assert File.read!(target) == "kept"
    end

    @tag rfc: "8182#3.4.1",
         doc: "RFC 8182 §3.4.1 RECOMMENDS a User-Agent naming the RP and its version."
    test "requests name lumina and its version, and ask for no content coding",
         %{tmp_dir: dir} do
      test = self()

      {base, _port, pki} =
        serve(%{
          "/n.xml" => fn request ->
            send(test, {:request, request.headers})
            {200, [], "x"}
          end
        })

      assert {:ok, %{last_modified: nil}} =
               HTTPS.fetch_to_file(uri!(base <> "/n.xml"), Path.join(dir, "n.xml"),
                 cacerts: pki.cacerts
               )

      assert_received {:request, headers}
      assert {"user-agent", "lumina/#{Lumina.version()}"} in headers
      assert {"accept-encoding", "identity"} in headers
    end

    @tag doc: "Without If-Modified-Since a 304 is just an unexpected status."
    test "a 304 to an unconditional request is :http_status", %{tmp_dir: dir} do
      {base, _port, pki} = serve(%{"/n.xml" => {304, [], ""}})

      assert {:error, %{reason: :http_status, detail: 304}} =
               HTTPS.fetch_to_file(uri!(base <> "/n.xml"), Path.join(dir, "n.xml"),
                 cacerts: pki.cacerts
               )
    end
  end

  describe "same-origin redirects (RFC 9674)" do
    @tag rfc: "9674#3.2"
    test "a redirect to the same origin is followed", %{tmp_dir: dir} do
      {base, _port, pki} =
        serve(%{
          "/old.xml" => redirect(302, &"https://LOCALHOST:#{&1}/new.xml"),
          "/new.xml" => {200, [], "moved"}
        })

      target = Path.join(dir, "n.xml")

      assert {:ok, %{uri: uri}} =
               HTTPS.fetch_to_file(uri!(base <> "/old.xml"), target,
                 cacerts: pki.cacerts,
                 same_origin: true
               )

      assert to_string(uri) == base <> "/new.xml"
      assert File.read!(target) == "moved"
    end

    @tag rfc: "9674#3.2",
         doc:
           "RFC 9674 §3.2: implementations SHOULD log a message when cross-origin redirects are detected."
    test "a redirect to another host fails as :cross_origin_redirect and is logged",
         %{tmp_dir: dir} do
      {base, port, pki} =
        serve(%{"/n.xml" => redirect(302, &"https://127.0.0.1:#{&1}/n.xml")})

      log =
        capture_log(fn ->
          assert {:error, %{reason: :cross_origin_redirect}} =
                   HTTPS.fetch_to_file(uri!(base <> "/n.xml"), Path.join(dir, "n.xml"),
                     cacerts: pki.cacerts,
                     same_origin: true
                   )
        end)

      assert log =~ "https://127.0.0.1:#{port}/n.xml"
      assert log =~ "RFC 9674"
      assert files(dir) == []
    end

    @tag rfc: "9674#3.2"
    test "a redirect to another port fails as :cross_origin_redirect", %{tmp_dir: dir} do
      {base, _port, pki} =
        serve(%{"/n.xml" => redirect(302, &"https://localhost:#{&1 + 1}/n.xml")})

      capture_log(fn ->
        assert {:error, %{reason: :cross_origin_redirect}} =
                 HTTPS.fetch_to_file(uri!(base <> "/n.xml"), Path.join(dir, "n.xml"),
                   cacerts: pki.cacerts,
                   same_origin: true
                 )
      end)
    end

    @tag rfc: "9674#3.2"
    test "a redirect to http on the same host fails as :cross_origin_redirect", %{tmp_dir: dir} do
      {base, _port, pki} =
        serve(%{"/n.xml" => redirect(301, &"http://localhost:#{&1}/n.xml")})

      capture_log(fn ->
        assert {:error, %{reason: :cross_origin_redirect}} =
                 HTTPS.fetch_to_file(uri!(base <> "/n.xml"), Path.join(dir, "n.xml"),
                   cacerts: pki.cacerts,
                   same_origin: true
                 )
      end)
    end

    @tag rfc: "9674#3.2",
         doc: """
         For a snapshot or delta the origin is the notification's, passed
         as :same_origin. Here the snapshot URI is on the same server, and
         the notification URI on another port.
         """
    test "the origin can be given as the notification URI", %{tmp_dir: dir} do
      {base, port, pki} = serve(%{"/s.xml" => {302, [{"location", "/t.xml"}], ""}})
      notify = uri!("https://localhost:#{port + 1}/notification.xml")

      capture_log(fn ->
        assert {:error, %{reason: :cross_origin_redirect}} =
                 HTTPS.fetch_to_file(uri!(base <> "/s.xml"), Path.join(dir, "s.xml"),
                   cacerts: pki.cacerts,
                   same_origin: notify
                 )
      end)
    end

    test "without :same_origin a redirect to another host is followed", %{tmp_dir: dir} do
      {base, port, pki} =
        serve(%{
          "/old.xml" => redirect(302, &"https://127.0.0.1:#{&1}/new.xml"),
          "/new.xml" => {200, [], "moved"}
        })

      # The certificate names only localhost, so the TLS check on
      # 127.0.0.1 shows the redirect was followed.
      capture_log(fn ->
        assert {:error, %{reason: :tls_hostname, uri: uri}} =
                 HTTPS.fetch_to_file(uri!(base <> "/old.xml"), Path.join(dir, "n.xml"),
                   cacerts: pki.cacerts
                 )

        assert uri == "https://127.0.0.1:#{port}/new.xml"
      end)
    end
  end

  # The largest heap plus held binaries seen while `pid` runs.
  defp sample(pid, peak) do
    case Process.info(pid, [:memory, :binary]) do
      [memory: memory, binary: binaries] ->
        held = binaries |> Enum.map(&elem(&1, 1)) |> Enum.sum()
        Process.sleep(5)
        sample(pid, max(peak, memory + held))

      nil ->
        peak
    end
  end
end
