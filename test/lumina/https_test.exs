defmodule Lumina.HTTPSTest do
  @moduledoc """
  Tests the HTTPS fetcher (`Lumina.HTTPS`, #73) against a local TLS server
  (`Lumina.Test.HTTPSServer`) whose CA and certificates are made in each
  test, so nothing depends on the network or on the system's CA store.

  RFC 8630 §4 makes TLS certificate and host name validation mandatory for
  TA certificates fetched over HTTPS, and asks for validation issues to be
  logged: each kind of bad certificate must be rejected with its own
  reason and a log line. The rest pins D-008's limits: redirects only to
  HTTPS and at most 3, and a size limit that holds however the server
  frames the body (Content-Length, chunked, or until it closes, F-026).
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Lumina.{HTTPS, URI}
  alias Lumina.Test.{HTTPSServer, RsyncDaemon}

  @body :binary.copy(<<0x30, 0x82>>, 600)

  defp uri!(string) do
    {:ok, uri} = URI.parse(string)
    uri
  end

  defp serve(routes, pki_opts \\ []) do
    pki = HTTPSServer.pki(pki_opts)
    port = HTTPSServer.start!(pki, routes)
    {"https://localhost:#{port}", pki}
  end

  describe "certificate validation" do
    @tag rfc: "8630#4"
    test "a file from a server with a valid certificate is fetched byte-identical" do
      {base, pki} = serve(%{"/ta/ta.cer" => {200, [], @body}})

      assert {:ok, %{body: @body, uri: uri}} =
               HTTPS.fetch(uri!(base <> "/ta/ta.cer"), cacerts: pki.cacerts)

      assert to_string(uri) == base <> "/ta/ta.cer"
    end

    @tag rfc: "8630#4"
    test "a certificate for another host name is rejected and logged" do
      {base, pki} = serve(%{"/ta.cer" => {200, [], @body}}, host: "other.example")

      log =
        capture_log(fn ->
          assert {:error, %{reason: :tls_hostname}} =
                   HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts)
        end)

      assert log =~ "TLS validation failed for #{base}/ta.cer: tls_hostname"
    end

    @tag rfc: "8630#4"
    test "a certificate from a CA that isn't trusted is rejected and logged" do
      {base, _pki} = serve(%{"/ta.cer" => {200, [], @body}})
      other = HTTPSServer.pki()

      log =
        capture_log(fn ->
          assert {:error, %{reason: :tls_untrusted}} =
                   HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: other.cacerts)
        end)

      assert log =~ "tls_untrusted"
    end

    @tag rfc: "8630#4"
    test "an expired certificate is rejected and logged" do
      {base, pki} =
        serve(%{"/ta.cer" => {200, [], @body}}, validity: {{2020, 1, 1}, {2021, 1, 1}})

      log =
        capture_log(fn ->
          assert {:error, %{reason: :tls_expired}} =
                   HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts)
        end)

      assert log =~ "tls_expired"
    end

    @tag rfc: "8630#4"
    test "a certificate that isn't valid yet is rejected and logged" do
      {base, pki} =
        serve(%{"/ta.cer" => {200, [], @body}}, validity: {{2090, 1, 1}, {2100, 1, 1}})

      log =
        capture_log(fn ->
          assert {:error, %{reason: :tls_expired}} =
                   HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts)
        end)

      assert log =~ "tls_expired"
    end

    @tag rfc: "8630#4",
         doc: "A host given as an IP address must match the certificate too; a dNSName doesn't."
    test "a URI with an IP address is rejected when the certificate only names a host" do
      {base, pki} = serve(%{"/ta.cer" => {200, [], @body}})
      ip_base = String.replace(base, "localhost", "127.0.0.1")

      capture_log(fn ->
        assert {:error, %{reason: :tls_hostname}} =
                 HTTPS.fetch(uri!(ip_base <> "/ta.cer"), cacerts: pki.cacerts)
      end)
    end

    @tag rfc: "8630#4",
         doc: "Without :cacerts the system CA store is used, and it doesn't trust a test CA."
    test "by default only the system CA store is trusted" do
      {base, _pki} = serve(%{"/ta.cer" => {200, [], @body}})

      capture_log(fn ->
        assert {:error, %{reason: :tls_untrusted}} = HTTPS.fetch(uri!(base <> "/ta.cer"))
      end)
    end
  end

  describe "wildcard certificates (D-010)" do
    @tag rfc: "8630#4",
         doc: """
         RFC 8630 §4: server names SHOULD NOT contain "*". The fetch succeeds,
         with a log line and a warning in the result. :address connects to
         127.0.0.1 while the name checked stays rpki.example.test.
         """
    test "a certificate that matches only by wildcard is accepted, logged and reported" do
      {base, pki} = serve(%{"/ta.cer" => {200, [], @body}}, host: "*.example.test")
      uri = String.replace(base, "localhost", "rpki.example.test") <> "/ta.cer"

      log =
        capture_log(fn ->
          assert {:ok,
                  %{body: @body, warnings: [{:wildcard_certificate, ^uri, "*.example.test"}]}} =
                   HTTPS.fetch(uri!(uri), cacerts: pki.cacerts, address: {127, 0, 0, 1})
        end)

      assert log =~ "only by wildcard (*.example.test)"
    end

    test "a certificate that also names the host exactly gives no warning" do
      {base, pki} = serve(%{"/ta.cer" => {200, [], @body}}, host: ["*.example.test", "localhost"])

      assert {:ok, %{warnings: []}} = HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts)
    end

    @tag rfc: "8630#4"
    test "a wildcard covers one label only" do
      {base, pki} = serve(%{"/ta.cer" => {200, [], @body}}, host: "*.example.test")
      uri = String.replace(base, "localhost", "a.b.example.test") <> "/ta.cer"

      capture_log(fn ->
        assert {:error, %{reason: :tls_hostname}} =
                 HTTPS.fetch(uri!(uri), cacerts: pki.cacerts, address: {127, 0, 0, 1})
      end)
    end
  end

  describe "redirects (D-008)" do
    test "a redirect to another HTTPS URI is followed, and the final URI reported" do
      {base, pki} =
        serve(%{
          "/old.cer" => {301, [{"location", "/new/ta.cer"}], ""},
          "/new/ta.cer" => {200, [], @body}
        })

      assert {:ok, %{body: @body, uri: uri}} =
               HTTPS.fetch(uri!(base <> "/old.cer"), cacerts: pki.cacerts)

      assert to_string(uri) == base <> "/new/ta.cer"
    end

    test "a redirect to http:// is refused" do
      {base, pki} = serve(%{"/ta.cer" => {302, [{"location", "http://localhost/ta.cer"}], ""}})

      assert {:error, %{reason: :redirect_not_https, detail: "http://localhost/ta.cer"}} =
               HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts)
    end

    test "three redirects are followed, a fourth is refused" do
      chain = fn n -> {307, [{"location", "/r#{n}"}], ""} end

      {base, pki} =
        serve(%{
          "/r0" => chain.(1),
          "/r1" => chain.(2),
          "/r2" => chain.(3),
          "/r3" => {200, [], @body},
          "/s0" => {308, [{"location", "/r0"}], ""}
        })

      assert {:ok, %{body: @body}} = HTTPS.fetch(uri!(base <> "/r0"), cacerts: pki.cacerts)

      assert {:error, %{reason: :too_many_redirects}} =
               HTTPS.fetch(uri!(base <> "/s0"), cacerts: pki.cacerts)
    end

    @tag doc:
           "The target must pass Lumina.URI.parse/1, like any URI from a repository; a query doesn't."
    test "a redirect to a URI Lumina doesn't accept is refused" do
      {base, pki} = serve(%{"/ta.cer" => {302, [{"location", "/ta.cer?v=2"}], ""}})

      assert {:error, %{reason: :bad_redirect}} =
               HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts)
    end
  end

  describe "size limit (D-008)" do
    test "a body whose Content-Length is over the limit is refused" do
      {base, pki} = serve(%{"/ta.cer" => {200, [], @body}})

      assert {:error, %{reason: :too_large, detail: 1000}} =
               HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts, max_size: 1000)
    end

    @tag doc: "F-026: the case OTP's :httpc can't bound. The server just keeps sending."
    test "a body sent until the server closes is cut off at the limit" do
      {base, pki} =
        serve(%{"/ta.cer" => {:raw, ["HTTP/1.1 200 OK\r\n\r\n", :binary.copy("x", 5000)]}})

      assert {:error, %{reason: :too_large}} =
               HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts, max_size: 1000)
    end

    test "a chunked body over the limit is cut off" do
      chunk = "200\r\n" <> :binary.copy("x", 512) <> "\r\n"

      {base, pki} =
        serve(%{
          "/ta.cer" =>
            {:raw,
             ["HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n", List.duplicate(chunk, 4)]}
        })

      assert {:error, %{reason: :too_large}} =
               HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts, max_size: 1000)
    end
  end

  describe "responses" do
    @tag doc: "RFC 9112 §7.1 chunked framing, which servers may use for any response."
    test "a chunked body is decoded" do
      {base, pki} =
        serve(%{
          "/ta.cer" =>
            {:raw,
             "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"}
        })

      assert {:ok, %{body: "abcde"}} = HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts)
    end

    test "a body that ends before its Content-Length is :truncated" do
      {base, pki} =
        serve(%{"/ta.cer" => {:raw, "HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort"}})

      assert {:error, %{reason: :truncated}} =
               HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts)
    end

    test "a status other than 200 is :http_status" do
      {base, pki} = serve(%{})

      assert {:error, %{reason: :http_status, detail: 404}} =
               HTTPS.fetch(uri!(base <> "/missing.cer"), cacerts: pki.cacerts)
    end

    test "a response that isn't HTTP is :bad_response" do
      {base, pki} = serve(%{"/ta.cer" => {:raw, "SSH-2.0-nope\r\n\r\n"}})

      assert {:error, %{reason: :bad_response}} =
               HTTPS.fetch(uri!(base <> "/ta.cer"), cacerts: pki.cacerts)
    end
  end

  describe "connection failures" do
    test "a refused connection is :connection_refused" do
      uri = uri!("https://localhost:#{RsyncDaemon.closed_port()}/ta.cer")
      assert {:error, %{reason: :connection_refused}} = HTTPS.fetch(uri)
    end

    test "a host that doesn't resolve is :unknown_host" do
      assert {:error, %{reason: :unknown_host}} =
               HTTPS.fetch(uri!("https://no-such-host.invalid/ta.cer"))
    end

    @tag doc: "A server that accepts TCP and never starts TLS hits the connect timeout (D-008)."
    test "a server that never answers times out" do
      uri = uri!("https://localhost:#{RsyncDaemon.silent_server!()}/ta.cer")

      assert {:error, %{reason: :connect_timeout}} =
               HTTPS.fetch(uri, connect_timeout: 1, timeout: 5)
    end
  end
end
