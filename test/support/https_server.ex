defmodule Lumina.Test.HTTPSServer do
  @moduledoc ~S"""
  A small HTTPS server for tests of `Lumina.HTTPS` (#73), on 127.0.0.1 and
  a free port, with certificates made in the test by OTP's
  `:public_key.pkix_test_data/1`.

      pki = Lumina.Test.HTTPSServer.pki(host: "localhost")
      port = Lumina.Test.HTTPSServer.start!(pki, %{"/ta.cer" => {200, [], "bytes"}})
      {:ok, uri} = Lumina.URI.parse("https://localhost:#{port}/ta.cer")
      Lumina.HTTPS.fetch(uri, cacerts: pki.cacerts)

  Routes map a request path to `{status, headers, body}`, sent with a
  Content-Length, or to `{:raw, iodata}`, sent exactly as given after the
  request is read (for chunked, close-delimited and broken responses).
  Any other path is a 404. One request per connection. The server stops
  when the test exits.
  """

  import ExUnit.Callbacks, only: [on_exit: 1]

  @type pki :: %{cert: binary(), key: term(), cacerts: [binary()]}

  @doc """
  A test CA and a server certificate it signed. Options: `:host` (the
  certificate's dNSName, default `"localhost"`) and `:validity`
  (`{from_date, to_date}`, default 2020-01-01 to 2100-01-01).
  """
  @spec pki(keyword()) :: pki()
  def pki(opts \\ []) do
    host = Keyword.get(opts, :host, "localhost")
    validity = Keyword.get(opts, :validity, {{2020, 1, 1}, {2100, 1, 1}})
    san = {:Extension, {2, 5, 29, 17}, false, [dNSName: String.to_charlist(host)]}
    # OTP's default test certificates are signed with SHA-1, which TLS 1.3 refuses.
    key = [key: {:namedCurve, :secp256r1}, digest: :sha256]

    %{server_config: config} =
      :public_key.pkix_test_data(%{
        server_chain: %{
          root: key,
          intermediates: [],
          peer: key ++ [extensions: [san], validity: validity]
        },
        client_chain: %{root: [], intermediates: [], peer: []}
      })

    %{cert: config[:cert], key: config[:key], cacerts: config[:cacerts]}
  end

  @doc "Starts the server; returns its port."
  @spec start!(pki(), %{
          String.t() => {pos_integer(), [{String.t(), String.t()}], binary()} | {:raw, iodata()}
        }) :: :inet.port_number()
  def start!(pki, routes) do
    {:ok, listen} =
      :ssl.listen(0,
        ip: {127, 0, 0, 1},
        cert: pki.cert,
        key: pki.key,
        versions: [:"tlsv1.3", :"tlsv1.2"],
        reuseaddr: true,
        active: false,
        mode: :binary
      )

    {:ok, {_, port}} = :ssl.sockname(listen)
    server = spawn(fn -> accept_loop(listen, routes) end)
    :ok = :ssl.controlling_process(listen, server)
    on_exit(fn -> Process.exit(server, :kill) end)
    port
  end

  defp accept_loop(listen, routes) do
    with {:ok, socket} <- :ssl.transport_accept(listen) do
      pid = spawn(fn -> serve(socket, routes) end)
      _ = :ssl.controlling_process(socket, pid)
      send(pid, :go)
      accept_loop(listen, routes)
    end
  end

  defp serve(socket, routes) do
    receive do
      :go -> :ok
    end

    with {:ok, socket} <- :ssl.handshake(socket, 5_000),
         {:ok, path} <- read_request(socket, "") do
      _ = respond(socket, Map.get(routes, path, {404, [], "not found"}))
      _ = :ssl.close(socket)
    end
  end

  defp read_request(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      [_method, path | _] = String.split(acc, " ", parts: 3)
      {:ok, path}
    else
      with {:ok, data} <- :ssl.recv(socket, 0, 5_000), do: read_request(socket, acc <> data)
    end
  end

  defp respond(socket, {:raw, data}), do: _ = :ssl.send(socket, data)

  defp respond(socket, {status, headers, body}) do
    _ =
      :ssl.send(socket, [head(status, [{"content-length", "#{byte_size(body)}"} | headers]), body])
  end

  defp head(status, headers) do
    [
      "HTTP/1.1 #{status} X\r\n",
      "connection: close\r\n",
      for({name, value} <- headers, do: "#{name}: #{value}\r\n"),
      "\r\n"
    ]
  end
end
