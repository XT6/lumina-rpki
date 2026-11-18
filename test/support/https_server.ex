defmodule Lumina.Test.HTTPSServer do
  @moduledoc ~S"""
  A small HTTPS server for tests of `Lumina.HTTPS` (#73), on 127.0.0.1 and
  a free port, with certificates made in the test by OTP's
  `:public_key.pkix_test_data/1`.

      pki = Lumina.Test.HTTPSServer.pki(host: "localhost")
      port = Lumina.Test.HTTPSServer.start!(pki, %{"/ta.cer" => {200, [], "bytes"}})
      {:ok, uri} = Lumina.URI.parse("https://localhost:#{port}/ta.cer")
      Lumina.HTTPS.fetch(uri, cacerts: pki.cacerts)

  Routes map a request path to a response:

    * `{status, headers, body}`, sent with a Content-Length;
    * `{:raw, iodata}`, sent exactly as given after the request is read
      (for chunked, close-delimited and broken responses);
    * `{:file, path}`, a 200 with the file's Content-Length, its contents
      sent 64 KiB at a time (large bodies, #200);
    * `{:script, steps}`, each step iodata sent as given or `{:sleep, ms}`
      (slow and stalling bodies);
    * a function of the request, `%{path: path, headers: headers}`
      (header names in lower case), returning one of the above.

  `routes` can also be one function of the request, for every path (a
  test that changes what is served between requests).

  Any other path is a 404. One request per connection. The server stops
  when the test exits.
  """

  import ExUnit.Callbacks, only: [on_exit: 1]

  @type pki :: %{cert: binary(), key: term(), cacerts: [binary()]}
  @type response ::
          {pos_integer(), [{String.t(), String.t()}], binary()}
          | {:raw, iodata()}
          | {:file, Path.t()}
          | {:script, [iodata() | {:sleep, non_neg_integer()}]}

  @doc """
  A test CA and a server certificate it signed. Options: `:host` (the
  certificate's dNSName, or a list of them; default `"localhost"`) and `:validity`
  (`{from_date, to_date}`, default 2020-01-01 to 2100-01-01).
  """
  @spec pki(keyword()) :: pki()
  def pki(opts \\ []) do
    host = Keyword.get(opts, :host, "localhost")
    validity = Keyword.get(opts, :validity, {{2020, 1, 1}, {2100, 1, 1}})
    names = for name <- List.wrap(host), do: {:dNSName, String.to_charlist(name)}
    san = {:Extension, {2, 5, 29, 17}, false, names}
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

  @doc """
  A cross-signed chain, as rrdp.apnic.net served in November 2026 (#209):
  the server sends its certificate and its root's certificate as issued
  by another, older root (same subject and key, a different issuer). The
  client is to trust only the root's self-signed certificate (`cacerts`),
  so the chain the server sends ends at a root it doesn't know, and only
  the other path, through the self-signed one, validates. `old_root` is
  the older root's certificate.
  """
  @spec cross_signed_pki() :: %{
          cert: [binary()],
          key: term(),
          cacerts: [binary()],
          old_root: binary()
        }
  def cross_signed_pki do
    pki = pki()

    # The root that issued the server's certificate, among the CA
    # certificates OTP's test data gives (a client root is there too).
    tbs = fn der -> der |> :public_key.pkix_decode_cert(:otp) |> elem(1) end
    issuer = elem(tbs.(pki.cert), 4)
    root = Enum.find(pki.cacerts, &(elem(tbs.(&1), 6) == issuer))
    # secp256r1, by OID as pkix_test_root_cert/2's spec asks.
    key = [key: {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}, digest: :sha256]
    old = :public_key.pkix_test_root_cert(~c"Old Root", key)

    root_tbs = tbs.(root)
    old_tbs = tbs.(old.cert)

    # The root's name and key, issued by the old root: the issuer and
    # serial change, and the key identifier extensions go, so the only
    # link is the name.
    cross_tbs =
      root_tbs
      |> put_elem(2, 4_242)
      |> put_elem(4, elem(old_tbs, 6))
      |> put_elem(10, elem(root_tbs, 10) |> Enum.reject(&(elem(&1, 1) == {2, 5, 29, 35})))

    cross = :public_key.pkix_sign(cross_tbs, old.key)
    %{cert: [pki.cert, cross], key: pki.key, cacerts: [root], old_root: old.cert}
  end

  @doc """
  Routes serving every file under `dir` at `prefix` plus its relative
  path, such as a fixture's `rrdp/` at `"/rrdp/"` (#202). Fixture URIs
  name `localhost:8443`; fetch them with
  `remap: %{"localhost:8443" => "localhost:<port>"}`.
  """
  @spec dir_routes(Path.t(), String.t()) :: %{String.t() => {:file, Path.t()}}
  def dir_routes(dir, prefix) do
    for path <- Path.wildcard(Path.join(dir, "**/*")), File.regular?(path), into: %{} do
      {prefix <> Path.relative_to(path, dir), {:file, path}}
    end
  end

  @doc "Starts the server; returns its port."
  @spec start!(pki(), %{String.t() => response() | (map() -> response())} | (map() -> response())) ::
          :inet.port_number()
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
         {:ok, request} <- read_request(socket, "") do
      route =
        if is_function(routes, 1),
          do: routes,
          else: Map.get(routes, request.path, {404, [], "not found"})

      response = if is_function(route, 1), do: route.(request), else: route

      _ = respond(socket, response)
      _ = :ssl.close(socket)
    end
  end

  defp read_request(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      [head | _] = String.split(acc, "\r\n\r\n", parts: 2)
      [request_line | lines] = String.split(head, "\r\n")
      [_method, path | _] = String.split(request_line, " ", parts: 3)

      headers =
        for line <- lines, [name, value] = String.split(line, ":", parts: 2) do
          {String.downcase(name), String.trim(value)}
        end

      {:ok, %{path: path, headers: headers}}
    else
      with {:ok, data} <- :ssl.recv(socket, 0, 5_000), do: read_request(socket, acc <> data)
    end
  end

  defp respond(socket, {:raw, data}), do: _ = :ssl.send(socket, data)

  defp respond(socket, {:file, path}) do
    with :ok <- :ssl.send(socket, head(200, [{"content-length", "#{File.stat!(path).size}"}])) do
      path |> File.stream!(65_536) |> Enum.reduce_while(:ok, &send_part(socket, &1, &2))
    end
  end

  defp respond(socket, {:script, steps}) do
    Enum.reduce_while(steps, :ok, fn
      {:sleep, ms}, :ok ->
        Process.sleep(ms)
        {:cont, :ok}

      data, :ok ->
        send_part(socket, data, :ok)
    end)
  end

  defp respond(socket, {status, headers, body}) do
    _ =
      :ssl.send(socket, [head(status, [{"content-length", "#{byte_size(body)}"} | headers]), body])
  end

  defp send_part(socket, data, :ok) do
    case :ssl.send(socket, data) do
      :ok -> {:cont, :ok}
      error -> {:halt, error}
    end
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
