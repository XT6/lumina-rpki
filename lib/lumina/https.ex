defmodule Lumina.HTTPS do
  @moduledoc """
  Fetches a single file, such as a TA certificate, over HTTPS (RFC 8630
  §4, D-003), with the limits of D-008 (#73).

  RFC 8630 §4: RPs MUST validate the TLS certificate and host name, and
  SHOULD log any validation issue. The connection uses OTP's `:ssl`
  directly:

    * `verify_peer` against the operating system's CA store
      (`:public_key.cacerts_get/0`), or the `:cacerts` option in tests;
    * host name checked against the certificate's subjectAltName dNSName
      (RFC 6125 via `:public_key.pkix_verify_hostname_match_fun(:https)`);
    * TLS 1.2 or 1.3 only.

  Every TLS validation failure is logged as a warning, with the URI and
  the reason. A certificate that matched the host only through a wildcard
  dNSName is accepted, but logged and reported in `:warnings`: RFC 8630 §4
  says repository server names SHOULD NOT contain `*` (D-010).

  The HTTP side is a minimal HTTP/1.1 GET with `Connection: close`. OTP's
  `:httpc` isn't used: it can't bound a response body that has no
  Content-Length and ends when the server closes, so a hostile server
  could make it hold any amount of memory (F-026). Here every body is
  bounded by `:max_size`, every read by a timeout, and the response head
  by 64 KiB. Bodies come with a Content-Length, chunked (RFC 9112 §7.1)
  or until the server closes; a body that ends before its Content-Length
  or its last chunk is `:truncated`. Requests send
  `User-Agent: lumina/<version>` (RFC 8182 §3.4.1) and
  `Accept-Encoding: identity`, so no content coding is ever applied.

  `fetch/2` returns the body in memory (TA certificates, D-008: 20 MiB
  and 300 s for the whole fetch). `fetch_to_file/3` streams it to a file
  for RRDP (#200, D-043: 2 GiB, no total time limit but 300 s without
  data), with conditional requests (RFC 8182 §3.4.4) and optionally
  same-origin redirects only (RFC 9674 §3.2).

  Redirects (301, 302, 303, 307, 308) are followed up to `:max_redirects`
  times, and only to `https://` URIs that `Lumina.URI.parse/1` accepts
  (D-008).

  Failures are `{:error, %{reason: reason, uri: uri, detail: term}}`, where
  `uri` is the URI that failed (after any redirects) and `reason` is one
  of:

    * `:tls_untrusted`, `:tls_expired` (expired or not yet valid),
      `:tls_hostname`, `:tls_error` (any other TLS failure)
    * `:connection_refused`, `:unknown_host`, `:socket_error`
    * `:connect_timeout`, `:timeout` (`detail` is `:deadline` for the
      total time, `:idle` for the time without data)
    * `:http_status` (`detail` is the status code), `:bad_response`,
      `:truncated` (the body ended before its Content-Length or last chunk)
    * `:too_large` (`detail` is the limit)
    * `:redirect_not_https`, `:bad_redirect`, `:too_many_redirects`,
      `:cross_origin_redirect` (with `:same_origin`)
    * `:file_error` (`fetch_to_file/3` couldn't write the file)
  """

  require Logger

  alias Lumina.URI

  @defaults [connect_timeout: 30, timeout: 300, max_size: 20 * 1024 * 1024, max_redirects: 3]
  # D-043: snapshots and deltas up to 2 GiB, no total time limit.
  @file_defaults [
    connect_timeout: 30,
    idle_timeout: 300,
    max_size: 2 * 1024 * 1024 * 1024,
    max_redirects: 3,
    same_origin: false
  ]
  @max_head 65_536
  @redirects [301, 302, 303, 307, 308]

  @type error :: %{reason: atom(), uri: String.t(), detail: term()}

  @type file_result :: %{
          uri: URI.t(),
          sha256: <<_::256>>,
          size: non_neg_integer(),
          headers: [{String.t(), String.t()}],
          last_modified: String.t() | nil,
          warnings: [tuple()]
        }

  @doc """
  Fetches `uri` and returns its body, and the URI it finally came from.

  Options: `:connect_timeout` and `:timeout` (seconds; defaults 30 and
  300, the second for the whole fetch, redirects included), `:max_size`
  (bytes; default 20 MiB), `:max_redirects` (default 3), and `:cacerts`
  (DER CA certificates to trust instead of the system store) and
  `:address` (an IP address tuple to connect to instead of resolving the
  host, which is still the name checked) and `:remap` (a map from
  `"host:port"` in URIs to the `"host:port"` actually connected to, as
  `Lumina.Walk`'s for rsync: URIs, origins and the name checked stay as
  they are); the last three are for tests.

  `:warnings` lists `{:wildcard_certificate, uri, name}` for each server
  on the way whose certificate matched only through a wildcard.
  """
  @spec fetch(URI.t(), keyword()) ::
          {:ok, %{body: binary(), uri: URI.t(), warnings: [tuple()]}} | {:error, error()}
  def fetch(%URI{scheme: "https"} = uri, opts \\ []) do
    opts = Keyword.merge(@defaults, opts)
    timer = {:deadline, System.monotonic_time(:millisecond) + opts[:timeout] * 1000}

    with {:ok, result} <- follow(uri, uri, :memory, opts, timer, opts[:max_redirects], []),
         do: {:ok, Map.take(result, [:body, :uri, :warnings])}
  end

  @doc """
  Fetches `uri` into the file `path` (#200): the body is streamed to a
  temporary file next to `path`, its SHA-256 computed on the way, and the
  file renamed to `path` only when the whole body has arrived. On any
  failure `path` is left as it was and the temporary file removed.

  Returns the URI the body finally came from, its `sha256` (32 raw bytes)
  and `size`, the response `headers` (names in lower case), its
  `last_modified` header (or `nil`) and `warnings` as for `fetch/2`. With
  `:if_modified_since` (a `Last-Modified` value from an earlier fetch,
  sent as given, RFC 9110 §13.1.3), a `304` returns `{:ok, :not_modified}`
  and leaves `path` alone (RFC 8182 §3.4.4).

  Options (D-043): `:max_size` (bytes; default 2 GiB), `:idle_timeout`
  (seconds without data; default 300; there is no total limit),
  `:connect_timeout` (default 30), `:max_redirects` (default 3),
  `:same_origin` (`true` follows only redirects to the scheme, host and
  port of `uri`; a `Lumina.URI`, typically the notification URI when
  fetching a snapshot or delta, to that URI's; RFC 9674 §3.2: others fail
  as `:cross_origin_redirect` and are logged), `:on_data` (a function
  called with the bytes received so far after each piece of the body is
  written, for progress; a two-argument function also gets the length
  the response announced, or `nil` without a Content-Length), and `:cacerts`, `:address` and `:remap` as for
  `fetch/2`.
  """
  @spec fetch_to_file(URI.t(), Path.t(), keyword()) ::
          {:ok, file_result()} | {:ok, :not_modified} | {:error, error()}
  def fetch_to_file(%URI{scheme: "https"} = uri, path, opts \\ []) do
    opts = Keyword.merge(@file_defaults, opts)
    timer = {:idle, opts[:idle_timeout] * 1000}
    origin = with(%URI{} = notify <- opts[:same_origin], do: notify, else: (_ -> uri))

    target = {:file, path, opts[:on_data]}

    case follow(uri, origin, target, opts, timer, opts[:max_redirects], []) do
      {:ok, %{body: body} = result} ->
        last_modified = result.headers |> List.keyfind("last-modified", 0) |> header_value()

        {:ok,
         result
         |> Map.delete(:body)
         |> Map.merge(body)
         |> Map.put(:last_modified, if(printable?(last_modified), do: last_modified))}

      other ->
        other
    end
  end

  defp follow(uri, origin, target, opts, timer, redirects_left, warnings) do
    conditional = printable?(opts[:if_modified_since])

    case get(uri, target, opts, timer) do
      {:ok, 200, headers, body, new} ->
        {:ok, %{body: body, headers: headers, uri: uri, warnings: warnings ++ new}}

      {:ok, 304, _headers, _, _} when conditional ->
        {:ok, :not_modified}

      {:ok, status, headers, _, new} when status in @redirects ->
        with {:ok, next} <- location(uri, origin, headers, opts) do
          if redirects_left > 0,
            do: follow(next, origin, target, opts, timer, redirects_left - 1, warnings ++ new),
            else: error(:too_many_redirects, uri, opts[:max_redirects])
        end

      {:ok, status, _headers, _, _} ->
        error(:http_status, uri, status)

      {:error, reason, detail} ->
        error(reason, uri, detail)
    end
  end

  # The redirect target, resolved against `uri` (RFC 9110 §10.2.2 allows a
  # relative reference). Only https:// targets are followed, and with
  # :same_origin only those of the first URI's origin (RFC 9674 §3.2).
  defp location(uri, origin, headers, opts) do
    case List.keyfind(headers, "location", 0) do
      {_, target} ->
        merged = Elixir.URI.merge(to_string(uri), target)

        cond do
          opts[:same_origin] && not same_origin?(merged, origin) ->
            Logger.warning(
              "#{uri} redirects to #{target}, of another origin than #{origin} (RFC 9674)"
            )

            error(:cross_origin_redirect, uri, target)

          merged.scheme != "https" ->
            error(:redirect_not_https, uri, target)

          true ->
            case URI.parse(Elixir.URI.to_string(merged)) do
              {:ok, next} -> {:ok, next}
              {:error, _} -> error(:bad_redirect, uri, target)
            end
        end

      nil ->
        error(:bad_redirect, uri, "no Location header")
    end
  rescue
    _ -> error(:bad_redirect, uri, "unparseable Location header")
  end

  # Elixir's URI fills in the scheme's default port and drops the brackets
  # of an IPv6 literal; Lumina.URI drops a default port and keeps them.
  defp same_origin?(%Elixir.URI{} = merged, %URI{} = origin) do
    host = fn h ->
      h |> String.trim_leading("[") |> String.trim_trailing("]") |> String.downcase()
    end

    merged.scheme == origin.scheme and is_binary(merged.host) and
      host.(merged.host) == host.(origin.host) and merged.port == (origin.port || 443)
  end

  defp printable?(value), do: is_binary(value) and value =~ ~r/\A[\x20-\x7e]+\z/

  defp error(reason, uri, detail) do
    if reason in [:tls_untrusted, :tls_expired, :tls_hostname, :tls_error] do
      Logger.warning("TLS validation failed for #{uri}: #{reason} (#{inspect(detail)})")
    end

    {:error, %{reason: reason, uri: to_string(uri), detail: detail}}
  end

  # One request.

  defp get(uri, target, opts, timer) do
    case connect(uri, opts, timer) do
      {:ok, socket} ->
        try do
          warnings = wildcard_warnings(socket, uri)

          with {:ok, status, headers, body} <- request(socket, uri, target, opts, timer),
               do: {:ok, status, headers, body, warnings}
        after
          _ = :ssl.close(socket)
        end

      error ->
        error
    end
  end

  defp connect(uri, opts, timer) do
    name = connect_host(uri.host)
    host = Keyword.get(opts, :address, name)
    timeout = min(opts[:connect_timeout] * 1000, remaining(timer))
    caller = self()
    ref = make_ref()

    # Called by :ssl for each certificate in the chain; it reports why the
    # chain was rejected, so the error can say so precisely. It fails with
    # the whole {:bad_cert, reason}, as :ssl's own does: only then does
    # :ssl try the other paths of a cross-signed chain (a root the store
    # holds under another issuer), so one rejected path isn't the verdict.
    verify = fn
      _cert, {:bad_cert, reason} = bad, _state ->
        send(caller, {ref, reason})
        {:fail, bad}

      _cert, {:extension, _}, state ->
        {:unknown, state}

      _cert, valid, state when valid in [:valid, :valid_peer] ->
        {:valid, state}
    end

    options = [
      verify: :verify_peer,
      cacerts: Keyword.get_lazy(opts, :cacerts, &:public_key.cacerts_get/0),
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)],
      verify_fun: {verify, nil},
      versions: [:"tlsv1.3", :"tlsv1.2"],
      depth: 10,
      active: false,
      mode: :binary
    ]

    # With :address or :remap, :ssl checks the name given as SNI. Never pass
    # `server_name_indication: :disable`: :ssl then skips the host name
    # check altogether (F-026).
    options =
      if (opts[:address] || opts[:remap]) && not ip_literal?(name),
        do: [{:server_name_indication, name} | options],
        else: options

    {host, port} = remap(uri, host, opts[:remap])
    result = :ssl.connect(host, port, options, timeout)

    # A path rejected on the way doesn't matter when another validated;
    # when none did, the last rejection says why.
    case {result, last_reason(ref, nil)} do
      {{:error, _}, reason} when reason != nil -> {:error, tls_reason(reason), reason}
      _ -> connect_result(result)
    end
  end

  defp last_reason(ref, last) do
    receive do
      {^ref, reason} -> last_reason(ref, reason)
    after
      0 -> last
    end
  end

  defp remap(uri, host, nil), do: {host, uri.port || 443}

  defp remap(uri, host, map) do
    authority = "#{uri.host}:#{uri.port || 443}"

    case Map.fetch(map, authority) do
      {:ok, target} ->
        [to_host, to_port] = String.split(target, ":")
        {String.to_charlist(to_host), String.to_integer(to_port)}

      :error ->
        {host, uri.port || 443}
    end
  end

  defp ip_literal?(name), do: match?({:ok, _}, :inet.parse_address(name))

  # The host passed the check; warn if no exact dNSName names it, so a
  # wildcard did (RFC 8630 §4, D-010).
  defp wildcard_warnings(socket, uri) do
    with {:ok, der} <- :ssl.peercert(socket),
         names = dns_names(der),
         wildcards = Enum.filter(names, &String.contains?(&1, "*")),
         true <- wildcards != [] and uri.host not in names do
      Logger.warning(
        "#{uri}: the server certificate names the host only by wildcard " <>
          "(#{Enum.join(wildcards, ", ")}); RFC 8630 §4 says it SHOULD NOT"
      )

      for name <- wildcards, do: {:wildcard_certificate, to_string(uri), name}
    else
      _ -> []
    end
  end

  defp dns_names(der) do
    {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(der, :otp)

    for {:Extension, {2, 5, 29, 17}, _, names} <- List.wrap(elem(tbs, 10)),
        {:dNSName, name} <- names,
        do: name |> to_string() |> String.downcase()
  end

  # "[::1]" is an IPv6 address literal; :ssl takes it without brackets.
  defp connect_host("[" <> rest), do: rest |> String.trim_trailing("]") |> String.to_charlist()
  defp connect_host(host), do: String.to_charlist(host)

  defp tls_reason(:cert_expired), do: :tls_expired
  defp tls_reason({:bad_cert, reason}), do: tls_reason(reason)
  defp tls_reason(:hostname_check_failed), do: :tls_hostname
  defp tls_reason(_), do: :tls_untrusted

  defp connect_result({:ok, socket}), do: {:ok, socket}
  defp connect_result({:error, :econnrefused}), do: {:error, :connection_refused, :econnrefused}
  defp connect_result({:error, :nxdomain}), do: {:error, :unknown_host, :nxdomain}
  defp connect_result({:error, :timeout}), do: {:error, :connect_timeout, :timeout}
  defp connect_result({:error, {:tls_alert, alert}}), do: {:error, :tls_error, alert}
  defp connect_result({:error, reason}), do: {:error, :socket_error, reason}

  defp request(socket, uri, target, opts, timer) do
    path = "/" <> Enum.join(uri.path, "/")
    host = if uri.port, do: "#{uri.host}:#{uri.port}", else: uri.host
    since = opts[:if_modified_since]

    head = [
      "GET #{path} HTTP/1.1\r\n",
      "Host: #{host}\r\n",
      "User-Agent: lumina/#{Lumina.version()}\r\n",
      "Accept: */*\r\n",
      "Accept-Encoding: identity\r\n",
      # Sent as given, but only as one printable line.
      if(printable?(since), do: "If-Modified-Since: #{since}\r\n", else: []),
      "Connection: close\r\n\r\n"
    ]

    with :ok <- send_request(socket, head),
         {:ok, status, headers, rest} <- read_head(socket, "", timer) do
      if status == 200 do
        with {:ok, body} <- body(socket, headers, rest, target, opts[:max_size], timer),
             do: {:ok, status, headers, body}
      else
        # Only the status and headers matter; the body isn't read.
        {:ok, status, headers, ""}
      end
    end
  end

  defp send_request(socket, head) do
    case :ssl.send(socket, head) do
      :ok -> :ok
      {:error, reason} -> {:error, :socket_error, reason}
    end
  end

  defp read_head(socket, acc, timer) do
    case :binary.split(acc, "\r\n\r\n") do
      [head, rest] ->
        parse_head(head, rest)

      [_] when byte_size(acc) > @max_head ->
        {:error, :bad_response, "response head too long"}

      [_] ->
        with {:ok, data} <- recv(socket, timer), do: read_head(socket, acc <> data, timer)
    end
  end

  defp parse_head(head, rest) do
    [status_line | lines] = String.split(head, "\r\n")

    with [_, code] <- Regex.run(~r/\AHTTP\/1\.[01] (\d{3})(?: |\z)/, status_line),
         {:ok, headers} <- parse_headers(lines, []) do
      {:ok, String.to_integer(code), headers, rest}
    else
      _ -> {:error, :bad_response, status_line}
    end
  end

  defp parse_headers([], acc), do: {:ok, Enum.reverse(acc)}

  defp parse_headers([line | lines], acc) do
    case String.split(line, ":", parts: 2) do
      [name, value] when name != "" ->
        parse_headers(lines, [{String.downcase(name), String.trim(value)} | acc])

      _ ->
        :error
    end
  end

  # The body goes to a sink: memory for fetch/2, a temporary file for
  # fetch_to_file/3, renamed into place only once the body is complete.
  defp body(socket, headers, rest, target, max, timer) do
    with {:ok, sink} <- open_sink(target, max) do
      sink = Map.put(sink, :total, content_length(headers))

      result =
        try do
          read_body(socket, headers, rest, sink, timer)
        catch
          kind, reason ->
            discard(sink)
            :erlang.raise(kind, reason, __STACKTRACE__)
        end

      case result do
        {:ok, sink} ->
          close_sink(sink)

        error ->
          discard(sink)
          error
      end
    end
  end

  defp open_sink(:memory, max), do: {:ok, %{out: :memory, acc: [], size: 0, max: max}}

  defp open_sink({:file, path, on_data}, max) do
    temp = "#{path}.#{System.unique_integer([:positive])}.part"

    with :ok <- File.mkdir_p(Path.dirname(path)),
         {:ok, io} <- :file.open(temp, [:write, :raw, :binary, :exclusive]) do
      {:ok,
       %{
         out: io,
         path: path,
         temp: temp,
         hash: :crypto.hash_init(:sha256),
         size: 0,
         max: max,
         on_data: on_data
       }}
    else
      {:error, reason} -> {:error, :file_error, reason}
    end
  end

  defp write(%{size: size, max: max}, data) when size + byte_size(data) > max,
    do: {:error, :too_large, max}

  defp write(%{out: :memory} = sink, data),
    do: {:ok, %{sink | acc: [sink.acc, data], size: sink.size + byte_size(data)}}

  defp write(sink, data) do
    case :file.write(sink.out, data) do
      :ok ->
        size = sink.size + byte_size(data)
        progress(sink.on_data, size, sink.total)
        {:ok, %{sink | hash: :crypto.hash_update(sink.hash, data), size: size}}

      {:error, reason} ->
        {:error, :file_error, reason}
    end
  end

  defp progress(nil, _size, _total), do: :ok
  defp progress(fun, size, total) when is_function(fun, 2), do: _ = fun.(size, total)
  defp progress(fun, size, _total), do: _ = fun.(size)

  # The body's announced length, for progress only (read_body/5 checks it).
  defp content_length(headers) do
    with value when is_binary(value) <-
           headers |> List.keyfind("content-length", 0) |> header_value(),
         {n, ""} when n >= 0 <- Integer.parse(value) do
      n
    else
      _ -> nil
    end
  end

  defp close_sink(%{out: :memory} = sink), do: {:ok, IO.iodata_to_binary(sink.acc)}

  defp close_sink(sink) do
    with :ok <- :file.close(sink.out),
         :ok <- :file.rename(sink.temp, sink.path) do
      {:ok, %{sha256: :crypto.hash_final(sink.hash), size: sink.size}}
    else
      {:error, reason} ->
        _ = :file.delete(sink.temp)
        {:error, :file_error, reason}
    end
  end

  defp discard(%{out: :memory}), do: :ok

  defp discard(sink) do
    _ = :file.close(sink.out)
    _ = :file.delete(sink.temp)
    :ok
  end

  # RFC 9112 §6.3: chunked if Transfer-Encoding says so, else
  # Content-Length, else everything until the server closes.
  defp read_body(socket, headers, rest, sink, timer) do
    encoding = headers |> List.keyfind("transfer-encoding", 0) |> header_value()
    length = headers |> List.keyfind("content-length", 0) |> header_value()

    cond do
      encoding != nil and String.ends_with?(String.downcase(encoding), "chunked") ->
        read_chunked(socket, rest, sink, timer)

      encoding != nil ->
        {:error, :bad_response, "unsupported transfer-encoding #{encoding}"}

      length != nil ->
        case Integer.parse(length) do
          {n, ""} when n > sink.max ->
            {:error, :too_large, sink.max}

          {n, ""} when n >= 0 ->
            with {:ok, sink, _rest} <- copy(socket, rest, n, sink, timer), do: {:ok, sink}

          _ ->
            {:error, :bad_response, "bad content-length #{length}"}
        end

      true ->
        read_until_close(socket, rest, sink, timer)
    end
  end

  defp header_value({_, value}), do: value
  defp header_value(nil), do: nil

  # Copies the next `n` body bytes, `buffer` first, to the sink as they
  # come; returns what follows them in the last read.
  defp copy(_socket, buffer, n, sink, _timer) when byte_size(buffer) >= n do
    <<data::binary-size(^n), rest::binary>> = buffer
    with {:ok, sink} <- write(sink, data), do: {:ok, sink, rest}
  end

  defp copy(socket, buffer, n, sink, timer) do
    with {:ok, sink} <- write(sink, buffer) do
      case recv(socket, timer) do
        {:ok, data} -> copy(socket, data, n - byte_size(buffer), sink, timer)
        {:error, :closed, _} -> {:error, :truncated, sink.size}
        error -> error
      end
    end
  end

  defp read_until_close(socket, buffer, sink, timer) do
    with {:ok, sink} <- write(sink, buffer) do
      case recv(socket, timer) do
        {:ok, data} -> read_until_close(socket, data, sink, timer)
        {:error, :closed, _} -> {:ok, sink}
        error -> error
      end
    end
  end

  # RFC 9112 §7.1: chunk-size [ext] CRLF data CRLF ... 0 CRLF trailers CRLF.
  # A chunk that would pass the size limit is refused before it's read.
  defp read_chunked(socket, buffer, sink, timer) do
    with {:ok, line, buffer} <- line(socket, buffer, timer),
         {:ok, n} <- chunk_size(line) do
      cond do
        n == 0 ->
          {:ok, sink}

        sink.size + n > sink.max ->
          {:error, :too_large, sink.max}

        true ->
          with {:ok, sink, buffer} <- copy(socket, buffer, n, sink, timer),
               {:ok, "", buffer} <- line(socket, buffer, timer) do
            read_chunked(socket, buffer, sink, timer)
          else
            {:ok, _, _} -> {:error, :bad_response, "malformed chunk"}
            error -> error
          end
      end
    end
  end

  defp chunk_size(line) do
    hex = line |> String.split(";", parts: 2) |> hd() |> String.trim()

    case Integer.parse(hex, 16) do
      {n, ""} when n >= 0 and byte_size(hex) <= 16 -> {:ok, n}
      _ -> {:error, :bad_response, "bad chunk size #{inspect(line)}"}
    end
  end

  defp line(socket, buffer, timer) do
    case :binary.split(buffer, "\r\n") do
      [line, rest] ->
        {:ok, line, rest}

      [_] when byte_size(buffer) > @max_head ->
        {:error, :bad_response, "chunk line too long"}

      [_] ->
        case recv(socket, timer) do
          {:ok, data} -> line(socket, buffer <> data, timer)
          {:error, :closed, _} -> {:error, :truncated, :chunked}
          error -> error
        end
    end
  end

  # Each read waits for what is left of the total time (fetch/2) or for the
  # idle timeout (fetch_to_file/3).
  defp recv(socket, timer) do
    case :ssl.recv(socket, 0, remaining(timer)) do
      {:ok, data} -> {:ok, data}
      {:error, :closed} -> {:error, :closed, :closed}
      {:error, :timeout} -> {:error, :timeout, elem(timer, 0)}
      {:error, reason} -> {:error, :socket_error, reason}
    end
  end

  defp remaining({:deadline, deadline}),
    do: max(deadline - System.monotonic_time(:millisecond), 0)

  defp remaining({:idle, ms}), do: ms
end
