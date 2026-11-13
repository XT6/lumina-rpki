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
  bounded by `:max_size`, every read by the overall `:timeout`, and the
  response head by 64 KiB.

  Redirects (301, 302, 303, 307, 308) are followed up to `:max_redirects`
  times, and only to `https://` URIs that `Lumina.URI.parse/1` accepts
  (D-008).

  Failures are `{:error, %{reason: reason, uri: uri, detail: term}}`, where
  `uri` is the URI that failed (after any redirects) and `reason` is one
  of:

    * `:tls_untrusted`, `:tls_expired` (expired or not yet valid),
      `:tls_hostname`, `:tls_error` (any other TLS failure)
    * `:connection_refused`, `:unknown_host`, `:socket_error`
    * `:connect_timeout`, `:timeout`
    * `:http_status` (`detail` is the status code), `:bad_response`,
      `:truncated` (the body ended before its Content-Length)
    * `:too_large` (`detail` is the limit)
    * `:redirect_not_https`, `:bad_redirect`, `:too_many_redirects`
  """

  require Logger

  alias Lumina.URI

  @defaults [connect_timeout: 30, timeout: 300, max_size: 20 * 1024 * 1024, max_redirects: 3]
  @max_head 65_536
  @redirects [301, 302, 303, 307, 308]

  @type error :: %{reason: atom(), uri: String.t(), detail: term()}

  @doc """
  Fetches `uri` and returns its body, and the URI it finally came from.

  Options: `:connect_timeout` and `:timeout` (seconds; defaults 30 and
  300, the second for the whole fetch, redirects included), `:max_size`
  (bytes; default 20 MiB), `:max_redirects` (default 3), and `:cacerts`
  (DER CA certificates to trust instead of the system store) and
  `:address` (an IP address tuple to connect to instead of resolving the
  host, which is still the name checked); the last two are for tests.

  `:warnings` lists `{:wildcard_certificate, uri, name}` for each server
  on the way whose certificate matched only through a wildcard.
  """
  @spec fetch(URI.t(), keyword()) ::
          {:ok, %{body: binary(), uri: URI.t(), warnings: [tuple()]}} | {:error, error()}
  def fetch(%URI{scheme: "https"} = uri, opts \\ []) do
    opts = Keyword.merge(@defaults, opts)
    deadline = System.monotonic_time(:millisecond) + opts[:timeout] * 1000
    follow(uri, opts, deadline, opts[:max_redirects], [])
  end

  defp follow(uri, opts, deadline, redirects_left, warnings) do
    case get(uri, opts, deadline) do
      {:ok, 200, _headers, body, new} ->
        {:ok, %{body: body, uri: uri, warnings: warnings ++ new}}

      {:ok, status, headers, _, new} when status in @redirects ->
        with {:ok, next} <- location(uri, headers) do
          if redirects_left > 0,
            do: follow(next, opts, deadline, redirects_left - 1, warnings ++ new),
            else: error(:too_many_redirects, uri, opts[:max_redirects])
        end

      {:ok, status, _headers, _, _} ->
        error(:http_status, uri, status)

      {:error, reason, detail} ->
        error(reason, uri, detail)
    end
  end

  # The redirect target, resolved against `uri` (RFC 9110 §10.2.2 allows a
  # relative reference). Only https:// targets are followed.
  defp location(uri, headers) do
    case List.keyfind(headers, "location", 0) do
      {_, target} ->
        merged = Elixir.URI.merge(to_string(uri), target)

        case {merged.scheme, URI.parse(Elixir.URI.to_string(merged))} do
          {"https", {:ok, next}} -> {:ok, next}
          {"https", {:error, _}} -> error(:bad_redirect, uri, target)
          _ -> error(:redirect_not_https, uri, target)
        end

      nil ->
        error(:bad_redirect, uri, "no Location header")
    end
  rescue
    _ -> error(:bad_redirect, uri, "unparseable Location header")
  end

  defp error(reason, uri, detail) do
    if reason in [:tls_untrusted, :tls_expired, :tls_hostname, :tls_error] do
      Logger.warning("TLS validation failed for #{uri}: #{reason} (#{inspect(detail)})")
    end

    {:error, %{reason: reason, uri: to_string(uri), detail: detail}}
  end

  # One request.

  defp get(uri, opts, deadline) do
    case connect(uri, opts, deadline) do
      {:ok, socket} ->
        try do
          warnings = wildcard_warnings(socket, uri)

          with {:ok, status, headers, body} <- request(socket, uri, opts, deadline),
               do: {:ok, status, headers, body, warnings}
        after
          _ = :ssl.close(socket)
        end

      error ->
        error
    end
  end

  defp connect(uri, opts, deadline) do
    name = connect_host(uri.host)
    host = Keyword.get(opts, :address, name)
    timeout = min(opts[:connect_timeout] * 1000, remaining(deadline))
    caller = self()
    ref = make_ref()

    # Called by :ssl for each certificate in the chain; it reports why the
    # chain was rejected, so the error can say so precisely.
    verify = fn
      _cert, {:bad_cert, reason}, _state ->
        send(caller, {ref, reason})
        {:fail, reason}

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

    # With :address, :ssl checks the name given as SNI. Never pass
    # `server_name_indication: :disable`: :ssl then skips the host name
    # check altogether (F-026).
    options =
      if opts[:address] && not ip_literal?(name),
        do: [{:server_name_indication, name} | options],
        else: options

    result = :ssl.connect(host, uri.port || 443, options, timeout)

    receive do
      {^ref, reason} ->
        _ = if match?({:ok, _}, result), do: :ssl.close(elem(result, 1))
        flush(ref)
        {:error, tls_reason(reason), reason}
    after
      0 -> connect_result(result)
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

  defp flush(ref) do
    receive do
      {^ref, _} -> flush(ref)
    after
      0 -> :ok
    end
  end

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

  defp request(socket, uri, opts, deadline) do
    path = "/" <> Enum.join(uri.path, "/")
    host = if uri.port, do: "#{uri.host}:#{uri.port}", else: uri.host

    head = [
      "GET #{path} HTTP/1.1\r\n",
      "Host: #{host}\r\n",
      "User-Agent: lumina\r\n",
      "Accept: */*\r\n",
      "Connection: close\r\n\r\n"
    ]

    with :ok <- send_request(socket, head),
         {:ok, status, headers, rest} <- read_head(socket, "", deadline) do
      if status == 200 do
        with {:ok, body} <- read_body(socket, headers, rest, opts[:max_size], deadline),
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

  defp read_head(socket, acc, deadline) do
    case :binary.split(acc, "\r\n\r\n") do
      [head, rest] ->
        parse_head(head, rest)

      [_] when byte_size(acc) > @max_head ->
        {:error, :bad_response, "response head too long"}

      [_] ->
        with {:ok, data} <- recv(socket, deadline), do: read_head(socket, acc <> data, deadline)
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

  # RFC 9112 §6.3: chunked if Transfer-Encoding says so, else
  # Content-Length, else everything until the server closes.
  defp read_body(socket, headers, rest, max, deadline) do
    encoding = headers |> List.keyfind("transfer-encoding", 0) |> header_value()
    length = headers |> List.keyfind("content-length", 0) |> header_value()

    cond do
      encoding != nil and String.ends_with?(String.downcase(encoding), "chunked") ->
        read_chunked(socket, rest, [], 0, max, deadline)

      encoding != nil ->
        {:error, :bad_response, "unsupported transfer-encoding #{encoding}"}

      length != nil ->
        case Integer.parse(length) do
          {n, ""} when n > max -> {:error, :too_large, max}
          {n, ""} when n >= 0 -> read_length(socket, rest, n, deadline)
          _ -> {:error, :bad_response, "bad content-length #{length}"}
        end

      true ->
        read_until_close(socket, rest, max, deadline)
    end
  end

  defp header_value({_, value}), do: value
  defp header_value(nil), do: nil

  defp read_length(_socket, acc, n, _deadline) when byte_size(acc) >= n,
    do: {:ok, binary_part(acc, 0, n)}

  defp read_length(socket, acc, n, deadline) do
    case recv(socket, deadline) do
      {:ok, data} -> read_length(socket, acc <> data, n, deadline)
      {:error, :closed, _} -> {:error, :truncated, byte_size(acc)}
      error -> error
    end
  end

  defp read_until_close(socket, acc, max, deadline) do
    if byte_size(acc) > max do
      {:error, :too_large, max}
    else
      case recv(socket, deadline) do
        {:ok, data} -> read_until_close(socket, acc <> data, max, deadline)
        {:error, :closed, _} -> {:ok, acc}
        error -> error
      end
    end
  end

  # RFC 9112 §7.1: chunk-size [ext] CRLF data CRLF ... 0 CRLF trailers CRLF.
  # A chunk that would pass the size limit is refused before it's read.
  defp read_chunked(socket, buffer, acc, size, max, deadline) do
    with {:ok, line, buffer} <- line(socket, buffer, deadline),
         {:ok, n} <- chunk_size(line) do
      cond do
        n == 0 ->
          {:ok, IO.iodata_to_binary(acc)}

        size + n > max ->
          {:error, :too_large, max}

        true ->
          with {:ok, data, buffer} <- take(socket, buffer, n + 2, deadline),
               <<chunk::binary-size(^n), "\r\n">> <- data do
            read_chunked(socket, buffer, [acc, chunk], size + n, max, deadline)
          else
            {:error, _, _} = error -> error
            _ -> {:error, :bad_response, "malformed chunk"}
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

  defp line(socket, buffer, deadline) do
    case :binary.split(buffer, "\r\n") do
      [line, rest] ->
        {:ok, line, rest}

      [_] when byte_size(buffer) > @max_head ->
        {:error, :bad_response, "chunk line too long"}

      [_] ->
        case recv(socket, deadline) do
          {:ok, data} -> line(socket, buffer <> data, deadline)
          {:error, :closed, _} -> {:error, :truncated, :chunked}
          error -> error
        end
    end
  end

  defp take(_socket, buffer, n, _deadline) when byte_size(buffer) >= n do
    <<data::binary-size(^n), rest::binary>> = buffer
    {:ok, data, rest}
  end

  defp take(socket, buffer, n, deadline) do
    case recv(socket, deadline) do
      {:ok, data} -> take(socket, buffer <> data, n, deadline)
      {:error, :closed, _} -> {:error, :truncated, :chunked}
      error -> error
    end
  end

  defp recv(socket, deadline) do
    case :ssl.recv(socket, 0, remaining(deadline)) do
      {:ok, data} -> {:ok, data}
      {:error, :closed} -> {:error, :closed, :closed}
      {:error, :timeout} -> {:error, :timeout, :timeout}
      {:error, reason} -> {:error, :socket_error, reason}
    end
  end

  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end
