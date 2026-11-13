defmodule Lumina.URI do
  @moduledoc """
  Repository URIs: `rsync` (RFC 5781 §2) and `https` (RFC 3986), parsed,
  normalized and mapped to paths in the local cache (#70).

  Normalization (RFC 3986 §6.2.2.1, §6.2.3):

    * the scheme and host are lowercased;
    * an empty port, or the scheme's default (873 for rsync, RFC 5781 §2;
      443 for https), is dropped;
    * a trailing `/` is dropped, so a directory URI means the same with or
      without it (F-016, #43).

  Two URIs that normalize to the same struct name the same thing and map
  to the same cache path.

  Repository URIs come from certificates, which anyone can publish, and
  they become paths on the relying party's disk. So the parser is strict,
  in the spirit of D-002: anything that could escape the cache, or give
  one file two names, is an error naming its rule. In particular:

    * `.` and `..` segments are rejected, not resolved. RFC 3986 §6.2.2.3
      would remove them, but they only belong in relative references
      (§5.2), and a repository URI that contains one is malformed;
    * percent-encoding is rejected. Decoding it would give the same file
      two spellings, and the rsync URI scheme defines no encoding of its
      own (RFC 5781 §2, "Encoding considerations");
    * user information is rejected. RPKI repositories are public, and
      credentials in a URI are sensitive information (RFC 3986 §7.5);
    * queries and fragments are rejected. A repository object is a file.

  An rsync URI's first path segment is its module, the unit of fetching
  (D-006). RFC 5781 doesn't name this structure (F-024).
  """

  @enforce_keys [:scheme, :host]
  defstruct scheme: nil, host: nil, port: nil, path: []

  @type t :: %__MODULE__{
          scheme: String.t(),
          host: String.t(),
          port: pos_integer() | nil,
          path: [String.t()]
        }

  @type error :: %{rule: atom(), rfc: String.t(), message: String.t()}

  @default_ports %{"rsync" => 873, "https" => 443}

  # pchar (RFC 3986 §3.3) without pct-encoded: unreserved, sub-delims, ":", "@".
  @segment ~r/\A[A-Za-z0-9\-._~!$&'()*+,;=:@]+\z/
  # reg-name (RFC 3986 §3.2.2), limited to DNS-style labels: letters, digits,
  # "-" and "_", separated by single dots.
  @reg_name ~r/\A[a-z0-9_-]+(\.[a-z0-9_-]+)*\z/
  @ipv6 ~r/\A\[[0-9a-f:.]+\]\z/

  @doc """
  Parses and normalizes a repository URI.

  ## Examples

      iex> {:ok, uri} = Lumina.URI.parse("RSYNC://Repository.LACNIC.net:873/rpki/lacnic/")
      iex> to_string(uri)
      "rsync://repository.lacnic.net/rpki/lacnic"

      iex> {:error, %{rule: :dot_segment}} = Lumina.URI.parse("rsync://h.example/rpki/../etc")

  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, error()}
  def parse(string) when is_binary(string) do
    with {:ok, scheme, rest} <- scheme(string),
         {:ok, authority, path} <- split_authority(rest),
         :ok <- no_query_or_fragment(path),
         {:ok, host, port} <- host_port(authority, scheme),
         {:ok, segments} <- segments(path) do
      {:ok, %__MODULE__{scheme: scheme, host: host, port: port, path: segments}}
    end
  end

  @doc """
  The rsync module a URI belongs to: `rsync://host[:port]/module`, its
  first path segment (D-006).

  ## Examples

      iex> {:ok, uri} = Lumina.URI.parse("rsync://localhost:8873/rpki/ca1/roa1.roa")
      iex> {:ok, module} = Lumina.URI.module(uri)
      iex> to_string(module)
      "rsync://localhost:8873/rpki"

  """
  @spec module(t()) :: {:ok, t()} | {:error, error()}
  def module(%__MODULE__{scheme: "rsync", path: [module | _]} = uri),
    do: {:ok, %{uri | path: [module]}}

  def module(%__MODULE__{scheme: "rsync"}),
    do: error(:no_module, "5781#2", "the URI names no module (its path is empty)")

  def module(%__MODULE__{scheme: scheme}),
    do: error(:no_module, "5781#2", "only rsync URIs have modules, not #{scheme}")

  @doc """
  The path a URI maps to under the cache directory `root`:
  `<root>/<scheme>/<host[:port]>/<path segments>`. The result is always
  inside `root`, because `parse/1` rejects every segment that could
  leave it.

  ## Examples

      iex> {:ok, uri} = Lumina.URI.parse("rsync://localhost:8873/rpki/ca1/")
      iex> Lumina.URI.cache_path(uri, "/var/cache/lumina")
      "/var/cache/lumina/rsync/localhost:8873/rpki/ca1"

  """
  @spec cache_path(t(), Path.t()) :: Path.t()
  def cache_path(%__MODULE__{} = uri, root),
    do: Path.join([root, uri.scheme, authority(uri) | uri.path])

  @doc "The normalized text of a URI."
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{} = uri),
    do: Enum.join(["#{uri.scheme}://#{authority(uri)}" | uri.path], "/")

  defp authority(%__MODULE__{host: host, port: nil}), do: host
  defp authority(%__MODULE__{host: host, port: port}), do: "#{host}:#{port}"

  # Parsing, one component at a time (RFC 3986 §3).

  defp scheme(string) do
    case String.split(string, "://", parts: 2) do
      [scheme, rest] ->
        case String.downcase(scheme) do
          lower when is_map_key(@default_ports, lower) ->
            {:ok, lower, rest}

          _ ->
            error(:unsupported_scheme, "8630#2.2", "#{inspect(scheme)} isn't rsync or https")
        end

      [_] ->
        error(:missing_authority, "3986#3.2", "expected scheme://host/path")
    end
  end

  defp split_authority(rest) do
    case String.split(rest, "/", parts: 2) do
      [authority, path] -> {:ok, authority, path}
      [authority] -> {:ok, authority, ""}
    end
  end

  defp no_query_or_fragment(path) do
    cond do
      String.contains?(path, "?") ->
        error(:query, "3986#3.4", "a repository URI names a file; it has no query")

      String.contains?(path, "#") ->
        error(:fragment, "3986#3.5", "a repository URI names a file; it has no fragment")

      true ->
        :ok
    end
  end

  defp host_port(authority, scheme) do
    cond do
      String.contains?(authority, "@") ->
        error(:userinfo, "3986#7.5", "user information isn't allowed in a repository URI")

      String.contains?(authority, ["?", "#"]) ->
        error(:invalid_host, "3986#3.2.2", "the host is followed by a query or fragment")

      true ->
        {host, port} = split_port(authority)

        with {:ok, host} <- host(String.downcase(host)),
             {:ok, port} <- port(port, scheme),
             do: {:ok, host, port}
    end
  end

  # "[v6]:port", "[v6]", "host:port" or "host".
  defp split_port("[" <> _ = authority) do
    case String.split(authority, "]", parts: 2) do
      [v6, ":" <> port] -> {v6 <> "]", port}
      [v6, ""] -> {v6 <> "]", nil}
      _ -> {authority, nil}
    end
  end

  defp split_port(authority) do
    case String.split(authority, ":", parts: 2) do
      [host, port] -> {host, port}
      [host] -> {host, nil}
    end
  end

  defp host(""), do: error(:invalid_host, "3986#3.2.2", "the host is empty")

  defp host(host) do
    if Regex.match?(@reg_name, host) or Regex.match?(@ipv6, host),
      do: {:ok, host},
      else: error(:invalid_host, "3986#3.2.2", "#{inspect(host)} isn't a valid host name")
  end

  defp port(nil, _scheme), do: {:ok, nil}
  defp port("", _scheme), do: {:ok, nil}

  defp port(digits, scheme) do
    case Regex.match?(~r/\A[0-9]{1,5}\z/, digits) and String.to_integer(digits) do
      port when port in 1..65_535 ->
        {:ok, if(port == @default_ports[scheme], do: nil, else: port)}

      _ ->
        error(:invalid_port, "3986#3.2.3", "#{inspect(digits)} isn't a port number")
    end
  end

  defp segments(path) do
    # A trailing "/" is dropped (F-016); any other empty segment is an error.
    path
    |> String.split("/")
    |> drop_trailing_empty()
    |> Enum.reduce_while({:ok, []}, fn segment, {:ok, acc} ->
      case segment(segment) do
        :ok -> {:cont, {:ok, [segment | acc]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      error -> error
    end
  end

  defp drop_trailing_empty([""]), do: []

  defp drop_trailing_empty(segments) do
    case List.last(segments) do
      "" -> Enum.drop(segments, -1)
      _ -> segments
    end
  end

  defp segment(""), do: error(:empty_segment, "3986#3.3", "the path has an empty segment (//)")

  defp segment(dot) when dot in [".", ".."],
    do: error(:dot_segment, "3986#3.3", "the path has a #{inspect(dot)} segment")

  defp segment(segment) do
    cond do
      String.contains?(segment, "%") ->
        error(:percent_encoding, "3986#2.1", "percent-encoding isn't allowed in a repository URI")

      Regex.match?(@segment, segment) ->
        :ok

      true ->
        error(
          :invalid_character,
          "3986#3.3",
          "#{inspect(segment)} has a character not allowed in a path"
        )
    end
  end

  defp error(rule, rfc, message), do: {:error, %{rule: rule, rfc: rfc, message: message}}

  defimpl String.Chars do
    def to_string(uri), do: Lumina.URI.to_string(uri)
  end
end
