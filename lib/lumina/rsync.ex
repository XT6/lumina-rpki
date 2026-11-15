defmodule Lumina.Rsync do
  @moduledoc """
  Runs the `rsync` binary to fetch a publication point or a single file
  from an rsync server (RFC 5781, RFC 6481 §3), with the limits of D-008
  (#72).

  A directory (the walk fetches whole modules, D-012) is fetched
  recursively, every subdirectory included, into a directory the caller
  chose, normally a
  `Lumina.Cache.stage/1` directory. The flags are fixed:

    * `-rt --delete`: recursive, with modification times, and nothing in the
      destination that the server no longer has;
    * no `-l`, `--no-specials`, `--no-devices`: symlinks and special files on
      the server are skipped, never created (`Lumina.Cache.commit/3`
      removes any that appear anyway);
    * `--max-size`, `--contimeout`, `--timeout`: D-008's object size,
      connect and I/O limits;
    * `--no-motd`, and `--info=skip1` so that skipped oversize files are
      reported.

  Arguments go to the executable as a list, never through a shell, and the
  source is always a full `rsync://` URI from `Lumina.URI`. That isn't
  enough on its own: the client passes the path after the module to the
  server, and an rsync daemon reads a path starting with `-` as one of its
  own options, with or without `--secluded-args`. Repository file names
  may legitimately start with `-` (base64url), so they can't simply be
  rejected. Instead the source is always written
  `rsync://host/module/./path`: the `./` is a no-op for rsync without
  `--relative`, and nothing after it can start with `-` (F-025).

  A file over the size limit doesn't fail the fetch: rsync skips it and
  the rest is fetched. Its name is reported in `:oversize`, and the
  manifest check (M5) will find it missing. Failing the whole fetch
  instead would let one oversize file freeze a publication point at its
  last good copy for ever.

  Failures are `{:error, %{reason: reason, exit_status: n, output: text}}`,
  with `reason` one of:

    * `:connection_refused`, `:unknown_host`, `:socket_error`
    * `:connect_timeout`, `:timeout`
    * `:no_such_module`, `:not_found`, `:no_module` (the URI has no path)
    * `:partial` (some files not transferred, or files vanished meanwhile)
    * `:usage_error` (rsync rejected its arguments: exit 1, typically an
      rsync older than 3.1.0, such as macOS's openrsync)
    * `:protocol_error`, `:rsync_error`

  `output` keeps rsync's own messages, for reports.
  """

  alias Lumina.URI

  @minimum_version {3, 1, 0}
  @max_output 65_536

  @defaults [contimeout: 10, timeout: 300, max_size: 20 * 1024 * 1024]

  @type error :: %{reason: atom(), exit_status: non_neg_integer() | nil, output: String.t()}
  @type result :: %{oversize: [String.t()], output: String.t()}

  @doc """
  Fetches the directory `uri` names, recursively, into `dest`.

  Options: `:rsync` (path to the binary; default: found on `PATH`),
  `:contimeout` and `:timeout` (seconds; defaults 10 and 300),
  `:max_size` (bytes; default 20 MiB), and `:link_dest`, a previous copy
  whose unchanged files are hard-linked instead of downloaded again.
  """
  @spec fetch_dir(URI.t(), Path.t(), keyword()) :: {:ok, result()} | {:error, error()}
  def fetch_dir(%URI{scheme: "rsync"} = uri, dest, opts \\ []) do
    opts = Keyword.merge(@defaults, opts)

    link_dest =
      case opts[:link_dest] do
        nil -> []
        dir -> ["--link-dest=#{Path.expand(dir)}"]
      end

    with {:ok, source} <- source(uri) do
      run(["-rt", "--delete"] ++ common(opts) ++ link_dest ++ [source <> "/", dest <> "/"], opts)
    end
  end

  @doc """
  Fetches the single file `uri` names, such as a TA certificate, to the
  path `dest`. Options as for `fetch_dir/3`, without `:link_dest`.
  """
  @spec fetch_file(URI.t(), Path.t(), keyword()) :: {:ok, result()} | {:error, error()}
  def fetch_file(%URI{scheme: "rsync"} = uri, dest, opts \\ []) do
    opts = Keyword.merge(@defaults, opts)

    with {:ok, source} <- source(uri) do
      run(["-t"] ++ common(opts) ++ [source, dest], opts)
    end
  end

  @doc """
  The source argument for `uri`: `rsync://host[:port]/module/./path`. The
  `./` keeps the rsync daemon from reading a path that starts with `-` as
  an option (F-025).

  ## Examples

      iex> {:ok, uri} = Lumina.URI.parse("rsync://h.example/rpki/-x/ca.cer")
      iex> Lumina.Rsync.source(uri)
      {:ok, "rsync://h.example/rpki/./-x/ca.cer"}

  """
  @spec source(URI.t()) :: {:ok, String.t()} | {:error, error()}
  def source(%URI{scheme: "rsync", path: [module | rest]} = uri) do
    {:ok, base} = URI.module(%{uri | path: [module]})
    {:ok, Enum.join([to_string(base), "." | rest], "/")}
  end

  def source(%URI{}),
    do: {:error, %{reason: :no_module, exit_status: nil, output: "the URI names no rsync module"}}

  @doc """
  Finds the rsync binary and checks its version (3.1.0 or later, for
  `--info`). Returns its path and version.
  """
  @spec check(keyword()) ::
          {:ok,
           %{path: Path.t(), version: {non_neg_integer(), non_neg_integer(), non_neg_integer()}}}
          | {:error, :rsync_not_found | {:rsync_too_old, String.t()} | :rsync_version_unknown}
  def check(opts \\ []) do
    with {:ok, path} <- executable(opts),
         {text, 0} <- System.cmd(path, ["--version"], stderr_to_stdout: true),
         [_, version] <- Regex.run(~r/version (\d+\.\d+\.\d+)/, text) do
      parsed = version |> String.split(".") |> Enum.map(&String.to_integer/1) |> List.to_tuple()

      if parsed >= @minimum_version,
        do: {:ok, %{path: path, version: parsed}},
        else: {:error, {:rsync_too_old, version}}
    else
      {:error, _} = error -> error
      _ -> {:error, :rsync_version_unknown}
    end
  end

  defp common(opts) do
    [
      "--no-motd",
      "--no-specials",
      "--no-devices",
      "--info=skip1",
      "--max-size=#{opts[:max_size]}",
      "--contimeout=#{opts[:contimeout]}",
      "--timeout=#{opts[:timeout]}"
    ]
  end

  defp executable(opts) do
    path = opts[:rsync] || System.find_executable("rsync")

    case is_binary(path) && File.stat(path) do
      {:ok, %File.Stat{type: :regular, mode: mode}} when Bitwise.band(mode, 0o111) != 0 ->
        {:ok, path}

      _ ->
        {:error, :rsync_not_found}
    end
  end

  defp run(args, opts) do
    with {:ok, path} <- executable(opts) do
      port =
        Port.open({:spawn_executable, path}, [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          :hide,
          args: args
        ])

      {status, output} = collect(port, [], 0)
      result(status, output)
    else
      {:error, :rsync_not_found} ->
        {:error, %{reason: :rsync_not_found, exit_status: nil, output: ""}}
    end
  end

  # rsync's own timeouts bound the run. Output is kept up to @max_output
  # bytes; a server can't make Lumina hold more.
  defp collect(port, acc, size) do
    receive do
      {^port, {:data, data}} when size < @max_output ->
        collect(port, [acc, data], size + byte_size(data))

      {^port, {:data, _data}} ->
        collect(port, acc, size)

      {^port, {:exit_status, status}} ->
        {status, acc |> IO.iodata_to_binary() |> binary_slice(0, @max_output)}
    end
  end

  defp result(0, output), do: {:ok, %{oversize: oversize(output), output: output}}

  defp result(status, output),
    do: {:error, %{reason: reason(status, output), exit_status: status, output: output}}

  defp oversize(output) do
    for [_, name] <- Regex.scan(~r/^(.+) is over max-size$/m, output), do: name
  end

  # rsync's exit values (rsync(1), "EXIT VALUES"), refined by its messages.
  defp reason(1, _output), do: :usage_error

  defp reason(5, output) do
    if output =~ "Unknown module", do: :no_such_module, else: :protocol_error
  end

  defp reason(10, output) do
    cond do
      output =~ "Connection refused" -> :connection_refused
      output =~ ~r/getaddrinfo|not known|Name or service/ -> :unknown_host
      true -> :socket_error
    end
  end

  defp reason(23, output) do
    if output =~ "No such file or directory", do: :not_found, else: :partial
  end

  defp reason(24, _output), do: :partial
  defp reason(30, _output), do: :timeout
  defp reason(35, _output), do: :connect_timeout
  defp reason(status, _output) when status in [2, 12], do: :protocol_error
  defp reason(_status, _output), do: :rsync_error
end
