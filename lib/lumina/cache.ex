defmodule Lumina.Cache do
  @moduledoc """
  The local cache of repository content (#71), laid out like the
  repositories (RFC 6481 §5):

      <root>/rsync/<host[:port]>/<path>/...      rsync modules, fetched by rsync (D-012)
      <root>/https/<host[:port]>/<path>          single files, such as TA certificates

  Paths come from `Lumina.URI.cache_path/2`, so they never leave `root`.

  A fetch never writes into the live copy. It writes into a staging
  directory (`stage/1`), and `commit/3` swaps the staging directory in only
  when the fetch succeeded. A failed fetch is `discard/1`ed and the last
  good copy stays as it was (RFC 8897 §7: a failed fetch mustn't destroy
  the cache).

  The swap is two renames: the live copy moves aside, then the staging
  directory moves in. A crash between them leaves the live copy aside,
  with a note saying where it belongs, and `recover/1`, run at the start of
  every sync, puts it back. It also removes staging directories that a
  crash left behind.

  Only regular files and directories are kept. `commit/3` removes anything
  else (symlinks, devices, FIFOs, sockets) before the swap and reports it,
  so a repository can't plant a link that points out of the cache.

  Each fetched URI's last attempt and last success are recorded
  (`record/4`, `status/2`), for reporting and for D-007 (M5).

  The working directories live under `root` and start with a dot, which no
  scheme directory does, so they can't collide with repository content:
  `.staging/`, `.aside/` and `.status/`, `.ta/`, where `Lumina.TA`
  keeps accepted TA certificates, and `.valid/`, where `Lumina.LastValid`
  keeps the last valid copy of each publication point (D-023). `.state/`
  also holds `Lumina.ManifestState`'s per-CA manifest records (D-024).
  """

  alias Lumina.URI

  @type status :: %{
          uri: String.t(),
          last_attempt: DateTime.t(),
          outcome: :ok | {:error, String.t()},
          last_success: DateTime.t() | nil
        }

  @doc "Where `uri`'s content lives in the cache."
  @spec path(Path.t(), URI.t()) :: Path.t()
  def path(root, %URI{} = uri), do: URI.cache_path(uri, root)

  @doc """
  Creates an empty staging directory under `root` for one fetch, on the
  same file system as the cache so `commit/3` can rename it into place.
  """
  @spec stage(Path.t()) :: {:ok, Path.t()} | {:error, File.posix()}
  def stage(root) do
    dir = Path.join([root, ".staging", token()])

    with :ok <- File.mkdir_p(dir), do: {:ok, dir}
  end

  @doc "Throws a staging directory away, after a failed fetch."
  @spec discard(Path.t()) :: :ok
  def discard(staging) do
    _ = File.rm_rf!(staging)
    :ok
  end

  @doc """
  Replaces `uri`'s live copy with the staging directory.

  Anything that isn't a regular file or a directory is removed from the
  staging directory first; the removed paths, relative to it, are
  returned. The previous copy, if any, is deleted after the swap.
  """
  @spec commit(Path.t(), URI.t(), Path.t()) ::
          {:ok, %{removed: [Path.t()]}} | {:error, atom()}
  def commit(root, %URI{} = uri, staging) do
    target = path(root, uri)

    with :ok <- if(File.dir?(staging), do: :ok, else: {:error, :enoent}),
         removed = keep_regular(staging),
         :ok <- File.mkdir_p(Path.dirname(target)),
         {:ok, aside} <- move_aside(root, target) do
      case File.rename(staging, target) do
        :ok ->
          _ = if aside, do: finish_aside(aside)
          {:ok, %{removed: removed}}

        error ->
          # Put the live copy back; the cache is as it was.
          _ = if aside, do: restore_aside(aside, target)
          error
      end
    end
  end

  @doc """
  Writes a single file for `uri`, such as a TA certificate fetched over
  HTTPS. The file is written next to its final name and renamed into
  place, so a reader sees the old file or the new one, never a partial
  one.
  """
  @spec put_file(Path.t(), URI.t(), binary()) :: :ok | {:error, File.posix()}
  def put_file(root, %URI{} = uri, bytes) do
    target = path(root, uri)
    temp = Path.join(Path.dirname(target), ".#{Path.basename(target)}.#{token()}")

    with :ok <- File.mkdir_p(Path.dirname(target)),
         :ok <- File.write(temp, bytes),
         :ok <- File.rename(temp, target) do
      :ok
    else
      error ->
        _ = File.rm(temp)
        error
    end
  end

  @doc """
  Repairs the cache after a crash: puts back any live copy left aside by
  an interrupted `commit/3` (if nothing took its place), and removes
  leftover staging and aside directories. Returns what it restored.
  """
  @spec recover(Path.t()) :: {:ok, %{restored: [Path.t()]}}
  def recover(root) do
    aside_dir = Path.join(root, ".aside")

    restored =
      for note <- Path.wildcard(Path.join(aside_dir, "*.target")),
          dir = Path.rootname(note, ".target"),
          target = Path.join(root, File.read!(note)),
          reduce: [] do
        acc ->
          cond do
            # The swap finished (or the copy is gone): only cleanup is left.
            not File.dir?(dir) or File.exists?(target) ->
              finish_aside(dir)
              acc

            restore_aside(dir, target) == :ok ->
              acc ++ [target]

            # Couldn't put it back: leave it, and the note, for next time.
            true ->
              acc
          end
      end

    _ = File.rm_rf!(Path.join(root, ".staging"))
    {:ok, %{restored: restored}}
  end

  @doc """
  Records a fetch of `uri` at `at`: `:ok`, or `{:error, reason}`. A failed
  attempt keeps the time of the last success.
  """
  @spec record(Path.t(), URI.t(), :ok | {:error, term()}, DateTime.t()) :: :ok
  def record(root, %URI{} = uri, outcome, %DateTime{} = at) do
    previous = status(root, uri)

    entry = %{
      "uri" => to_string(uri),
      "last_attempt" => DateTime.to_iso8601(at),
      "outcome" =>
        case outcome do
          :ok -> "ok"
          {:error, reason} -> %{"error" => error_text(reason)}
        end,
      "last_success" =>
        case {outcome, previous} do
          {:ok, _} -> DateTime.to_iso8601(at)
          {_, %{last_success: %DateTime{} = t}} -> DateTime.to_iso8601(t)
          _ -> nil
        end
    }

    file = status_file(root, uri)
    File.mkdir_p!(Path.dirname(file))
    File.write!(file, JSON.encode!(entry))
  end

  @doc "The recorded status of `uri`, or `nil` if it was never fetched."
  @spec status(Path.t(), URI.t()) :: status() | nil
  def status(root, %URI{} = uri) do
    case File.read(status_file(root, uri)) do
      {:ok, text} ->
        entry = JSON.decode!(text)

        %{
          uri: entry["uri"],
          last_attempt: time!(entry["last_attempt"]),
          outcome:
            case entry["outcome"] do
              "ok" -> :ok
              %{"error" => reason} -> {:error, reason}
            end,
          last_success: entry["last_success"] && time!(entry["last_success"])
        }

      {:error, :enoent} ->
        nil
    end
  end

  # The swap.

  defp move_aside(root, target) do
    if File.exists?(target) do
      aside = Path.join([root, ".aside", token()])
      File.mkdir_p!(Path.dirname(aside))
      # The note is written first, so a crash after the rename can be undone.
      File.write!(aside <> ".target", Path.relative_to(target, root))

      case File.rename(target, aside) do
        :ok ->
          {:ok, aside}

        error ->
          _ = File.rm(aside <> ".target")
          error
      end
    else
      {:ok, nil}
    end
  end

  defp finish_aside(aside) do
    _ = File.rm_rf!(aside)
    _ = File.rm_rf!(aside <> ".target")
    :ok
  end

  defp restore_aside(aside, target) do
    with :ok <- File.mkdir_p(Path.dirname(target)),
         :ok <- File.rename(aside, target) do
      _ = File.rm_rf!(aside <> ".target")
      :ok
    end
  end

  # Removes everything under `dir` that isn't a regular file or directory.
  # lstat, so a symlink is seen as a link and never followed.
  defp keep_regular(dir) do
    dir
    |> File.ls!()
    |> Enum.sort()
    |> Enum.flat_map(fn name ->
      full = Path.join(dir, name)

      case File.lstat!(full).type do
        :regular ->
          []

        :directory ->
          dir |> Path.join(name) |> keep_regular() |> Enum.map(&Path.join(name, &1))

        _other ->
          _ = File.rm!(full)
          [name]
      end
    end)
  end

  defp status_file(root, uri), do: URI.cache_path(uri, Path.join(root, ".status")) <> ".json"

  defp error_text(reason) when is_binary(reason), do: reason
  defp error_text(reason), do: inspect(reason)

  defp time!(text) do
    {:ok, time, 0} = DateTime.from_iso8601(text)
    time
  end

  defp token do
    "#{System.os_time(:microsecond)}-#{System.unique_integer([:positive])}-#{:rand.uniform(1_000_000)}"
  end
end
