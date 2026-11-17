defmodule Lumina.RRDP.Store do
  @moduledoc """
  Where an RRDP repository's objects live in the cache (#201).

  Each repository, identified by its notification URI, has its own store,
  `<root>/rrdp/<host[:port]>/<SHA-256 of the notification URI, hex>/`,
  laid out by the objects' rsync URIs (`Lumina.URI.cache_path/2` with the
  store as root, so `<store>/rsync/<host>/<path>`). RFC 8182 §3.4.2 lets a
  withdraw or a replace touch only objects that came from the same
  server; with a store per repository that holds by construction: one
  repository can't overwrite or withdraw another's objects, or the rsync
  tree's, whatever rsync URIs it publishes.

  A snapshot or a run of deltas is applied in a transaction (`update/4`,
  or `begin/3` with `put/3`, `withdraw/2`, `lookup/2`, then `commit/1` or
  `discard/1`), on a staged copy swapped in at the end with
  `Lumina.Cache.swap/3`, so a failure leaves the last good store and
  `Lumina.Cache.recover/1` repairs an interrupted swap:

    * `:snapshot` starts from an empty staging tree;
    * `:deltas` starts from a copy of the current store whose files are
      hard links. A replaced file is written under a temporary name and
      renamed over its link, and a withdrawn one unlinked, so the current
      store's files are never written through a link.

  Only regular files and directories are ever created; every path comes
  from `Lumina.URI.cache_path/2`, so it stays inside the store.
  """

  alias Lumina.{Cache, URI}

  @enforce_keys [:root, :store, :dir]
  defstruct [:root, :store, :dir]

  @type t :: %__MODULE__{root: Path.t(), store: Path.t(), dir: Path.t()}
  @type mode :: :snapshot | :deltas

  @doc "The store of the repository whose notification URI is `notify`."
  @spec path(Path.t(), URI.t()) :: Path.t()
  def path(root, %URI{scheme: "https"} = notify) do
    host = if notify.port, do: "#{notify.host}:#{notify.port}", else: notify.host
    Path.join([root, "rrdp", host, id(notify)])
  end

  @doc "The hex SHA-256 of the notification URI's text: the repository's id."
  @spec id(URI.t()) :: String.t()
  def id(%URI{} = notify),
    do: :sha256 |> :crypto.hash(to_string(notify)) |> Base.encode16(case: :lower)

  @doc """
  Where `uri`, an rsync object URI, lives in `store`: a store path, or a
  transaction (its staged copy).
  """
  @spec object_path(Path.t() | t(), URI.t()) :: Path.t()
  def object_path(%__MODULE__{dir: dir}, uri), do: object_path(dir, uri)
  def object_path(store, %URI{scheme: "rsync"} = uri), do: URI.cache_path(uri, store)

  @doc """
  The stored object for `uri` in `store` (a store path or a transaction):
  its path and SHA-256, or `nil` if there is none. For the delta checks of
  RFC 8182 §3.4.2.
  """
  @spec lookup(Path.t() | t(), URI.t()) :: %{path: Path.t(), sha256: <<_::256>>} | nil
  def lookup(store, uri) do
    path = object_path(store, uri)

    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular}} ->
        %{path: path, sha256: hash_file(path)}

      _ ->
        nil
    end
  end

  @doc """
  Starts a transaction on the store of `notify`: `:snapshot` from an empty
  tree, `:deltas` from a hard-linked copy of the current store.
  """
  @spec begin(Path.t(), URI.t(), mode()) :: {:ok, t()} | {:error, term()}
  def begin(root, %URI{} = notify, mode) when mode in [:snapshot, :deltas] do
    store = path(root, notify)

    with {:ok, dir} <- Cache.stage(root) do
      tx = %__MODULE__{root: root, store: store, dir: dir}

      result = if mode == :deltas and File.dir?(store), do: link_copy(store, dir), else: :ok

      if result == :ok do
        {:ok, tx}
      else
        discard(tx)
        result
      end
    end
  end

  @doc """
  Writes `bytes` as the object `uri` in the transaction, replacing any
  object there by renaming over it.
  """
  @spec put(t(), URI.t(), iodata()) :: :ok | {:error, term()}
  def put(%__MODULE__{} = tx, %URI{} = uri, bytes) do
    target = object_path(tx, uri)

    temp =
      Path.join(
        Path.dirname(target),
        ".#{Path.basename(target)}.#{System.unique_integer([:positive])}.part"
      )

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
  Removes the object `uri` from the transaction, and any directories left
  empty above it. `{:error, :enoent}` if there is no such object.
  """
  @spec withdraw(t(), URI.t()) :: :ok | {:error, term()}
  def withdraw(%__MODULE__{} = tx, %URI{} = uri) do
    target = object_path(tx, uri)

    case File.lstat(target) do
      {:ok, %File.Stat{type: :regular}} ->
        with :ok <- File.rm(target), do: prune(Path.dirname(target), tx.dir)

      _ ->
        {:error, :enoent}
    end
  end

  @doc "Swaps the transaction's tree in as the store."
  @spec commit(t()) :: :ok | {:error, term()}
  def commit(%__MODULE__{} = tx) do
    case Cache.swap(tx.root, tx.store, tx.dir) do
      {:ok, _} ->
        :ok

      error ->
        discard(tx)
        error
    end
  end

  @doc "Drops the transaction; the store stays as it was."
  @spec discard(t()) :: :ok
  def discard(%__MODULE__{dir: dir}), do: Cache.discard(dir)

  @doc """
  Runs `fun.(tx)` in a transaction on the store of `notify`, and commits
  it if `fun` returns `{:ok, value}`, giving `{:ok, value}`. Any other
  return, or a raise, exit or throw, discards it (re-raised), and the
  store stays as it was.
  """
  @spec update(Path.t(), URI.t(), mode(), (t() -> {:ok, term()} | term())) ::
          {:ok, term()} | term()
  def update(root, notify, mode, fun) do
    with {:ok, tx} <- begin(root, notify, mode) do
      result =
        try do
          fun.(tx)
        catch
          kind, reason ->
            discard(tx)
            :erlang.raise(kind, reason, __STACKTRACE__)
        end

      case result do
        {:ok, value} ->
          with :ok <- commit(tx), do: {:ok, value}

        other ->
          discard(tx)
          other
      end
    end
  end

  # Copies the directory tree `from` into `to`, files as hard links. lstat,
  # so anything that isn't a regular file or directory is left out.
  defp link_copy(from, to) do
    from
    |> File.ls!()
    |> Enum.reduce_while(:ok, fn name, :ok ->
      source = Path.join(from, name)
      target = Path.join(to, name)

      result =
        case File.lstat!(source).type do
          :regular -> File.ln(source, target)
          :directory -> with :ok <- File.mkdir(target), do: link_copy(source, target)
          _ -> :ok
        end

      if result == :ok, do: {:cont, :ok}, else: {:halt, result}
    end)
  end

  defp prune(dir, top) do
    if dir != top and File.rmdir(dir) == :ok, do: prune(Path.dirname(dir), top), else: :ok
  end

  defp hash_file(path) do
    path
    |> File.stream!(65_536)
    |> Enum.reduce(:crypto.hash_init(:sha256), &:crypto.hash_update(&2, &1))
    |> :crypto.hash_final()
  end
end
