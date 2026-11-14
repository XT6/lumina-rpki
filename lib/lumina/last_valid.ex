defmodule Lumina.LastValid do
  @moduledoc """
  The last valid copy of each publication point (D-023, #135).

  When a publication point is accepted (RFC 9286 §6), `save/3` keeps its
  manifest and every file it lists in the cache, apart from the rsync
  mirror, under `<root>/.valid/`, at the cache path of the manifest's URI:

      <root>/.valid/rsync/<host[:port]>/<path>/ca1.mft/ca1.mft
      <root>/.valid/rsync/<host[:port]>/<path>/ca1.mft/roa1.roa ...

  One copy per manifest, so CA instances sharing a directory during a key
  rollover (§6.1) keep separate copies. When the point later fails, the
  copy can stand in for it (RFC 9286 §6.6: "the RP SHOULD continue to use
  cached versions of the objects associated with this CA instance, until
  such time as they become stale"); `Lumina.Validate.point/5` processes it
  as it would the live copy, so a copy whose manifest has gone stale isn't
  used.

  The files are copied, not linked, so nothing that later happens to the
  mirror can change them. A copy is replaced only when the manifest has
  changed: same manifest bytes, same listed hashes, same files. The new
  copy is written next to the old one and renamed into place, so a
  reader sees one or the other. Only `lumina sync` saves (D-024's rule
  for state: an offline `lumina validate` at another time doesn't move
  it).
  """

  alias Lumina.URI

  @doc """
  The directory holding the last valid copy of the publication point whose
  manifest is `manifest_uri`, or `nil` for a URI that doesn't parse.
  """
  @spec dir(Path.t(), String.t()) :: Path.t() | nil
  def dir(root, manifest_uri) do
    case URI.parse(manifest_uri) do
      {:ok, uri} -> URI.cache_path(uri, Path.join(root, ".valid"))
      {:error, _} -> nil
    end
  end

  @doc """
  The last valid copy of `manifest_uri`'s publication point, if there is
  one: a directory holding its manifest and listed files.
  """
  @spec load(Path.t(), String.t()) :: Path.t() | nil
  def load(root, manifest_uri) do
    with dir when is_binary(dir) <- dir(root, manifest_uri),
         true <- File.dir?(dir) do
      dir
    else
      _ -> nil
    end
  end

  @doc """
  Saves an accepted publication point (`Lumina.PublicationPoint.process/4`)
  as its last valid copy: the manifest, read from `path`, and the files it
  lists. Does nothing when the saved manifest is the same.
  """
  @spec save(Path.t(), map(), Path.t()) :: :ok | :unchanged | {:error, term()}
  def save(root, %{status: :accepted, manifest: uri, files: files}, path) do
    name = uri |> String.split("/") |> List.last()
    manifest = Path.join(path, name)

    with target when is_binary(target) <- dir(root, uri),
         {:ok, bytes} <- File.read(manifest) do
      if File.read(Path.join(target, name)) == {:ok, bytes},
        do: :unchanged,
        else: replace(target, [{name, manifest} | Enum.to_list(files)])
    else
      nil -> {:error, :bad_uri}
      error -> error
    end
  end

  defp replace(target, files) do
    token = Base.url_encode64(:crypto.strong_rand_bytes(6), padding: false)
    temp = Path.join(Path.dirname(target), ".#{Path.basename(target)}.#{token}")
    old = temp <> ".old"

    with :ok <- File.mkdir_p(temp),
         :ok <- copy_all(files, temp),
         :ok <- if(File.exists?(target), do: File.rename(target, old), else: :ok),
         :ok <- File.rename(temp, target) do
      _ = File.rm_rf(old)
      :ok
    else
      error ->
        _ = File.rm_rf(temp)
        _ = if File.exists?(old) and not File.exists?(target), do: File.rename(old, target)
        error
    end
  end

  defp copy_all(files, dir) do
    Enum.reduce_while(files, :ok, fn {name, from}, :ok ->
      case File.cp(from, Path.join(dir, name)) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end
end
