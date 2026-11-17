defmodule Lumina.Source do
  @moduledoc """
  Where each CA's publication point was last read from while accepted
  (#206): its RRDP repository's store or the rsync tree. A sync may read a
  point over RRDP one run and from rsync the next (D-040), and offline
  validation (#207) must read the copy the walk accepted.

  One file per point, keyed like the walk's (`Lumina.Walk.point_key/2`,
  the manifest URI): `<root>/.state/sources/<SHA-256 of the key, hex>.json`
  with the key, the transport (`"rrdp"` or `"rsync"`), the notification
  URI or rsync module, and the time. `load/2` gives `nil` for a point
  never recorded, or a file that can't be read or names another point.
  """

  alias Lumina.URI

  @type source :: {:rrdp, URI.t()} | {:rsync, URI.t()}

  @doc "The file recording the source of the point `key`."
  @spec file(Path.t(), String.t()) :: Path.t()
  def file(root, key) do
    id = :sha256 |> :crypto.hash(key) |> Base.encode16(case: :lower)
    Path.join([root, ".state", "sources", id <> ".json"])
  end

  @doc "Records that the point `key` was read from `source` at `at`."
  @spec save(Path.t(), String.t(), source(), DateTime.t()) :: :ok | {:error, term()}
  def save(root, key, {transport, %URI{} = uri}, %DateTime{} = at)
      when transport in [:rrdp, :rsync] do
    json =
      JSON.encode!(%{
        "point" => key,
        "transport" => Atom.to_string(transport),
        "uri" => to_string(uri),
        "at" => DateTime.to_iso8601(at)
      })

    path = file(root, key)
    temp = "#{path}.#{System.unique_integer([:positive])}.tmp"

    with :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- File.write(temp, json),
         :ok <- File.rename(temp, path) do
      :ok
    else
      error ->
        _ = File.rm(temp)
        error
    end
  end

  @doc "The source the point `key` was last read from, or `nil`."
  @spec load(Path.t(), String.t()) :: %{source: source(), at: DateTime.t()} | nil
  def load(root, key) do
    with {:ok, text} <- File.read(file(root, key)),
         {:ok, %{"point" => ^key, "transport" => transport, "uri" => uri, "at" => at}} <-
           JSON.decode(text),
         {:ok, transport} <- transport(transport),
         {:ok, uri} <- URI.parse(uri),
         {:ok, at, _} <- DateTime.from_iso8601(at) do
      %{source: {transport, uri}, at: at}
    else
      _ -> nil
    end
  end

  defp transport("rrdp"), do: {:ok, :rrdp}
  defp transport("rsync"), do: {:ok, :rsync}
  defp transport(_), do: :error
end
