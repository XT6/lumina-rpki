defmodule Lumina.RRDP.State do
  @moduledoc """
  What Lumina remembers about each RRDP repository between runs (#201),
  in `<root>/.state/rrdp/<SHA-256 of the notification URI, hex>.json`
  (`Lumina.RRDP.Store.id/1`):

    * `notify`: the notification URI, as text;
    * `session_id` and `serial`: the last snapshot or delta applied to the
      repository's store (RFC 8182 §3.4.1), `nil` before the first;
    * `deltas`: the delta hashes by serial from the last notification
      accepted, so a hash that changes for the same serial can be noticed
      (RFC 9697);
    * `last_modified`: the notification's `Last-Modified`, for the next
      `If-Modified-Since` (RFC 8182 §3.4.4);
    * `last_attempt`, `last_success` and `outcome` (`:ok` or
      `{:error, text}`).

  `load/2` gives `nil` for a repository never synced, and for a state file
  that can't be read, isn't valid or names another notification URI:
  the repository is then synced from its snapshot. `save/3` writes the
  file next to its final name and renames it into place.
  """

  alias Lumina.RRDP.Store
  alias Lumina.URI

  @type t :: %{
          notify: String.t(),
          session_id: String.t() | nil,
          serial: pos_integer() | nil,
          deltas: %{pos_integer() => <<_::256>>},
          last_modified: String.t() | nil,
          last_attempt: DateTime.t() | nil,
          last_success: DateTime.t() | nil,
          outcome: :ok | {:error, String.t()} | nil
        }

  @doc "The state file of the repository whose notification URI is `notify`."
  @spec file(Path.t(), URI.t()) :: Path.t()
  def file(root, %URI{} = notify),
    do: Path.join([root, ".state", "rrdp", Store.id(notify) <> ".json"])

  @doc "The saved state of `notify`'s repository, or `nil` (never synced)."
  @spec load(Path.t(), URI.t()) :: t() | nil
  def load(root, %URI{} = notify) do
    with {:ok, text} <- File.read(file(root, notify)),
         {:ok, %{} = json} <- JSON.decode(text),
         true <- json["notify"] == to_string(notify),
         {:ok, session_id} <- optional(json["session_id"], &is_binary/1),
         {:ok, serial} <- optional(json["serial"], &(is_integer(&1) and &1 > 0)),
         {:ok, deltas} <- deltas(json["deltas"]),
         {:ok, last_modified} <- optional(json["last_modified"], &is_binary/1),
         {:ok, last_attempt} <- time(json["last_attempt"]),
         {:ok, last_success} <- time(json["last_success"]),
         {:ok, outcome} <- outcome(json["outcome"]) do
      %{
        notify: json["notify"],
        session_id: session_id,
        serial: serial,
        deltas: deltas,
        last_modified: last_modified,
        last_attempt: last_attempt,
        last_success: last_success,
        outcome: outcome
      }
    else
      _ -> nil
    end
  end

  @doc """
  Saves `state` (the fields of `t()`; `notify` is taken from the
  argument, missing fields are `nil` or empty) for `notify`'s repository.
  """
  @spec save(Path.t(), URI.t(), map()) :: :ok | {:error, term()}
  def save(root, %URI{} = notify, state) do
    json =
      JSON.encode!(%{
        "notify" => to_string(notify),
        "session_id" => state[:session_id],
        "serial" => state[:serial],
        "deltas" =>
          Map.new(state[:deltas] || %{}, fn {serial, hash} ->
            {Integer.to_string(serial), Base.encode16(hash, case: :lower)}
          end),
        "last_modified" => state[:last_modified],
        "last_attempt" => state[:last_attempt] && DateTime.to_iso8601(state.last_attempt),
        "last_success" => state[:last_success] && DateTime.to_iso8601(state.last_success),
        "outcome" =>
          case state[:outcome] do
            :ok -> "ok"
            {:error, text} -> %{"error" => to_string(text)}
            nil -> nil
          end
      })

    path = file(root, notify)
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

  defp optional(nil, _valid?), do: {:ok, nil}
  defp optional(value, valid?), do: if(valid?.(value), do: {:ok, value}, else: :error)

  defp deltas(nil), do: {:ok, %{}}

  defp deltas(%{} = map) do
    Enum.reduce_while(map, {:ok, %{}}, fn {serial, hex}, {:ok, acc} ->
      with {n, ""} when n > 0 <- Integer.parse(serial),
           true <- is_binary(hex) and byte_size(hex) == 64,
           {:ok, hash} <- Base.decode16(hex, case: :mixed) do
        {:cont, {:ok, Map.put(acc, n, hash)}}
      else
        _ -> {:halt, :error}
      end
    end)
  end

  defp deltas(_), do: :error

  defp time(nil), do: {:ok, nil}

  defp time(text) when is_binary(text) do
    case DateTime.from_iso8601(text) do
      {:ok, at, _} -> {:ok, at}
      _ -> :error
    end
  end

  defp time(_), do: :error

  defp outcome(nil), do: {:ok, nil}
  defp outcome("ok"), do: {:ok, :ok}
  defp outcome(%{"error" => text}) when is_binary(text), do: {:ok, {:error, text}}
  defp outcome(_), do: :error
end
