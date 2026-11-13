defmodule Lumina.TA do
  @moduledoc """
  Retrieves and accepts the trust anchor certificate for a TAL (RFC 8630
  §3, #74).

  The TAL's URIs are tried in `Lumina.TAL.uris_by_preference/1` order
  (D-003): HTTPS through `Lumina.HTTPS`, rsync by fetching the single file
  through `Lumina.Rsync`. Each certificate fetched is decoded (DER checked,
  `Lumina.Object`) and checked against the TAL with `Lumina.TAL.check_ta/2`.
  The first one that passes is accepted. A fetch failure, a decode failure
  or a failed check, key mismatch included, moves on to the next URI.

  The accepted certificate is stored in the cache, keyed by the TAL's key
  (its expected Subject Key Identifier), not by URI, so the copy survives
  whichever URI it came from and whatever later fetches do to the
  repository trees:

      <root>/.ta/<ski hex>.cer     the accepted TA certificate
      <root>/.ta/<ski hex>.json    the URI it came from, and when

  If every URI fails, the result is an error, and the previously accepted
  certificate, if one is cached and still passes `check_ta/2` against
  this TAL, is returned in it as `:stale` for the caller to fall back on.
  Every attempt is listed, for the log and the CLI, and each URI's
  outcome is recorded with `Lumina.Cache.record/4`.

  Signature and validity dates are checked in M4.
  """

  alias Lumina.{Cache, Certificate, HTTPS, Object, Progress, Rsync, TAL, URI}

  @type attempt :: %{
          uri: String.t(),
          outcome: :accepted | :bad_uri | :fetch_failed | :decode_failed | :check_failed,
          detail: term(),
          warnings: [tuple()]
        }

  @type accepted :: %{
          certificate: Certificate.t(),
          uri: String.t(),
          path: Path.t(),
          fetched_at: DateTime.t()
        }

  @doc """
  Retrieves the TA certificate for `tal` into the cache at `root`.

  Returns `{:ok, accepted}` with the accepted certificate, the URI it came
  from, its cache path and the attempts, or `{:error, %{attempts: ...,
  stale: accepted | nil}}`. If the accepted certificate can't be
  written to the cache, the error also has `:store_error`.

  Options: `:now` (the time to record; default now), `:https` and
  `:rsync` (keyword options for `Lumina.HTTPS.fetch/2` and
  `Lumina.Rsync.fetch_file/3`).
  """
  @spec retrieve(TAL.t(), Path.t(), keyword()) ::
          {:ok,
           %{
             certificate: Certificate.t(),
             uri: String.t(),
             path: Path.t(),
             fetched_at: DateTime.t(),
             attempts: [attempt()]
           }}
          | {:error, %{attempts: [attempt()], stale: accepted() | nil}}
  def retrieve(%TAL{} = tal, root, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)

    result =
      Enum.reduce_while(TAL.uris_by_preference(tal), [], fn uri, attempts ->
        Progress.emit(opts, {:ta_trying, uri})

        case try_uri(tal, uri, root, opts, now) do
          {:accepted, attempt, cert} -> {:halt, {:ok, cert, Enum.reverse([attempt | attempts])}}
          {:failed, attempt} -> {:cont, [attempt | attempts]}
        end
      end)

    case result do
      {:ok, cert, attempts} ->
        case store(root, tal, cert, List.last(attempts).uri, now) do
          {:ok, accepted} ->
            {:ok, Map.put(accepted, :attempts, attempts)}

          {:error, reason} ->
            {:error, %{attempts: attempts, stale: cached(root, tal), store_error: reason}}
        end

      attempts ->
        {:error, %{attempts: Enum.reverse(attempts), stale: cached(root, tal)}}
    end
  end

  @doc """
  The previously accepted TA certificate for `tal` in the cache at `root`,
  if there is one and it still passes `Lumina.TAL.check_ta/2`; else `nil`.
  """
  @spec cached(Path.t(), TAL.t()) :: accepted() | nil
  def cached(root, %TAL{} = tal) do
    {cer, json} = paths(root, tal)

    with {:ok, bytes} <- File.read(cer),
         {:ok, %Object{value: %Certificate{} = cert}} <- Object.decode("ta.cer", bytes),
         :ok <- TAL.check_ta(tal, cert),
         {:ok, text} <- File.read(json),
         %{"uri" => uri, "fetched_at" => at} <- JSON.decode!(text),
         {:ok, fetched_at, 0} <- DateTime.from_iso8601(at) do
      %{certificate: cert, uri: uri, path: cer, fetched_at: fetched_at}
    else
      _ -> nil
    end
  end

  # One URI: fetch, decode, check.
  defp try_uri(tal, string, root, opts, now) do
    {outcome, detail, warnings, cert} =
      with {:ok, uri} <- parse(string),
           {:ok, bytes, warnings} <- fetch(uri, root, opts) do
        case decode_and_check(tal, uri, bytes) do
          {:ok, cert} -> {:accepted, nil, warnings, cert}
          {:error, outcome, detail} -> {outcome, detail, warnings, nil}
        end
      else
        {:error, outcome, detail} -> {outcome, detail, [], nil}
      end

    attempt = %{uri: string, outcome: outcome, detail: detail, warnings: warnings}

    # A URI that doesn't parse has no cache status to record.
    _ =
      with {:ok, uri} <- URI.parse(string) do
        Cache.record(root, uri, if(cert, do: :ok, else: {:error, {outcome, detail}}), now)
      end

    if cert, do: {:accepted, attempt, cert}, else: {:failed, attempt}
  end

  defp parse(string) do
    case URI.parse(string) do
      {:ok, uri} -> {:ok, uri}
      {:error, error} -> {:error, :bad_uri, error}
    end
  end

  defp fetch(%URI{scheme: "https"} = uri, _root, opts) do
    case HTTPS.fetch(uri, Keyword.get(opts, :https, [])) do
      {:ok, %{body: body, warnings: warnings}} -> {:ok, body, warnings}
      {:error, error} -> {:error, :fetch_failed, error}
    end
  end

  defp fetch(%URI{scheme: "rsync"} = uri, root, opts) do
    with {:ok, staging} <- stage(root) do
      try do
        file = Path.join(staging, "ta.cer")

        with {:ok, _} <- Rsync.fetch_file(uri, file, Keyword.get(opts, :rsync, [])),
             {:ok, bytes} <- read(file) do
          {:ok, bytes, []}
        else
          {:error, error} -> {:error, :fetch_failed, error}
        end
      after
        Cache.discard(staging)
      end
    end
  end

  defp stage(root) do
    case Cache.stage(root) do
      {:ok, staging} -> {:ok, staging}
      {:error, reason} -> {:error, :fetch_failed, reason}
    end
  end

  # A file over rsync's size limit is skipped, not an error (#72): then
  # there's nothing to read.
  defp read(file) do
    case File.read(file) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, :enoent} -> {:error, %{reason: :oversize_or_missing}}
      {:error, reason} -> {:error, %{reason: reason}}
    end
  end

  defp decode_and_check(tal, uri, bytes) do
    case Object.decode(List.last(uri.path) || "", bytes) do
      {:ok, %Object{value: %Certificate{} = cert}} ->
        case TAL.check_ta(tal, cert) do
          :ok -> {:ok, cert}
          {:error, problems} -> {:error, :check_failed, problems}
        end

      {:ok, %Object{type: type}} ->
        {:error, :decode_failed, {:not_a_certificate, type}}

      {:error, reason} ->
        {:error, :decode_failed, reason}
    end
  end

  # The accepted certificate, written atomically next to its note.
  defp store(root, tal, %Certificate{der: der} = cert, uri, now) do
    {cer, json} = paths(root, tal)
    note = JSON.encode!(%{"uri" => uri, "fetched_at" => DateTime.to_iso8601(now)})

    with :ok <- File.mkdir_p(Path.dirname(cer)),
         :ok <- write(cer, der),
         :ok <- write(json, note) do
      {:ok, %{certificate: cert, uri: uri, path: cer, fetched_at: now}}
    end
  end

  defp write(path, bytes) do
    temp = path <> ".tmp"

    with :ok <- File.write(temp, bytes), do: File.rename(temp, path)
  end

  defp paths(root, tal) do
    base = Path.join([root, ".ta", Base.encode16(TAL.subject_key_identifier(tal), case: :lower)])
    {base <> ".cer", base <> ".json"}
  end
end
