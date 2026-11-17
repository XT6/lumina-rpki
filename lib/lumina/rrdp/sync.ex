defmodule Lumina.RRDP.Sync do
  @moduledoc """
  Syncs one RRDP repository, from its deltas or its snapshot (#203, #204;
  RFC 8182 §3.4.1 to §3.4.3; RFC 9674 §3.2).

  `run/3` takes the repository's notification URI (the `rpkiNotify` URI
  in a CA certificate) and the cache root:

    1. The notification file is fetched (`Lumina.HTTPS.fetch_to_file/3`,
       at most 20 MiB, D-043; redirects only to its own origin, RFC 9674
       §3.2; `If-Modified-Since` with the `Last-Modified` of the last
       successful sync, §3.4.4) and decoded (`Lumina.RRDP.Notification`).
    2. If its session_id and serial are those of the store, nothing more
       is downloaded: `:unchanged`. With the same session_id, a serial
       below the store's rejects it (`:serial_not_greater`, §3.4.3). A new
       session_id is processed from its snapshot, whatever its serial
       (§3.4.1).
    3. With the same session_id and every delta from the store's serial
       plus one listed, the deltas are used (§3.4.2): each is fetched, its
       SHA-256 checked, its root checked against the session_id and its
       serial, and its elements applied in order to one hard-linked copy
       of the store, swapped in once all of them are in. A withdraw, or a
       publish with a hash, must name an object the store holds with that
       SHA-256; a publish without a hash must be for a URI it doesn't
       hold (erratum 6919, F-037). A rejected delta drops the copy and the
       snapshot is processed instead (§3.4.2): the result's `fallback`
       says why.
    4. Otherwise the snapshot is fetched to a temporary file (at most 2 GiB, D-043;
       redirects only to the notification's origin), its SHA-256 compared
       with the notification's (§3.4.3), then streamed
       (`Lumina.RRDP.Snapshot`, root checked against the notification's
       session_id and serial, §3.5.2.3) into a new tree for the
       repository's `Lumina.RRDP.Store`, swapped in only when the whole
       snapshot is in.
    5. The state (`Lumina.RRDP.State`) records the session_id, serial,
       delta hashes and `Last-Modified`, or, on failure, only the attempt
       and its outcome.

  Every failure leaves the last good store and returns
  `{:failed, reason}`, with `reason`:

    * `:notification_failed`: the notification couldn't be fetched;
    * `:notification_rejected`: it didn't decode or check (§3.4.1);
    * `:cross_origin`: a cross-origin URI in the notification, or a
      redirect to another origin while fetching the notification or the
      snapshot (RFC 9674 §3.2: RRDP can't be used);
    * `:serial_not_greater`: same session_id, lower serial (§3.4.3);
    * `:snapshot_failed`: the snapshot couldn't be fetched;
    * `:snapshot_hash_mismatch`: its SHA-256 isn't the notification's;
    * `:snapshot_rejected`: it didn't decode or check (§3.5.2.3), or it
      publishes one URI twice (`duplicate_publish`, F-041);
    * `:store_failed`: the cache couldn't be written.

  A cross-origin redirect while fetching a delta fails the sync too,
  without the snapshot (RFC 9674 §3.2). The other delta failures lead to
  the snapshot, and show in `fallback`: `:delta_failed` (not fetched),
  `:delta_hash_mismatch`, `:delta_rejected` (didn't decode or check, or
  an element failed the rules above: `publish_without_hash`,
  `replace_not_held`, `replace_hash_mismatch`, `withdraw_not_held`,
  `withdraw_hash_mismatch`) or `:store_failed`.

  What happens to a repository whose sync failed is the walk's (D-040,
  #206).

  Progress (D-036) goes to the `:progress` function: `{:rrdp_started,
  notify}`, `{:rrdp_download, notify, kind, bytes}` (`kind`
  `:notification`, `:snapshot` or `:delta`) every MiB received,
  `{:rrdp_downloaded, notify, kind, bytes}` once a file is in,
  `{:rrdp_objects, notify, count}` every 1000 snapshot objects written
  and at the end of a snapshot or a run of deltas (elements applied),
  `{:rrdp_fallback, notify, reason}` when a delta is rejected, and
  `{:rrdp_finished, notify, outcome}`.
  """

  alias Lumina.{Cache, HTTPS, Progress, URI}
  alias Lumina.RRDP
  alias Lumina.RRDP.{Delta, Notification, Snapshot, State, Store}

  # D-043.
  @max_notification 20 * 1024 * 1024
  @https_opts [:cacerts, :address, :remap, :connect_timeout, :idle_timeout, :max_redirects]
  @bytes_every 1024 * 1024
  @objects_every 1000

  @type reason ::
          :notification_failed
          | :notification_rejected
          | :cross_origin
          | :serial_not_greater
          | :snapshot_failed
          | :snapshot_hash_mismatch
          | :snapshot_rejected
          | :store_failed

  @type delta_reason :: :delta_failed | :delta_hash_mismatch | :delta_rejected | :store_failed

  @type result :: %{
          notify: URI.t(),
          outcome: :snapshot | {:deltas, pos_integer()} | :unchanged | {:failed, reason()},
          session_id: String.t() | nil,
          serial: pos_integer() | nil,
          objects: non_neg_integer() | nil,
          error: HTTPS.error() | RRDP.problem() | term() | nil,
          fallback: %{reason: delta_reason(), error: term()} | nil,
          warnings: [RRDP.problem() | tuple()]
        }

  @doc """
  Syncs the repository whose notification URI is `notify` into the cache
  at `root`. Returns the outcome; `session_id` and `serial` are the
  store's after the run (`nil` if it has never been synced); the outcome
  `{:deltas, n}` gives the deltas applied. `objects` counts the objects
  written from a snapshot or the delta elements applied, `error` is the
  failure's detail (a `Lumina.HTTPS` error, an RRDP problem or a file
  error), `fallback` why deltas gave way to the snapshot (or `nil`), and
  `warnings` the notification's (D-042) and the HTTPS fetches'.

  Options: `:now` (a `DateTime` for the state's times; default now),
  `:progress`, `:max_notification` (bytes; default 20 MiB), `:max_file`
  (snapshot or delta bytes; default 2 GiB), `:max_object` (default 20 MiB), and
  `:cacerts`, `:address`, `:remap`, `:connect_timeout`, `:idle_timeout`
  and `:max_redirects` for `Lumina.HTTPS.fetch_to_file/3`.
  """
  @spec run(URI.t(), Path.t(), keyword()) :: result()
  def run(%URI{scheme: "https"} = notify, root, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)
    state = State.load(root, notify)
    Progress.emit(opts, {:rrdp_started, notify})

    step =
      case Cache.stage(root) do
        {:ok, work} ->
          try do
            sync(notify, root, work, known(state, root, notify), opts)
          after
            Cache.discard(work)
          end

        {:error, reason} ->
          {:failed, :store_failed, reason, []}
      end

    result = finish(step, notify, root, state, now)
    Progress.emit(opts, {:rrdp_finished, notify, result.outcome})
    result
  end

  # The saved state, if the store it describes is there; otherwise the
  # repository is synced as if for the first time.
  defp known(%{session_id: id, serial: serial} = state, root, notify)
       when is_binary(id) and is_integer(serial) do
    if File.dir?(Store.path(root, notify)), do: state
  end

  defp known(_state, _root, _notify), do: nil

  defp sync(notify, root, work, known, opts) do
    case notification(notify, work, known, opts) do
      {:ok, :not_modified, warnings} ->
        {:unchanged, nil, known.last_modified, warnings}

      {:ok, n, last_modified, warnings} ->
        warnings = n.warnings ++ warnings

        cond do
          known && known.session_id == n.session_id && n.serial == known.serial ->
            {:unchanged, n, last_modified, warnings}

          known && known.session_id == n.session_id && n.serial < known.serial ->
            {:failed, :serial_not_greater,
             %{
               rule: :serial_not_greater,
               rfc: "8182#3.4.3",
               message:
                 "session #{n.session_id} is at serial #{n.serial}, " <>
                   "below the #{known.serial} last processed"
             }, warnings}

          known && known.session_id == n.session_id && covered?(n, known.serial) ->
            case deltas(notify, root, work, n, known.serial, opts) do
              {:ok, applied, count, more} ->
                {:deltas, n, last_modified, warnings ++ more, applied, count}

              # RFC 9674 §3.2: RRDP can't be used, so no snapshot either.
              {:failed, :cross_origin, detail, more} ->
                {:failed, :cross_origin, detail, warnings ++ more}

              {:failed, reason, detail, more} ->
                Progress.emit(opts, {:rrdp_fallback, notify, reason})

                {:fallback, %{reason: reason, error: detail},
                 snapshot(notify, root, work, n, last_modified, warnings ++ more, opts)}
            end

          true ->
            snapshot(notify, root, work, n, last_modified, warnings, opts)
        end

      failed ->
        failed
    end
  end

  defp notification(notify, work, known, opts) do
    path = Path.join(work, "notification.xml")

    fetch_opts =
      https(opts) ++
        [
          max_size: Keyword.get(opts, :max_notification, @max_notification),
          same_origin: true,
          if_modified_since: known && known.last_modified,
          on_data: on_data(opts, notify, :notification)
        ]

    case HTTPS.fetch_to_file(notify, path, fetch_opts) do
      {:ok, :not_modified} ->
        {:ok, :not_modified, []}

      {:ok, fetched} ->
        Progress.emit(opts, {:rrdp_downloaded, notify, :notification, fetched.size})

        with {:ok, xml} <- read(path, :notification_failed),
             {:ok, n} <- decode(xml, notify),
             do: {:ok, n, fetched.last_modified, fetched.warnings}

      {:error, %{reason: :cross_origin_redirect} = error} ->
        {:failed, :cross_origin, error, []}

      {:error, error} ->
        {:failed, :notification_failed, error, []}
    end
  end

  defp read(path, reason) do
    case File.read(path) do
      {:ok, xml} -> {:ok, xml}
      {:error, posix} -> {:failed, reason, {:file, posix}, []}
    end
  end

  defp decode(xml, notify) do
    case Notification.decode(xml, notify) do
      {:ok, n} -> {:ok, n}
      {:error, %{rule: :cross_origin} = problem} -> {:failed, :cross_origin, problem, []}
      {:error, problem} -> {:failed, :notification_rejected, problem, []}
    end
  end

  defp snapshot(notify, root, work, n, last_modified, warnings, opts) do
    path = Path.join(work, "snapshot.xml")

    with {:ok, fetched} <- fetch(notify, n.snapshot, path, :snapshot, opts) do
      case apply_snapshot(notify, root, path, n, opts) do
        {:ok, count} ->
          {:snapshot, n, last_modified, warnings ++ fetched.warnings, count}

        {:failed, reason, detail} ->
          {:failed, reason, detail, warnings ++ fetched.warnings}

        {:error, reason} ->
          {:failed, :store_failed, reason, warnings ++ fetched.warnings}
      end
    else
      {:failed, reason, detail, more} -> {:failed, reason, detail, warnings ++ more}
    end
  end

  # Fetches a snapshot or delta file (`ref`: its URI and hash in the
  # notification) to `path`, with redirects only to the notification's
  # origin, and checks its SHA-256 (RFC 8182 §3.4.2, §3.4.3).
  defp fetch(notify, ref, path, kind, opts) do
    fetch_opts =
      https(opts) ++
        [same_origin: notify, on_data: on_data(opts, notify, kind)] ++
        if(opts[:max_file], do: [max_size: opts[:max_file]], else: [])

    {failed, mismatch, rfc} =
      case kind do
        :snapshot -> {:snapshot_failed, :snapshot_hash_mismatch, "8182#3.4.3"}
        :delta -> {:delta_failed, :delta_hash_mismatch, "8182#3.4.2"}
      end

    case HTTPS.fetch_to_file(ref.uri, path, fetch_opts) do
      {:ok, %{sha256: hash} = fetched} when hash == ref.hash ->
        Progress.emit(opts, {:rrdp_downloaded, notify, kind, fetched.size})
        {:ok, fetched}

      {:ok, fetched} ->
        {:failed, mismatch,
         %{
           rule: mismatch,
           rfc: rfc,
           message:
             "#{ref.uri} has SHA-256 #{Base.encode16(fetched.sha256, case: :lower)}, " <>
               "the notification says #{Base.encode16(ref.hash, case: :lower)}"
         }, fetched.warnings}

      # No If-Modified-Since is sent, so there is no :not_modified here.
      {:error, %{reason: :cross_origin_redirect} = error} ->
        {:failed, :cross_origin, error, []}

      {:error, error} ->
        {:failed, failed, error, []}
    end
  end

  # Deltas can bring the store from `serial` to the notification's when
  # the notification lists the one right after it; the list is contiguous
  # up to the notification's serial (`Notification.decode/2`), so the rest
  # follow (RFC 8182 §3.4.1, §3.4.2).
  defp covered?(n, serial),
    do: n.serial > serial and Enum.any?(n.deltas, &(&1.serial == serial + 1))

  # Applies the deltas after `from`, in serial order, to one staged copy
  # of the store, swapped in only when all of them are in (#204).
  defp deltas(notify, root, work, n, from, opts) do
    run = Enum.filter(n.deltas, &(&1.serial > from))

    result =
      Store.update(root, notify, :deltas, fn tx ->
        result =
          Enum.reduce_while(run, {:ok, 0, []}, fn delta, {:ok, count, warnings} ->
            case apply_delta(tx, notify, work, n.session_id, delta, opts) do
              {:ok, applied, more} -> {:cont, {:ok, count + applied, warnings ++ more}}
              failed -> {:halt, failed}
            end
          end)

        case result do
          {:ok, count, warnings} ->
            Progress.emit(opts, {:rrdp_objects, notify, count})
            {:ok, {count, warnings}}

          failed ->
            failed
        end
      end)

    case result do
      {:ok, {count, warnings}} -> {:ok, length(run), count, warnings}
      {:failed, _reason, _detail, _warnings} = failed -> failed
      {:error, reason} -> {:failed, :store_failed, reason, []}
    end
  end

  # One delta: fetched, its hash checked, its root checked against the
  # session_id and its serial (one more than the last applied, since the
  # run is in order, RFC 8182 §3.4.2), and its elements applied.
  defp apply_delta(tx, notify, work, session_id, delta, opts) do
    path = Path.join(work, "delta-#{delta.serial}.xml")
    expected = %{session_id: session_id, serial: delta.serial}

    with {:ok, fetched} <- fetch(notify, delta, path, :delta, opts) do
      apply = fn element, count ->
        case change(tx, element) do
          :ok -> {:cont, count + 1}
          {:rejected, problem} -> {:halt, {:failed, :delta_rejected, problem, fetched.warnings}}
          {:error, reason} -> {:halt, {:failed, :store_failed, reason, fetched.warnings}}
        end
      end

      case Delta.stream(path, expected, apply, 0, xml_opts(opts)) do
        {:ok, count} -> {:ok, count, fetched.warnings}
        {:halted, failed} -> failed
        {:error, problem} -> {:failed, :delta_rejected, problem, fetched.warnings}
      end
    end
  end

  # RFC 8182 §3.4.2 with erratum 6919 (F-037): a withdraw, or a publish
  # with a hash, must name an object this repository's store holds, with
  # that SHA-256; a publish without a hash must be for a URI it doesn't
  # hold. The store is the repository's own (`Lumina.RRDP.Store`), so
  # another repository's objects can't be touched.
  defp change(tx, {:publish, uri, bytes}) do
    if Store.lookup(tx, uri) do
      rejected(
        :publish_without_hash,
        "#{uri} is already held; a publish replacing it must give its hash (erratum 6919)"
      )
    else
      Store.put(tx, uri, bytes)
    end
  end

  defp change(tx, {:publish, uri, bytes, hash}) do
    with :ok <- held(tx, uri, hash, :replace_not_held, :replace_hash_mismatch),
         do: Store.put(tx, uri, bytes)
  end

  defp change(tx, {:withdraw, uri, hash}) do
    with :ok <- held(tx, uri, hash, :withdraw_not_held, :withdraw_hash_mismatch),
         do: Store.withdraw(tx, uri)
  end

  defp held(tx, uri, hash, not_held, mismatch) do
    case Store.lookup(tx, uri) do
      %{sha256: ^hash} ->
        :ok

      nil ->
        rejected(not_held, "#{uri} isn't held from this repository")

      %{sha256: other} ->
        rejected(
          mismatch,
          "#{uri} has SHA-256 #{Base.encode16(other, case: :lower)}, " <>
            "the delta names #{Base.encode16(hash, case: :lower)}"
        )
    end
  end

  defp rejected(rule, message),
    do: {:rejected, %{rule: rule, rfc: "8182#3.4.2", message: message}}

  # Streams the snapshot into a new tree for the store, swapped in only if
  # every object was written.
  defp apply_snapshot(notify, root, path, n, opts) do
    expected = %{session_id: n.session_id, serial: n.serial}

    Store.update(root, notify, :snapshot, fn tx ->
      put = fn {:publish, uri, bytes}, count ->
        with {:ok, _} <- duplicate(tx, uri),
             :ok <- Store.put(tx, uri, bytes) do
          if rem(count + 1, @objects_every) == 0,
            do: Progress.emit(opts, {:rrdp_objects, notify, count + 1})

          {:cont, count + 1}
        else
          {:duplicate, problem} -> {:halt, {:failed, :snapshot_rejected, problem}}
          {:error, reason} -> {:halt, {:failed, :store_failed, {uri, reason}}}
        end
      end

      case Snapshot.stream(path, expected, put, 0, xml_opts(opts)) do
        {:ok, count} ->
          Progress.emit(opts, {:rrdp_objects, notify, count})
          {:ok, count}

        {:halted, failed} ->
          failed

        {:error, problem} ->
          {:failed, :snapshot_rejected, problem}
      end
    end)
  end

  # RFC 8182 §3.5.2.3 says a snapshot is the repository's complete state,
  # but not that a URI appears once; one published twice has no single
  # content, so the snapshot is rejected (F-041).
  defp duplicate(tx, uri) do
    case File.lstat(Store.object_path(tx, uri)) do
      {:ok, %File.Stat{type: :regular}} ->
        {:duplicate,
         %{
           rule: :duplicate_publish,
           rfc: "8182#3.5.2.3",
           message: "#{uri} is published more than once"
         }}

      _ ->
        {:ok, uri}
    end
  end

  defp finish({:fallback, fallback, step}, notify, root, state, now),
    do: %{finish(step, notify, root, state, now) | fallback: fallback}

  defp finish(step, notify, root, state, now) do
    old = state || %{}

    {outcome, n, last_modified, warnings, objects, error} =
      case step do
        {:unchanged, n, last_modified, warnings} ->
          {:unchanged, n, last_modified, warnings, nil, nil}

        {:snapshot, n, last_modified, warnings, count} ->
          {:snapshot, n, last_modified, warnings, count, nil}

        {:deltas, n, last_modified, warnings, applied, count} ->
          {{:deltas, applied}, n, last_modified, warnings, count, nil}

        {:failed, reason, detail, warnings} ->
          {{:failed, reason}, nil, nil, warnings, nil, detail}
      end

    saved =
      case outcome do
        {:failed, reason} ->
          Map.merge(old, %{last_attempt: now, outcome: {:error, describe(reason, error)}})

        _ ->
          new = if n, do: notification_state(n, last_modified), else: %{}
          Map.merge(old, Map.merge(new, %{last_attempt: now, last_success: now, outcome: :ok}))
      end

    # The store is what matters; a state that can't be written is read as
    # never synced, and the next run starts from the snapshot.
    _ = State.save(root, notify, saved)

    %{
      notify: notify,
      outcome: outcome,
      session_id: saved[:session_id],
      serial: saved[:serial],
      objects: objects,
      error: error,
      fallback: nil,
      warnings: warnings
    }
  end

  defp notification_state(n, last_modified) do
    %{
      session_id: n.session_id,
      serial: n.serial,
      deltas: Map.new(n.deltas, &{&1.serial, &1.hash}),
      last_modified: last_modified
    }
  end

  defp describe(reason, %{message: message}), do: "#{reason}: #{message}"
  defp describe(reason, %{reason: why, uri: uri}), do: "#{reason}: #{why} (#{uri})"
  defp describe(reason, detail), do: "#{reason}: #{inspect(detail)}"

  defp https(opts), do: Keyword.take(opts, @https_opts)

  defp xml_opts(opts), do: Keyword.take(opts, [:max_object])

  # Reports the bytes received every MiB.
  defp on_data(opts, notify, kind) do
    if opts[:progress] do
      last = :atomics.new(1, [])

      fn size ->
        mib = div(size, @bytes_every)

        if mib > :atomics.get(last, 1) do
          :atomics.put(last, 1, mib)
          Progress.emit(opts, {:rrdp_download, notify, kind, size})
        end
      end
    end
  end
end
