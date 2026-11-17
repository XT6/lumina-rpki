defmodule Lumina.RRDP.Notification do
  @moduledoc """
  The Update Notification File (RFC 8182 §3.5.1), decoded and checked
  (#199).

  `decode/2` takes the file and the URI it was fetched from (the
  `rpkiNotify` URI in the certificate, before any redirect), and checks:

    * well-formed XML (`Lumina.RRDP.XML`, D-041) with the RFC 8182 §3.5.4
      schema: a `notification` root with `xmlns`, `version`,
      `session_id` and `serial`, then exactly one `snapshot` (`uri`,
      `hash`), then any number of `delta`s (`serial`, `uri`, `hash`), no
      other attributes, elements or text;
    * the namespace, `version="1"`, the session_id (a version 4 UUID; any
      other UUID only warns, D-042) and a positive decimal serial
      (§3.5.1.3);
    * the deltas: a contiguous run of serials, in any order, without
      duplicates, ending at the notification's serial (§3.5.1.3);
    * each hash: 64 hex digits, a SHA-256 (§3.5.1.3);
    * each `uri`: an HTTPS URI with the notification URI's scheme, host
      and port (RFC 9674 §3.2), which `Lumina.URI.parse/1` accepts. A
      cross-origin URI rejects the file and is logged, as RFC 9674 §3.2
      says implementations SHOULD.

  The result's deltas are sorted by serial; hashes are the 32 raw bytes.
  """

  require Logger

  alias Lumina.{RRDP, URI}
  alias Lumina.RRDP.XML

  @rfc "8182#3.5.1.3"
  @schema "8182#3.5.4"

  @enforce_keys [:uri, :session_id, :serial, :snapshot, :deltas, :warnings]
  defstruct [:uri, :session_id, :serial, :snapshot, :deltas, :warnings]

  @type file_ref :: %{uri: URI.t(), hash: <<_::256>>}
  @type t :: %__MODULE__{
          uri: URI.t(),
          session_id: String.t(),
          serial: pos_integer(),
          snapshot: file_ref(),
          deltas: [%{serial: pos_integer(), uri: URI.t(), hash: <<_::256>>}],
          warnings: [RRDP.problem()]
        }

  @doc """
  Decodes the notification file `xml`, fetched from `uri` (a
  `Lumina.URI`). Options go to the XML parser (limits).
  """
  @spec decode(binary(), URI.t(), keyword()) :: {:ok, t()} | {:error, RRDP.problem()}
  def decode(xml, %URI{scheme: "https"} = uri, opts \\ []) do
    state = %{uri: uri, stage: :root, root: nil, snapshot: nil, deltas: []}

    case XML.parse(xml, &event/2, state, opts) do
      {:ok, state} -> finish(state)
      {:halted, {:error, _} = error} -> error
      {:error, error} -> RRDP.xml_error(error, @rfc)
    end
  end

  defp event({:start, "notification", attrs}, %{stage: :root} = state) do
    case RRDP.root(attrs, @rfc) do
      {:ok, session, serial, warnings} ->
        {:cont, %{state | stage: :children, root: {session, serial, warnings}}}

      error ->
        {:halt, error}
    end
  end

  defp event({:start, name, _}, %{stage: :root}),
    do: halt(:root, @schema, "the root must be notification, not #{name}")

  defp event({:start, "snapshot", attrs}, %{stage: :children, snapshot: nil, deltas: []} = state) do
    with :ok <- RRDP.attributes(attrs, ~w(uri hash), [], "snapshot", @schema),
         :ok <- RRDP.namespace(attrs, @rfc),
         {:ok, uri} <- same_origin(attrs["uri"], state.uri),
         {:ok, hash} <- RRDP.hash(attrs["hash"], @rfc) do
      {:cont, %{state | stage: :snapshot, snapshot: %{uri: uri, hash: hash}}}
    else
      error -> {:halt, error}
    end
  end

  defp event({:start, "snapshot", _}, %{stage: :children}),
    do: halt(:snapshot_count, @rfc, "a notification has exactly one snapshot, before any delta")

  defp event({:start, "delta", _}, %{stage: :children, snapshot: nil}),
    do: halt(:schema, @schema, "the snapshot element comes before the deltas")

  defp event({:start, "delta", attrs}, %{stage: :children} = state) do
    with :ok <- RRDP.attributes(attrs, ~w(serial uri hash), [], "delta", @schema),
         :ok <- RRDP.namespace(attrs, @rfc),
         {:ok, serial} <- RRDP.serial(attrs["serial"], @rfc),
         {:ok, uri} <- same_origin(attrs["uri"], state.uri),
         {:ok, hash} <- RRDP.hash(attrs["hash"], @rfc) do
      delta = %{serial: serial, uri: uri, hash: hash}
      {:cont, %{state | stage: :delta, deltas: [delta | state.deltas]}}
    else
      error -> {:halt, error}
    end
  end

  defp event({:start, name, _}, %{stage: stage}) when stage in [:snapshot, :delta],
    do: halt(:schema, @schema, "#{stage} has no child elements, but has #{name}")

  defp event({:start, name, _}, _state),
    do: halt(:schema, @schema, "notification has no #{name} element")

  defp event({:end, _name}, %{stage: stage} = state) when stage in [:snapshot, :delta],
    do: {:cont, %{state | stage: :children}}

  defp event({:end, "notification"}, state), do: {:cont, %{state | stage: :done}}

  defp event({:text, text}, state) do
    if RRDP.blank?(text),
      do: {:cont, state},
      else: halt(:schema, @schema, "the notification file has no text content")
  end

  defp halt(rule, rfc, message), do: {:halt, RRDP.error(rule, rfc, message)}

  # RFC 9674 §3.2: the same scheme, host and port as the notification.
  defp same_origin(text, %URI{} = notification) do
    case URI.parse(text) do
      {:ok, %URI{scheme: scheme, host: host, port: port} = uri}
      when scheme == notification.scheme and host == notification.host and
             port == notification.port ->
        {:ok, uri}

      {:ok, _other} ->
        cross_origin(text, notification)

      {:error, %{rule: :unsupported_scheme}} ->
        cross_origin(text, notification)

      {:error, error} ->
        RRDP.error(:bad_uri, @rfc, "#{text} isn't a valid URI: #{error.message}")
    end
  end

  defp cross_origin(text, notification) do
    Logger.warning("RRDP: #{notification} refers to #{text}, of another origin (RFC 9674)")

    RRDP.error(
      :cross_origin,
      "9674#3.2",
      "#{text} isn't of the notification's origin (#{origin(notification)})"
    )
  end

  defp origin(%URI{} = uri), do: to_string(%{uri | path: []})

  # RFC 8182 §3.5.1.3: exactly one snapshot, deltas contiguous up to the
  # notification's serial.
  defp finish(%{snapshot: nil}),
    do: RRDP.error(:snapshot_count, @rfc, "a notification has exactly one snapshot")

  defp finish(%{root: {session, serial, warnings}} = state) do
    deltas = Enum.sort_by(state.deltas, & &1.serial)
    serials = Enum.map(deltas, & &1.serial)

    cond do
      serials != Enum.uniq(serials) ->
        RRDP.error(:delta_serials, @rfc, "two deltas have the same serial")

      serials != [] and List.last(serials) != serial ->
        RRDP.error(
          :delta_serials,
          @rfc,
          "the deltas must end at the notification's serial, #{serial}"
        )

      serials != [] and serials != Enum.to_list(hd(serials)..serial) ->
        RRDP.error(:delta_serials, @rfc, "the delta serials must be contiguous")

      true ->
        {:ok,
         %__MODULE__{
           uri: state.uri,
           session_id: session,
           serial: serial,
           snapshot: state.snapshot,
           deltas: deltas,
           warnings: warnings
         }}
    end
  end
end
