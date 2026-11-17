defmodule Lumina.RRDP.Content do
  @moduledoc """
  The streaming decoder shared by `Lumina.RRDP.Snapshot` and
  `Lumina.RRDP.Delta` (#199): the root checked against what the
  notification announced, then each `publish` and `withdraw` element
  decoded and passed to the caller's callback as soon as it ends, so a
  snapshot of hundreds of megabytes is never held whole.

  Callers use `Snapshot.stream/5` and `Delta.stream/5`; this module holds
  what they share.
  """

  alias Lumina.{RRDP, URI}
  alias Lumina.RRDP.XML

  # D-043: each published object at most 20 MiB, as for rsync (D-008).
  @max_object 20 * 1024 * 1024

  @type kind :: :snapshot | :delta
  @type expected :: %{session_id: String.t(), serial: pos_integer()}
  @type element ::
          {:publish, URI.t(), binary()}
          | {:publish, URI.t(), binary(), <<_::256>>}
          | {:withdraw, URI.t(), <<_::256>>}

  @doc """
  Decodes `source` (`{:file, path}` or `{:binary, xml}`) as a file of
  `kind`, checking its root against `expected` (the session_id and serial
  the notification gives for it), and calls `fun.(element, acc)` for each
  element, which returns `{:cont, acc}` or `{:halt, acc}`. Returns
  `{:ok, acc}`, `{:halted, acc}` or `{:error, problem}`.

  Options: `:max_object` (bytes in one decoded object; default 20 MiB,
  D-043); the rest go to the XML parser.
  """
  @spec stream(
          kind(),
          {:file, Path.t()} | {:binary, binary()},
          expected(),
          function(),
          term(),
          keyword()
        ) ::
          {:ok, term()} | {:halted, term()} | {:error, RRDP.problem()}
  def stream(kind, source, expected, fun, acc, opts) do
    {max_object, opts} = Keyword.pop(opts, :max_object, @max_object)
    # Base64 is 4/3 of the object, plus line breaks and indentation.
    opts = Keyword.put_new(opts, :max_text, div(max_object * 4, 3) + div(max_object, 4) + 4096)

    state = %{
      kind: kind,
      rfc: rfc(kind),
      expected: expected,
      fun: fun,
      acc: acc,
      max_object: max_object,
      stage: :root,
      count: 0
    }

    result =
      case source do
        {:file, path} -> XML.parse_file(path, &event/2, state, opts)
        {:binary, xml} -> XML.parse(xml, &event/2, state, opts)
      end

    case result do
      {:ok, %{kind: :delta, count: 0}} ->
        RRDP.error(
          :empty_delta,
          "8182#3.5.4",
          "a delta has at least one publish or withdraw element"
        )

      {:ok, state} ->
        {:ok, state.acc}

      {:halted, {:error, _} = error} ->
        error

      {:halted, {:caller, acc}} ->
        {:halted, acc}

      {:error, error} ->
        RRDP.xml_error(error, rfc(kind))
    end
  end

  defp rfc(:snapshot), do: "8182#3.5.2.3"
  defp rfc(:delta), do: "8182#3.5.3.3"

  defp event({:start, name, attrs}, %{stage: :root} = state) do
    with :ok <- root_name(name, state),
         {:ok, session, serial, _warnings} <- RRDP.root(attrs, state.rfc),
         :ok <- expected(session, serial, state) do
      {:cont, %{state | stage: :children}}
    else
      error -> {:halt, error}
    end
  end

  defp event({:start, "publish", attrs}, %{stage: :children} = state) do
    optional = if state.kind == :delta, do: ["hash"], else: []

    with :ok <- RRDP.attributes(attrs, ["uri"], optional, "publish", "8182#3.5.4"),
         :ok <- RRDP.namespace(attrs, state.rfc),
         {:ok, uri} <- object_uri(attrs["uri"], state),
         {:ok, hash} <- optional_hash(attrs["hash"], state) do
      {:cont, %{state | stage: {:publish, uri, hash, ""}}}
    else
      error -> {:halt, error}
    end
  end

  defp event({:start, "withdraw", attrs}, %{stage: :children, kind: :delta} = state) do
    with :ok <- RRDP.attributes(attrs, ["uri", "hash"], [], "withdraw", "8182#3.5.4"),
         :ok <- RRDP.namespace(attrs, state.rfc),
         {:ok, uri} <- object_uri(attrs["uri"], state),
         {:ok, hash} <- RRDP.hash(attrs["hash"], state.rfc) do
      {:cont, %{state | stage: {:withdraw, uri, hash}}}
    else
      error -> {:halt, error}
    end
  end

  defp event({:start, name, _}, state),
    do: halt(:schema, "8182#3.5.4", "#{state.kind} has no #{name} element here")

  defp event({:text, text}, %{stage: {:publish, uri, hash, _}} = state),
    do: {:cont, %{state | stage: {:publish, uri, hash, text}}}

  defp event({:text, text}, state) do
    if RRDP.blank?(text),
      do: {:cont, state},
      else: halt(:schema, "8182#3.5.4", "text appears where the schema allows only elements")
  end

  defp event({:end, "publish"}, %{stage: {:publish, uri, hash, text}} = state) do
    case base64(text, state) do
      {:ok, bytes} ->
        element = if hash, do: {:publish, uri, bytes, hash}, else: {:publish, uri, bytes}
        call(element, state)

      error ->
        {:halt, error}
    end
  end

  defp event({:end, "withdraw"}, %{stage: {:withdraw, uri, hash}} = state),
    do: call({:withdraw, uri, hash}, state)

  defp event({:end, _root}, state), do: {:cont, %{state | stage: :done}}

  defp call(element, state) do
    case state.fun.(element, state.acc) do
      {:cont, acc} -> {:cont, %{state | acc: acc, stage: :children, count: state.count + 1}}
      {:halt, acc} -> {:halt, {:caller, acc}}
    end
  end

  defp halt(rule, rfc, message), do: {:halt, RRDP.error(rule, rfc, message)}

  defp root_name(name, %{kind: kind}) do
    if name == Atom.to_string(kind),
      do: :ok,
      else: RRDP.error(:root, "8182#3.5.4", "the root must be #{kind}, not #{name}")
  end

  # RFC 8182 §3.5.2.3, §3.5.3.3: the session_id and serial must match the
  # notification's reference. UUIDs compare without regard to case.
  defp expected(session, serial, %{expected: expected} = state) do
    cond do
      String.downcase(session) != String.downcase(expected.session_id) ->
        RRDP.error(
          :session_mismatch,
          state.rfc,
          "the session_id #{session} isn't the notification's, #{expected.session_id}"
        )

      serial != expected.serial ->
        RRDP.error(
          :serial_mismatch,
          state.rfc,
          "the serial #{serial} isn't the one the notification gives, #{expected.serial}"
        )

      true ->
        :ok
    end
  end

  # A published object's URI: rsync, and valid for `Lumina.URI`, which
  # rejects anything that could escape the cache.
  defp object_uri(text, state) do
    case URI.parse(text) do
      {:ok, %URI{scheme: "rsync", path: [_, _ | _]} = uri} ->
        {:ok, uri}

      {:ok, _} ->
        RRDP.error(:bad_uri, state.rfc, "#{text} isn't an rsync URI of an object in a module")

      {:error, error} ->
        RRDP.error(:bad_uri, state.rfc, "#{text} isn't a valid rsync URI: #{error.message}")
    end
  end

  defp optional_hash(nil, _state), do: {:ok, nil}
  defp optional_hash(text, state), do: RRDP.hash(text, state.rfc)

  # xsd:base64Binary (RFC 8182 §3.5.4): whitespace between characters,
  # padding, and zero bits in the last group's padding.
  defp base64(text, state) do
    bytes = :base64.decode(text)

    cond do
      not canonical_end?(text) ->
        RRDP.error(:base64, "8182#3.5.4", "a publish element's base64 has non-zero padding bits")

      byte_size(bytes) > state.max_object ->
        RRDP.error(
          :object_too_large,
          "8182#3.5.4",
          "a published object is over #{state.max_object} bytes (D-043)"
        )

      true ->
        {:ok, bytes}
    end
  rescue
    _ -> RRDP.error(:base64, "8182#3.5.4", "a publish element's content isn't valid base64")
  end

  @alphabet ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

  defp canonical_end?(text) do
    # The last four characters, whitespace between them removed.
    size = byte_size(text)
    end_part = binary_part(text, size - min(size, 64), min(size, 64))
    compact = :binary.replace(end_part, [" ", "\t", "\n"], "", [:global])
    tail = binary_part(compact, max(byte_size(compact) - 4, 0), min(byte_size(compact), 4))

    case tail do
      <<_, c, "==">> -> rem(index(c), 16) == 0
      <<_, _, c, "=">> -> rem(index(c), 4) == 0
      _ -> true
    end
  end

  defp index(c), do: Enum.find_index(@alphabet, &(&1 == c))
end
