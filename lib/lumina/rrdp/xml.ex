defmodule Lumina.RRDP.XML do
  @moduledoc """
  A strict, streaming XML parser for RRDP files (RFC 8182 §3.5, D-041,
  #198).

  RRDP files must be well-formed XML (RFC 8182 §3.5.1.3, §3.5.2.3,
  §3.5.3.3), and a snapshot can be hundreds of megabytes (ARIN's was
  760 MB on 2026-11-16), so the file is read in chunks and never held in
  memory whole: memory is bounded by the largest text node and tag, which
  the caller limits. RFC 8182 cites no XML specification (F-039); the
  rules here are XML 1.0 (Fifth Edition) for the subset RRDP needs, and
  error clauses name its sections.

  **Accepted:**

    * an optional XML declaration at the very start: `version` 1.x, an
      optional `encoding`, which must be US-ASCII (RFC 8182 §3.5.1.3),
      and an optional `standalone`, in single or double quotes;
    * elements, with attributes in any order;
    * the five predefined entities (`&amp;` `&lt;` `&gt;` `&quot;`
      `&apos;`) and character references (`&#65;`, `&#x41;`), in text
      and attribute values;
    * text, whitespace, and comments (XML 1.0 §2.5), which are skipped:
      text on both sides of a comment is one text node.

  **Rejected (D-041):** a DOCTYPE, processing instructions other than the
  declaration, CDATA sections, any other entity, bytes outside US-ASCII
  and characters XML doesn't allow, and namespace prefixes (an element or
  attribute name with a colon, such as `xmlns:r`): RRDP needs only a
  default namespace, and no server surveyed used prefixes. `xmlns` is
  reported as an ordinary attribute; checking its value is the caller's
  job.

  Line ends are normalized to LF (XML 1.0 §2.11), and whitespace in
  attribute values to spaces (§3.3.3).

  **Events** go to a callback `fun.(event, acc)`, which returns
  `{:cont, acc}` to go on or `{:halt, acc}` to stop:

    * `{:start, name, attributes}`, attributes a map of name to value;
    * `{:text, text}`, a whole text node inside the root, decoded; it may
      be only whitespace;
    * `{:end, name}`.

  An empty element `<a/>` gives `:start` and `:end`. Text outside the
  root may only be whitespace and gives no event.

  **Errors** are `%{rule, clause, offset, message}`, `offset` the byte
  offset in the document where the problem starts, in the style of
  `Lumina.DER`.

  **Limits** (options): `:max_text` (bytes in one text node, decoded;
  default 1 MiB; the caller sets it from D-043's 20 MiB per object,
  base64-expanded), `:max_tag` (bytes in one tag, comment or
  declaration; default 64 KiB), `:max_depth` (element nesting; default
  8) and `:max_attributes` (per element; default 16).
  """

  @type event ::
          {:start, String.t(), %{String.t() => String.t()}}
          | {:text, binary()}
          | {:end, String.t()}
  @type error :: %{
          rule: atom(),
          clause: String.t(),
          offset: non_neg_integer(),
          message: String.t()
        }
  @type callback :: (event(), term() -> {:cont, term()} | {:halt, term()})
  @type result :: {:ok, term()} | {:halted, term()} | {:error, error()}

  @defaults [max_text: 1024 * 1024, max_tag: 64 * 1024, max_depth: 8, max_attributes: 16]
  @chunk 64 * 1024

  # Bytes XML doesn't allow, or RRDP's US-ASCII encoding (RFC 8182
  # §3.5.1.3) doesn't: control characters other than tab, LF and CR
  # (XML 1.0 §2.2), DEL, and everything from 0x80.
  @bad_bytes for b <-
                   Enum.to_list(0..8) ++
                     [11, 12] ++ Enum.to_list(14..31) ++ Enum.to_list(127..255),
                 do: <<b>>

  @whitespace ~c" \t\r\n"

  defstruct buffer: "",
            offset: 0,
            stage: :start,
            stack: [],
            depth: 0,
            text: [],
            text_size: 0,
            opts: []

  @opaque t :: %__MODULE__{}

  @doc """
  Parses the file at `path`, calling `fun` for each event. Returns
  `{:ok, acc}`, `{:halted, acc}` if `fun` stopped, `{:error, error}`, or
  `{:error, {:file, reason}}` if the file can't be read.
  """
  @spec parse_file(Path.t(), callback(), term(), keyword()) ::
          result() | {:error, {:file, File.posix()}}
  def parse_file(path, fun, acc, opts \\ []) do
    case File.open(path, [:read, :binary, :raw]) do
      {:ok, io} ->
        try do
          read_loop(io, new(opts), fun, acc)
        after
          File.close(io)
        end

      {:error, reason} ->
        {:error, {:file, reason}}
    end
  end

  defp read_loop(io, state, fun, acc) do
    case :file.read(io, @chunk) do
      {:ok, chunk} ->
        case feed(state, chunk, fun, acc) do
          {:ok, state, acc} -> read_loop(io, state, fun, acc)
          other -> other
        end

      :eof ->
        finish(state, fun, acc)

      {:error, reason} ->
        {:error, {:file, reason}}
    end
  end

  @doc """
  Parses `xml`, a whole document in memory, calling `fun` for each event.

      iex> collect = fn event, acc -> {:cont, [event | acc]} end
      iex> {:ok, events} = Lumina.RRDP.XML.parse(~s(<a x="1"><b>t&amp;u</b><!-- c --></a>), collect, [])
      iex> Enum.reverse(events)
      [{:start, "a", %{"x" => "1"}}, {:start, "b", %{}}, {:text, "t&u"}, {:end, "b"}, {:end, "a"}]

      iex> {:error, %{rule: :doctype}} = Lumina.RRDP.XML.parse("<!DOCTYPE a><a/>", fn _, acc -> {:cont, acc} end, nil)

  """
  @spec parse(binary(), callback(), term(), keyword()) :: result()
  def parse(xml, fun, acc, opts \\ []) when is_binary(xml) do
    case feed(new(opts), xml, fun, acc) do
      {:ok, state, acc} -> finish(state, fun, acc)
      other -> other
    end
  end

  @doc "A parser state for `feed/4` and `finish/3`, with the limits in `opts`."
  @spec new(keyword()) :: t()
  def new(opts \\ []), do: %__MODULE__{opts: Keyword.merge(@defaults, opts)}

  @doc """
  Feeds the next `chunk` of the document. Returns `{:ok, state, acc}` to
  feed more, `{:halted, acc}` or `{:error, error}`. Chunks may split the
  document anywhere: the events are the same.
  """
  @spec feed(t(), binary(), callback(), term()) ::
          {:ok, t(), term()} | {:halted, term()} | {:error, error()}
  def feed(%__MODULE__{} = state, chunk, fun, acc) when is_binary(chunk) do
    {state, acc} = run(%{state | buffer: state.buffer <> chunk}, fun, acc)
    {:ok, state, acc}
  catch
    {:xml_halt, acc} -> {:halted, acc}
    {:xml_error, error} -> {:error, error}
  end

  @doc """
  Ends the document: checks that it is complete (one root, closed, and
  nothing but whitespace and comments after it). Returns `{:ok, acc}` or
  `{:error, error}`.
  """
  @spec finish(t(), callback(), term()) :: {:ok, term()} | {:error, error()}
  def finish(%__MODULE__{buffer: rest, stage: stage} = state, _fun, acc) do
    cond do
      stage in [:start, :prolog] and blank?(rest) ->
        {:error, error(:no_root, "2.1", state.offset, "the document has no root element")}

      stage == :epilog and blank?(rest) ->
        {:ok, acc}

      stage == :epilog and :binary.match(rest, "<") == :nomatch ->
        {:error,
         error(:text_after_root, "2.8", state.offset, "only whitespace may follow the root")}

      true ->
        {:error, error(:truncated, "2.1", state.offset, "the document ends in the middle")}
    end
  end

  # The main loop: text up to the next `<`, then the markup there.
  defp run(%{buffer: buffer} = state, fun, acc) do
    case :binary.match(buffer, "<") do
      :nomatch ->
        {pending_text(state), acc}

      {pos, 1} ->
        text = binary_part(buffer, 0, pos)
        rest = binary_part(buffer, pos, byte_size(buffer) - pos)
        state = text(state, text, state.offset)
        state = %{state | buffer: rest, offset: state.offset + pos}

        case markup(state, rest, fun, acc) do
          :more ->
            if byte_size(rest) > state.opts[:max_tag],
              do:
                throw_error(:tag_too_long, "2.1", state.offset, "markup is over the size limit"),
              else: {state, acc}

          {state, acc} ->
            run(state, fun, acc)
        end
    end
  end

  # No `<` in the buffer: its text is taken now, so a large text node
  # isn't copied with every chunk, except a tail that a later chunk could
  # change: an unfinished reference, `]` or `]]` (which `>` would make
  # `]]>`), or a CR (which LF would make CRLF).
  defp pending_text(%{buffer: buffer} = state) do
    take = byte_size(buffer) - tail(buffer)
    text = binary_part(buffer, 0, take)
    rest = binary_part(buffer, take, byte_size(buffer) - take)
    state = text(state, text, state.offset)
    %{state | buffer: rest, offset: state.offset + take}
  end

  defp tail(buffer) do
    size = byte_size(buffer)
    window = min(size, 16)

    # A valid reference is at most 10 bytes (&#x10FFFF;), so one that
    # starts further back is complete or an error.
    amp =
      case :binary.matches(buffer, "&", scope: {size - window, window}) do
        [] ->
          0

        matches ->
          {pos, 1} = List.last(matches)

          if :binary.match(buffer, ";", scope: {pos, size - pos}) == :nomatch,
            do: size - pos,
            else: 0
      end

    other =
      cond do
        String.ends_with?(buffer, "]]") -> 2
        String.ends_with?(buffer, ["]", "\r"]) -> 1
        true -> 0
      end

    max(amp, other)
  end

  # Text at `offset`: outside the root only whitespace; inside it, checked,
  # decoded and added to the text node.
  defp text(state, "", _offset), do: state

  defp text(%{stage: stage} = state, text, offset) when stage in [:start, :prolog, :epilog] do
    cond do
      blank?(text) and stage == :start ->
        %{state | stage: :prolog}

      blank?(text) ->
        state

      true ->
        check_bytes(text, offset)

        if stage == :epilog,
          do: throw_error(:text_after_root, "2.8", offset, "only whitespace may follow the root"),
          else:
            throw_error(:text_before_root, "2.8", offset, "only whitespace may precede the root")
    end
  end

  defp text(state, text, offset) do
    check_bytes(text, offset)

    case :binary.match(text, "]]>") do
      {pos, _} -> throw_error(:cdata_end, "2.4", offset + pos, "]]> may not appear in text")
      :nomatch -> :ok
    end

    decoded = text |> line_ends() |> references(offset)
    size = state.text_size + byte_size(decoded)

    if size > state.opts[:max_text],
      do: throw_error(:text_too_long, "2.4", offset, "a text node is over the size limit")

    %{state | text: [state.text, decoded], text_size: size}
  end

  defp flush(%{text_size: 0} = state, _fun, acc), do: {state, acc}

  defp flush(state, fun, acc) do
    text = IO.iodata_to_binary(state.text)
    {%{state | text: [], text_size: 0}, emit(fun, {:text, text}, acc)}
  end

  defp emit(fun, event, acc) do
    case fun.(event, acc) do
      {:cont, acc} -> acc
      {:halt, acc} -> throw({:xml_halt, acc})
    end
  end

  # Markup at the start of `buffer` (`state.offset`). Returns the new state
  # and accumulator, or :more if the buffer ends before the markup does.
  defp markup(state, buffer, fun, acc) do
    case buffer do
      <<"<?", _::binary>> ->
        {declaration(state, buffer), acc}

      <<"<!--", _::binary>> ->
        {comment(state, buffer), acc}

      <<"<!-">> ->
        :more

      <<"<!-", _::binary>> ->
        throw_error(:bad_comment, "2.5", state.offset, "a comment starts with <!--")

      <<"<![", _::binary>> ->
        throw_error(:cdata, "2.7", state.offset, "CDATA sections are not accepted (D-041)")

      <<"<!">> ->
        :more

      <<"<!", _::binary>> ->
        throw_error(:doctype, "2.8", state.offset, "a DOCTYPE is not accepted (D-041)")

      <<"</", _::binary>> ->
        end_tag(state, buffer, fun, acc)

      <<"<">> ->
        :more

      _ ->
        start_tag(state, buffer, fun, acc)
    end
  catch
    :more -> :more
  end

  # XML 1.0 §2.8: <?xml version="1.x" encoding="..." standalone="..."?>,
  # only at the very start of the document.
  defp declaration(state, buffer) do
    cond do
      byte_size(buffer) < 6 and String.starts_with?("<?xml ", buffer) ->
        throw(:more)

      state.stage != :start or not declaration_start?(buffer) ->
        throw_error(
          :processing_instruction,
          "2.6",
          state.offset,
          "processing instructions are not accepted (D-041); an XML declaration must come first"
        )

      true ->
        case :binary.match(buffer, "?>") do
          :nomatch ->
            throw(:more)

          {pos, 2} ->
            check_size(state, pos + 2)
            body = binary_part(buffer, 5, pos - 5)
            check_bytes(body, state.offset + 5)
            check_declaration(pseudo_attributes(body, state.offset + 5), state.offset)
            consume(%{state | stage: :prolog}, pos + 2)
        end
    end
  end

  defp declaration_start?(<<"<?xml", c, _::binary>>) when c in @whitespace, do: true
  defp declaration_start?(_), do: false

  # The declaration's body is complete; "?" stands in for its end.
  defp pseudo_attributes(body, offset) do
    {:ok, attrs, "?"} = attributes(body <> "?", offset, [])
    attrs
  catch
    :more -> throw_error(:bad_declaration, "2.8", offset, "the XML declaration is malformed")
  end

  @declaration_orders [
    ~w(version),
    ~w(version encoding),
    ~w(version standalone),
    ~w(version encoding standalone)
  ]

  defp check_declaration(attrs, offset) do
    unless Enum.map(attrs, &elem(&1, 0)) in @declaration_orders,
      do: throw_error(:bad_declaration, "2.8", offset, "the XML declaration is malformed")

    values = Map.new(attrs)

    unless values["version"] =~ ~r/\A1\.[0-9]+\z/,
      do: throw_error(:bad_declaration, "2.8", offset, "the XML version must be 1.x")

    encoding = values["encoding"]

    unless encoding == nil or String.upcase(encoding) == "US-ASCII",
      do:
        throw_error(
          :encoding,
          "4.3.3",
          offset,
          "the encoding must be US-ASCII (RFC 8182 section 3.5.1.3), not #{encoding}"
        )

    unless values["standalone"] in [nil, "yes", "no"],
      do: throw_error(:bad_declaration, "2.9", offset, "standalone must be yes or no")

    :ok
  end

  # XML 1.0 §2.5: <!-- ... -->, without -- inside and not ending in -.
  defp comment(state, buffer) do
    case :binary.match(buffer, "-->", scope: {4, byte_size(buffer) - 4}) do
      :nomatch ->
        throw(:more)

      {pos, 3} ->
        check_size(state, pos + 3)
        body = binary_part(buffer, 4, pos - 4)
        check_bytes(body, state.offset + 4)

        if :binary.match(body, "--") != :nomatch or String.ends_with?(body, "-"),
          do: throw_error(:comment_dashes, "2.5", state.offset, "-- may not appear in a comment")

        consume(state, pos + 3)
    end
  end

  # XML 1.0 §3.1: </name S?>.
  defp end_tag(state, <<"</", rest::binary>> = buffer, fun, acc) do
    {:ok, name, after_name} = name(rest, state.offset + 2)
    after_space = skip_space(after_name)

    case after_space do
      <<">", _::binary>> ->
        consumed = byte_size(buffer) - byte_size(after_space) + 1
        check_size(state, consumed)
        check_bytes(binary_part(buffer, 0, consumed), state.offset)

        case state.stack do
          [^name | stack] ->
            {state, acc} = flush(state, fun, acc)
            acc = emit(fun, {:end, name}, acc)
            stage = if stack == [], do: :epilog, else: :content

            {consume(%{state | stack: stack, depth: state.depth - 1, stage: stage}, consumed),
             acc}

          [open | _] ->
            throw_error(:mismatched_tag, "3", state.offset, "</#{name}> closes <#{open}>")

          [] ->
            throw_error(:mismatched_tag, "3", state.offset, "</#{name}> closes nothing")
        end

      "" ->
        throw(:more)

      _ ->
        at = state.offset + byte_size(buffer) - byte_size(after_space)
        throw_error(:bad_tag, "3.1", at, "an end tag is malformed")
    end
  end

  # XML 1.0 §3.1: <name (S attribute)* S? (/>|>).
  defp start_tag(state, <<"<", rest::binary>> = buffer, fun, acc) do
    {:ok, name, after_name} = name(rest, state.offset + 1)
    at = state.offset + byte_size(buffer) - byte_size(after_name)
    {:ok, attrs, after_attrs} = attributes(after_name, at, [])

    {empty?, tail} =
      case after_attrs do
        <<"/>", tail::binary>> ->
          {true, tail}

        <<">", tail::binary>> ->
          {false, tail}

        <<"/">> ->
          throw(:more)

        _ ->
          at = state.offset + byte_size(buffer) - byte_size(after_attrs)
          throw_error(:bad_tag, "3.1", at, "a start tag is malformed")
      end

    consumed = byte_size(buffer) - byte_size(tail)
    check_size(state, consumed)
    check_bytes(binary_part(buffer, 0, consumed), state.offset)
    check_names(name, attrs, state.offset)
    attributes = attribute_map(attrs, state)

    if state.stage == :epilog,
      do: throw_error(:multiple_roots, "2.1", state.offset, "a document has one root element")

    if state.depth >= state.opts[:max_depth],
      do: throw_error(:too_deep, "3", state.offset, "elements nest deeper than the limit")

    {state, acc} = flush(state, fun, acc)
    acc = emit(fun, {:start, name, attributes}, acc)

    if empty? do
      acc = emit(fun, {:end, name}, acc)
      stage = if state.stack == [], do: :epilog, else: :content
      {consume(%{state | stage: stage}, consumed), acc}
    else
      state = %{state | stage: :content, stack: [name | state.stack], depth: state.depth + 1}
      {consume(state, consumed), acc}
    end
  end

  defp attribute_map(attrs, state) do
    if length(attrs) > state.opts[:max_attributes],
      do:
        throw_error(
          :too_many_attributes,
          "3.1",
          state.offset,
          "an element has more attributes than the limit"
        )

    Enum.reduce(attrs, %{}, fn {name, value}, map ->
      if Map.has_key?(map, name),
        do:
          throw_error(
            :duplicate_attribute,
            "3.1",
            state.offset,
            "attribute #{name} appears twice"
          ),
        else: Map.put(map, name, value)
    end)
  end

  defp check_names(name, attrs, offset) do
    for n <- [name | Enum.map(attrs, &elem(&1, 0))], String.contains?(n, ":") do
      throw_error(
        :namespace_prefix,
        "3.1",
        offset,
        "namespace prefixes are not accepted (D-041): #{n}"
      )
    end

    :ok
  end

  # Attributes: (S name S? = S? quoted)*, up to the `>`, `/` or `?` that
  # follows them; `offset` is where `bin` starts. Returns
  # {:ok, [{name, value}], rest}, or throws :more.
  defp attributes(bin, offset, acc) do
    after_space = skip_space(bin)
    at = offset + byte_size(bin) - byte_size(after_space)

    case after_space do
      "" ->
        throw(:more)

      <<c, _::binary>> when c in [?>, ?/, ??] ->
        {:ok, Enum.reverse(acc), after_space}

      _ when after_space == bin ->
        throw_error(:missing_whitespace, "3.1", at, "attributes are separated by whitespace")

      _ ->
        {:ok, name, rest} = name(after_space, at)

        rest =
          case skip_space(rest) do
            <<"=", rest::binary>> -> skip_space(rest)
            "" -> throw(:more)
            _ -> throw_error(:bad_attribute, "3.1", at, "attribute #{name} has no value")
          end

        value_at = offset + byte_size(bin) - byte_size(rest)

        case rest do
          <<q, quoted::binary>> when q in [?", ?'] ->
            case :binary.match(quoted, <<q>>) do
              :nomatch ->
                throw(:more)

              {pos, 1} ->
                raw = binary_part(quoted, 0, pos)
                rest = binary_part(quoted, pos + 1, byte_size(quoted) - pos - 1)
                value = value(raw, value_at + 1)
                attributes(rest, offset + byte_size(bin) - byte_size(rest), [{name, value} | acc])
            end

          "" ->
            throw(:more)

          _ ->
            throw_error(:unquoted_attribute, "3.1", value_at, "attribute values are quoted")
        end
    end
  end

  # XML 1.0 §3.1, §3.3.3: no <, references decoded, whitespace to spaces.
  defp value(raw, offset) do
    check_bytes(raw, offset)

    case :binary.match(raw, "<") do
      {pos, 1} ->
        throw_error(
          :lt_in_attribute,
          "3.1",
          offset + pos,
          "< may not appear in an attribute value"
        )

      :nomatch ->
        :ok
    end

    raw
    |> line_ends()
    |> :binary.replace(["\t", "\n"], " ", [:global])
    |> references(offset)
  end

  # XML 1.0 §2.3, restricted to ASCII names; a colon is allowed here and
  # rejected by `check_names/3` with its own rule. A name that runs to the
  # end of the buffer may go on in the next chunk.
  defp name(<<c, _::binary>> = bin, _offset)
       when c in ?a..?z or c in ?A..?Z or c in [?_, ?:] do
    size = name_size(bin, 0)

    if size == byte_size(bin),
      do: throw(:more),
      else: {:ok, binary_part(bin, 0, size), binary_part(bin, size, byte_size(bin) - size)}
  end

  defp name("", _offset), do: throw(:more)

  defp name(_bin, offset),
    do: throw_error(:bad_name, "2.3", offset, "a name must start with a letter or _")

  defp name_size(<<c, rest::binary>>, n)
       when c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in [?_, ?:, ?., ?-],
       do: name_size(rest, n + 1)

  defp name_size(_, n), do: n

  defp skip_space(<<c, rest::binary>>) when c in @whitespace, do: skip_space(rest)
  defp skip_space(bin), do: bin

  # XML 1.0 §4.1, §4.6: the five predefined entities and character
  # references; any other entity is rejected (D-041).
  defp references(text, offset) do
    case :binary.split(text, "&", [:global]) do
      [plain] -> plain
      [first | parts] -> decode(parts, offset + byte_size(first), [first])
    end
  end

  defp decode([], _offset, acc), do: acc |> Enum.reverse() |> IO.iodata_to_binary()

  defp decode([part | parts], offset, acc) do
    case :binary.split(part, ";") do
      [ref, rest] ->
        decode(parts, offset + 1 + byte_size(part), [rest, reference(ref, offset) | acc])

      [_] ->
        throw_error(:bad_reference, "4.1", offset, "& must start a reference ending in ;")
    end
  end

  defp reference("amp", _), do: "&"
  defp reference("lt", _), do: "<"
  defp reference("gt", _), do: ">"
  defp reference("quot", _), do: "\""
  defp reference("apos", _), do: "'"

  defp reference("#x" <> hex, offset) do
    if hex =~ ~r/\A[0-9a-fA-F]{1,6}\z/,
      do: char(String.to_integer(hex, 16), offset),
      else: throw_error(:bad_reference, "4.1", offset, "a character reference is malformed")
  end

  defp reference("#" <> dec, offset) do
    if dec =~ ~r/\A[0-9]{1,7}\z/,
      do: char(String.to_integer(dec), offset),
      else: throw_error(:bad_reference, "4.1", offset, "a character reference is malformed")
  end

  defp reference(name, offset) do
    if name =~ ~r/\A[A-Za-z_][A-Za-z0-9._-]*\z/,
      do: throw_error(:entity, "4.1", offset, "the entity &#{name}; is not accepted (D-041)"),
      else: throw_error(:bad_reference, "4.1", offset, "& must start a reference ending in ;")
  end

  # XML 1.0 §2.2: the characters a reference may name.
  defp char(c, offset) do
    if c in [0x9, 0xA, 0xD] or c in 0x20..0xD7FF or c in 0xE000..0xFFFD or c in 0x10000..0x10FFFF,
      do: <<c::utf8>>,
      else:
        throw_error(
          :bad_reference,
          "4.1",
          offset,
          "a character reference names a character XML doesn't allow"
        )
  end

  # XML 1.0 §2.11: CRLF and a lone CR become LF.
  defp line_ends(text) do
    if :binary.match(text, "\r") == :nomatch,
      do: text,
      else:
        text |> :binary.replace("\r\n", "\n", [:global]) |> :binary.replace("\r", "\n", [:global])
  end

  defp check_bytes(bin, offset) do
    case :binary.match(bin, bad_bytes()) do
      :nomatch ->
        :ok

      {pos, 1} ->
        byte = :binary.at(bin, pos)
        hex = Integer.to_string(byte, 16)

        if byte >= 0x80,
          do:
            throw_error(
              :non_ascii,
              "2.2",
              offset + pos,
              "byte 0x#{hex} isn't US-ASCII (RFC 8182 section 3.5.1.3)"
            ),
          else:
            throw_error(
              :invalid_char,
              "2.2",
              offset + pos,
              "byte 0x#{hex} isn't a character XML allows"
            )
    end
  end

  defp check_size(state, size) do
    if size > state.opts[:max_tag],
      do: throw_error(:tag_too_long, "2.1", state.offset, "markup is over the size limit")
  end

  # The compiled pattern of @bad_bytes, made once per VM: compiling the
  # list again on every call costs more than the search.
  defp bad_bytes do
    case :persistent_term.get({__MODULE__, :bad_bytes}, nil) do
      nil ->
        pattern = :binary.compile_pattern(@bad_bytes)
        :persistent_term.put({__MODULE__, :bad_bytes}, pattern)
        pattern

      pattern ->
        pattern
    end
  end

  defp blank?(<<c, rest::binary>>) when c in @whitespace, do: blank?(rest)
  defp blank?(<<>>), do: true
  defp blank?(_), do: false

  defp consume(state, n),
    do: %{
      state
      | buffer: binary_part(state.buffer, n, byte_size(state.buffer) - n),
        offset: state.offset + n
    }

  defp error(rule, section, offset, message),
    do: %{rule: rule, clause: "XML 1.0 §#{section}", offset: offset, message: message}

  @spec throw_error(atom(), String.t(), non_neg_integer(), String.t()) :: no_return()
  defp throw_error(rule, section, offset, message),
    do: throw({:xml_error, error(rule, section, offset, message)})
end
