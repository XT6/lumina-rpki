defmodule Lumina.DER do
  @moduledoc """
  Checks that input is valid DER, the encoding RPKI requires everywhere
  (RFC 6488 §3 check (l), RFC 6481 §2.2, RFC 9582 §1). OTP's ASN.1
  decoders accept BER, so DER is enforced here, in two complementary ways:

    * `check/1` walks the tag-length-value structure and applies every DER
      rule that can be checked without a schema: length and tag forms,
      primitive or constructed form, and the encoding of universal types
      (BOOLEAN, INTEGER, BIT STRING, OBJECT IDENTIFIER, NULL, the time
      types, SET OF ordering). Contents of constructed values are checked
      recursively, whatever their tag.
    * `check_canonical/3` decodes a value with its ASN.1 type, re-encodes it
      in DER and requires identical bytes. That catches what a walk can't
      see: DEFAULT values that were encoded, and rules hidden by implicit
      tags (an `[0] IMPLICIT SET OF` looks like any context-specific
      value).

  Errors name the rule, the X.690 clause and the byte offset. X.690 isn't
  in `doc/rfc/`; clause numbers follow X.690 (02/2021).

  A universal SET is checked as a SET OF (sorted elements, X.690 11.6).
  The only true SET types in Lumina's modules are X.400 address types that
  RPKI never uses (RFC 5280 A.1).
  """

  @type error :: %{
          rule: atom(),
          clause: String.t(),
          offset: non_neg_integer(),
          message: String.t()
        }

  # Universal tags.
  @boolean 1
  @integer 2
  @bit_string 3
  @octet_string 4
  @null 5
  @oid 6
  @enumerated 10
  @utf8_string 12
  @sequence 16
  @set 17
  @utc_time 23
  @generalized_time 24

  # Types that DER requires to be primitive: BIT STRING, OCTET STRING and
  # the restricted character string types, which include the time types
  # (X.690 10.2), plus the other primitive-only universal types.
  @primitive_only [
    @boolean,
    @integer,
    @bit_string,
    @octet_string,
    @null,
    @oid,
    @enumerated,
    @utf8_string,
    18,
    19,
    20,
    21,
    22,
    @utc_time,
    @generalized_time,
    25,
    26,
    27,
    28,
    30
  ]

  @doc """
  Checks that `der` is exactly one DER encoding, with nothing after it.

  ## Examples

      iex> Lumina.DER.check(<<0x02, 0x01, 0x05>>)
      :ok

      iex> {:error, %{rule: :indefinite_length}} = Lumina.DER.check(<<0x30, 0x80, 0x00, 0x00>>)

  """
  @spec check(binary()) :: :ok | {:error, error()}
  def check(der) when is_binary(der) do
    case tlv(der, 0) do
      {:ok, _tlv, <<>>} ->
        :ok

      {:ok, tlv, rest} ->
        error(
          :trailing_bytes,
          "X.690 8.1.1",
          tlv.next,
          "#{byte_size(rest)} byte(s) after the encoding"
        )

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Decodes `der` as `type` from `Lumina.ASN1` module `key`, re-encodes the
  value in DER and requires the same bytes. Run `check/1` first; this
  catches the DER rules a schema-less walk can't see.
  """
  @spec check_canonical(Lumina.ASN1.module_key(), atom(), binary()) ::
          :ok | {:error, error() | term()}
  def check_canonical(key, type, der) do
    with {:ok, value} <- Lumina.ASN1.decode(key, type, der),
         {:ok, reencoded} <- Lumina.ASN1.encode(key, type, value) do
      if reencoded == der,
        do: :ok,
        else:
          error(
            :not_canonical,
            "X.690 10, 11",
            first_difference(der, reencoded),
            "not the DER encoding of its value (for example a DEFAULT value was encoded, or an implicitly tagged SET OF is unsorted)"
          )
    end
  end

  # One TLV starting at `offset` (the position of `data` in the input).
  defp tlv(data, offset) do
    with {:ok, tag, after_tag} <- identifier(data, offset),
         {:ok, length, after_length} <-
           length(after_tag, offset + byte_size(data) - byte_size(after_tag)),
         content_offset = offset + byte_size(data) - byte_size(after_length),
         {:ok, contents, rest} <- contents(after_length, length, content_offset),
         tag =
           Map.merge(tag, %{
             offset: offset,
             contents_offset: content_offset,
             next: content_offset + length
           }),
         :ok <- check_form(tag),
         :ok <- check_contents(tag, contents) do
      {:ok, tag, rest}
    end
  end

  # Identifier octets (X.690 8.1.2).
  defp identifier(<<_class::2, _constructed::1, 31::5, 0x80, _::binary>>, offset),
    do:
      error(
        :non_minimal_tag,
        "X.690 8.1.2.4.2",
        offset + 1,
        "high tag number starts with a 0x80 octet"
      )

  defp identifier(<<class::2, constructed::1, 31::5, rest::binary>>, offset) do
    case high_tag(rest, 0) do
      {:ok, number, _rest} when number < 31 ->
        error(
          :non_minimal_tag,
          "X.690 8.1.2.2",
          offset,
          "tag number #{number} must use the single-octet form"
        )

      {:ok, number, rest} ->
        {:ok, %{class: class, constructed: constructed == 1, number: number}, rest}

      :error ->
        error(
          :truncated,
          "X.690 8.1.2.4",
          offset,
          "high tag number runs past the end of the input"
        )
    end
  end

  defp identifier(<<class::2, constructed::1, number::5, rest::binary>>, _offset),
    do: {:ok, %{class: class, constructed: constructed == 1, number: number}, rest}

  defp identifier(<<>>, offset),
    do: error(:truncated, "X.690 8.1.2", offset, "no identifier octet")

  defp high_tag(<<1::1, bits::7, rest::binary>>, acc), do: high_tag(rest, acc * 128 + bits)
  defp high_tag(<<0::1, bits::7, rest::binary>>, acc), do: {:ok, acc * 128 + bits, rest}
  defp high_tag(<<>>, _acc), do: :error

  # Length octets (X.690 8.1.3, 10.1).
  defp length(<<0x80, _::binary>>, offset),
    do: error(:indefinite_length, "X.690 10.1", offset, "indefinite length is not allowed in DER")

  defp length(<<0xFF, _::binary>>, offset),
    do: error(:invalid_length, "X.690 8.1.3.5", offset, "length octet 0xFF is reserved")

  defp length(<<0::1, length::7, rest::binary>>, _offset), do: {:ok, length, rest}

  defp length(<<1::1, count::7, rest::binary>>, offset) do
    bits = count * 8

    case rest do
      <<0, _::binary>> ->
        error(:non_minimal_length, "X.690 10.1", offset, "length has a leading zero octet")

      <<value::unsigned-size(^bits), _rest::binary>> when value < 128 ->
        error(:non_minimal_length, "X.690 10.1", offset, "long form used for length #{value}")

      <<value::unsigned-size(^bits), rest::binary>> ->
        {:ok, value, rest}

      _ ->
        error(:truncated, "X.690 8.1.3", offset, "length octets run past the end of the input")
    end
  end

  defp length(<<>>, offset), do: error(:truncated, "X.690 8.1.3", offset, "no length octet")

  defp contents(data, length, offset) do
    case data do
      <<contents::binary-size(^length), rest::binary>> ->
        {:ok, contents, rest}

      _ ->
        error(
          :truncated,
          "X.690 8.1.3",
          offset,
          "contents need #{length} byte(s), #{byte_size(data)} left"
        )
    end
  end

  # Primitive or constructed, for universal types (X.690 8.x, 10.2).
  defp check_form(%{class: 0, number: 0} = tag),
    do:
      error(
        :end_of_contents,
        "X.690 10.1",
        tag.offset,
        "end-of-contents octets only follow indefinite lengths"
      )

  defp check_form(%{class: 0, constructed: true, number: number} = tag)
       when number in @primitive_only,
       do:
         error(
           :constructed_form,
           "X.690 10.2",
           tag.offset,
           "#{type_name(number)} must use the primitive form"
         )

  defp check_form(%{class: 0, constructed: false, number: number} = tag)
       when number in [@sequence, @set],
       do:
         error(
           :primitive_form,
           "X.690 8.9.1, 8.11.1",
           tag.offset,
           "#{type_name(number)} must be constructed"
         )

  defp check_form(_tag), do: :ok

  defp check_contents(%{constructed: true} = tag, contents), do: children(tag, contents)

  defp check_contents(%{class: 0, number: @boolean} = tag, contents) do
    case contents do
      <<b>> when b in [0x00, 0xFF] ->
        :ok

      <<_>> ->
        error(:boolean_value, "X.690 11.1", tag.contents_offset, "BOOLEAN TRUE must be 0xFF")

      _ ->
        error(
          :boolean_length,
          "X.690 8.2.1",
          tag.contents_offset,
          "BOOLEAN must have one contents octet"
        )
    end
  end

  defp check_contents(%{class: 0, number: number} = tag, contents)
       when number in [@integer, @enumerated] do
    case contents do
      <<>> ->
        error(
          :empty_integer,
          "X.690 8.3.1",
          tag.contents_offset,
          "#{type_name(number)} has no contents octets"
        )

      <<0x00, 0::1, _::bitstring>> ->
        error(
          :non_minimal_integer,
          "X.690 8.3.2",
          tag.contents_offset,
          "leading 0x00 octet is redundant"
        )

      <<0xFF, 1::1, _::bitstring>> ->
        error(
          :non_minimal_integer,
          "X.690 8.3.2",
          tag.contents_offset,
          "leading 0xFF octet is redundant"
        )

      _ ->
        :ok
    end
  end

  defp check_contents(%{class: 0, number: @bit_string} = tag, contents) do
    case contents do
      <<>> ->
        error(
          :empty_bit_string,
          "X.690 8.6.2",
          tag.contents_offset,
          "BIT STRING has no initial octet"
        )

      <<unused, _::binary>> when unused > 7 ->
        error(
          :bit_string_unused,
          "X.690 8.6.2.2",
          tag.contents_offset,
          "#{unused} unused bits; at most 7"
        )

      <<0>> ->
        :ok

      <<unused>> when unused != 0 ->
        error(
          :bit_string_unused,
          "X.690 8.6.2.3",
          tag.contents_offset,
          "empty BIT STRING must have 0 unused bits"
        )

      <<unused, data::binary>> ->
        last = :binary.last(data)
        mask = Bitwise.bsl(1, unused) - 1

        if Bitwise.band(last, mask) == 0,
          do: :ok,
          else:
            error(:bit_string_padding, "X.690 11.2.1", tag.next - 1, "unused bits must be zero")
    end
  end

  defp check_contents(%{class: 0, number: @null} = tag, contents) do
    if contents == <<>>,
      do: :ok,
      else: error(:null_length, "X.690 8.8.2", tag.contents_offset, "NULL must have no contents")
  end

  defp check_contents(%{class: 0, number: @oid} = tag, contents) do
    cond do
      contents == <<>> ->
        error(
          :empty_oid,
          "X.690 8.19.2",
          tag.contents_offset,
          "OBJECT IDENTIFIER has no contents"
        )

      :binary.last(contents) >= 0x80 ->
        error(
          :truncated_oid,
          "X.690 8.19.2",
          tag.next - 1,
          "last subidentifier is not terminated"
        )

      offset = leading_0x80(contents) ->
        error(
          :non_minimal_oid,
          "X.690 8.19.2",
          tag.contents_offset + offset,
          "subidentifier starts with 0x80"
        )

      true ->
        :ok
    end
  end

  defp check_contents(%{class: 0, number: @utc_time} = tag, contents) do
    if Regex.match?(~r/\A\d{12}Z\z/, contents),
      do: :ok,
      else:
        error(
          :utc_time_format,
          "X.690 11.8",
          tag.contents_offset,
          "UTCTime must be YYMMDDHHMMSSZ, got #{inspect(contents)}"
        )
  end

  defp check_contents(%{class: 0, number: @generalized_time} = tag, contents) do
    cond do
      not Regex.match?(~r/\A\d{14}(\.\d+)?Z\z/, contents) ->
        error(
          :generalized_time_format,
          "X.690 11.7",
          tag.contents_offset,
          "GeneralizedTime must be YYYYMMDDHHMMSS[.f]Z, got #{inspect(contents)}"
        )

      Regex.match?(~r/\.\d*0Z\z/, contents) ->
        error(
          :generalized_time_fraction,
          "X.690 11.7.3",
          tag.contents_offset,
          "fractional seconds must not end in 0"
        )

      true ->
        :ok
    end
  end

  defp check_contents(_tag, _contents), do: :ok

  # The TLVs inside a constructed value; a universal SET's must be sorted.
  defp children(tag, contents) do
    case each_child(contents, tag.contents_offset, []) do
      {:ok, encodings} when tag.class == 0 and tag.number == @set ->
        check_set_order(encodings, tag)

      {:ok, _encodings} ->
        :ok

      error ->
        error
    end
  end

  defp each_child(<<>>, _offset, acc), do: {:ok, Enum.reverse(acc)}

  defp each_child(data, offset, acc) do
    case tlv(data, offset) do
      {:ok, child, rest} ->
        encoding = binary_part(data, 0, byte_size(data) - byte_size(rest))
        each_child(rest, child.next, [{child.offset, encoding} | acc])

      error ->
        error
    end
  end

  # X.690 11.6: SET OF elements in ascending order of their encodings, the
  # shorter padded with zero octets at the end.
  defp check_set_order(encodings, _tag) do
    encodings
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.find(fn [{_, a}, {_, b}] -> compare_padded(a, b) == :gt end)
    |> case do
      nil ->
        :ok

      [_, {offset, _}] ->
        error(:set_of_order, "X.690 11.6", offset, "SET OF elements are not in ascending order")
    end
  end

  defp compare_padded(a, b) do
    size = max(byte_size(a), byte_size(b))
    pad = fn x -> x <> :binary.copy(<<0>>, size - byte_size(x)) end

    cond do
      pad.(a) < pad.(b) -> :lt
      pad.(a) > pad.(b) -> :gt
      true -> :eq
    end
  end

  # Offset of a subidentifier whose first octet is 0x80, if any.
  defp leading_0x80(contents), do: leading_0x80(contents, 0, true)
  defp leading_0x80(<<>>, _offset, _start?), do: nil
  defp leading_0x80(<<0x80, _::binary>>, offset, true), do: offset

  defp leading_0x80(<<byte, rest::binary>>, offset, _start?),
    do: leading_0x80(rest, offset + 1, byte < 0x80)

  defp first_difference(a, b) do
    Enum.zip(:binary.bin_to_list(a), :binary.bin_to_list(b))
    |> Enum.find_index(fn {x, y} -> x != y end)
    |> Kernel.||(min(byte_size(a), byte_size(b)))
  end

  defp type_name(number) do
    %{
      @boolean => "BOOLEAN",
      @integer => "INTEGER",
      @bit_string => "BIT STRING",
      @octet_string => "OCTET STRING",
      @null => "NULL",
      @oid => "OBJECT IDENTIFIER",
      @enumerated => "ENUMERATED",
      @sequence => "SEQUENCE",
      @set => "SET",
      @utc_time => "UTCTime",
      @generalized_time => "GeneralizedTime"
    }
    |> Map.get(number, "universal type #{number}")
  end

  defp error(rule, clause, offset, message),
    do: {:error, %{rule: rule, clause: clause, offset: offset, message: message}}
end
