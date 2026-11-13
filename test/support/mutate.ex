defmodule Lumina.Test.Mutate do
  @moduledoc """
  Turns valid DER objects into minimally broken ones, for testing that
  decoding rejects non-DER input. Barry always writes DER, so these
  variants are built by hand from real fixture objects. Each mutation
  breaks exactly one rule and keeps everything else intact.

  Each function returns `{:ok, mutated}`, or `:not_applicable` when the
  object has nothing to mutate.
  """

  @doc """
  The mutations, with the rule each breaks and the X.690 clause:
  `{name, function, expected Lumina.DER rule}`.
  """
  def all do
    [
      # X.690 8.1.1 / F-010: data after the encoding.
      {:trailing_byte, &trailing_byte/1, :trailing_bytes},
      # X.690 10.1: DER forbids the indefinite length form.
      {:indefinite_length, &indefinite_length/1, :indefinite_length},
      # X.690 10.1: lengths use the minimum number of octets.
      {:non_minimal_length, &non_minimal_length/1, :non_minimal_length},
      # X.690 11.1: BOOLEAN TRUE is 0xFF.
      {:boolean_true_as_01, &boolean_true_as_01/1, :boolean_value},
      # X.690 11.6: SET OF in ascending order. signedAttrs is an [0]
      # IMPLICIT SET OF, so only re-encoding sees it (Lumina.DER.check_canonical).
      {:unsorted_signed_attrs, &unsorted_signed_attrs/1, :not_canonical}
    ]
  end

  @doc "Appends one zero byte."
  def trailing_byte(der), do: {:ok, der <> <<0>>}

  @doc "Re-encodes the outermost SEQUENCE with an indefinite length and end-of-contents octets."
  def indefinite_length(der) do
    with {:ok, contents} <- outer_contents(der), do: {:ok, <<0x30, 0x80>> <> contents <> <<0, 0>>}
  end

  @doc "Adds a redundant leading zero octet to the outermost length."
  def non_minimal_length(<<0x30, 0x81, n, rest::binary>>),
    do: {:ok, <<0x30, 0x82, 0, n, rest::binary>>}

  def non_minimal_length(<<0x30, 0x82, n::16, rest::binary>>),
    do: {:ok, <<0x30, 0x83, 0, n::16, rest::binary>>}

  def non_minimal_length(_der), do: :not_applicable

  @doc "Changes the first BOOLEAN TRUE (01 01 FF), for example an extension's critical flag, to 01 01 01."
  def boolean_true_as_01(der) do
    case :binary.match(der, <<1, 1, 0xFF>>) do
      {at, 3} ->
        {:ok,
         binary_part(der, 0, at) <>
           <<1, 1, 1>> <> binary_part(der, at + 3, byte_size(der) - at - 3)}

      :nomatch ->
        :not_applicable
    end
  end

  @doc """
  Reverses the order of a signed object's signed attributes in place. The
  size doesn't change, so every enclosing length stays valid.
  """
  def unsorted_signed_attrs(der) do
    with {:ok, %Lumina.SignedObject{signers: [%{signed_attrs_der: <<0x31, rest::binary>>} | _]}} <-
           Lumina.SignedObject.decode(der),
         {:ok, [_, _ | _] = attrs} <- Lumina.DER.children(<<0x31, rest::binary>>) do
      original = <<0xA0, rest::binary>>

      header =
        binary_part(original, 0, byte_size(original) - Enum.sum(Enum.map(attrs, &byte_size/1)))

      {:ok, :binary.replace(der, original, header <> Enum.join(Enum.reverse(attrs)))}
    else
      _ -> :not_applicable
    end
  end

  defp outer_contents(<<0x30, 0x81, n, contents::binary-size(n)>>), do: {:ok, contents}
  defp outer_contents(<<0x30, 0x82, n::16, contents::binary-size(n)>>), do: {:ok, contents}
  defp outer_contents(_der), do: :not_applicable
end
