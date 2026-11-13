defmodule Lumina.Resources do
  @moduledoc """
  Decodes the RFC 3779 resource extensions, IP address blocks (§2) and AS
  identifiers (§3), into data that resource-inclusion checks (M4/M6) can
  use directly.

  Addresses become integers: a prefix is `{:prefix, address, length}` and a
  range is `{:range, min, max}` with both ends inclusive. The bit strings
  are expanded as §2.1.2 and §2.2.3.9 define: a prefix and a range minimum
  are padded with zero bits, and a range maximum with one bits.

      %{afi: :ipv4, safi: nil, resources: [{:prefix, 167772160, 8}]}
      %{afi: :ipv6, safi: nil, resources: :inherit}

  AS identifiers become `%{asnum: ..., rdi: ...}`, where each value is `nil`
  (absent), `:inherit`, or a list of `{:id, n}` and `{:range, min, max}`.

  Decoding is structural. The canonical-form rules (sorting, no overlap,
  combining adjacent blocks, minimal encodings) are reported by
  `ip_issues/1` and `as_issues/1`, not enforced, because rejecting
  certificates for them belongs to validation (M4/M6).
  """

  import Bitwise

  @type afi :: :ipv4 | :ipv6 | {:unknown, non_neg_integer()}
  @type ip_resource ::
          {:prefix, non_neg_integer(), non_neg_integer()}
          | {:range, non_neg_integer(), non_neg_integer()}
          | {:raw_prefix, bitstring()}
          | {:raw_range, bitstring(), bitstring()}
  @type ip_family :: %{
          afi: afi(),
          safi: non_neg_integer() | nil,
          resources: :inherit | [ip_resource()],
          encoded: :inherit | [term()]
        }
  @type as_resources ::
          nil
          | :inherit
          | [{:id, non_neg_integer()} | {:range, non_neg_integer(), non_neg_integer()}]
  @type issue :: %{rule: atom(), rfc: String.t(), message: String.t()}

  @widths %{ipv4: 32, ipv6: 128}

  @doc """
  Decodes the DER of an `IPAddrBlocks` value (the contents of the
  id-pe-ipAddrBlocks extension's extnValue).
  """
  @spec decode_ip(binary()) :: {:ok, [ip_family()]} | {:error, term()}
  def decode_ip(der) do
    with {:ok, families} <- Lumina.ASN1.decode(:resources, :IPAddrBlocks, der) do
      families
      |> Enum.map(&ip_family/1)
      |> collect()
    end
  end

  @doc """
  Decodes the DER of an `ASIdentifiers` value (the contents of the
  id-pe-autonomousSysIds extension's extnValue).
  """
  @spec decode_as(binary()) ::
          {:ok, %{asnum: as_resources(), rdi: as_resources()}} | {:error, term()}
  def decode_as(der) do
    with {:ok, ids} <- Lumina.ASN1.decode(:resources, :ASIdentifiers, der) do
      {:ok, %{asnum: as_choice(Map.get(ids, :asnum)), rdi: as_choice(Map.get(ids, :rdi))}}
    end
  end

  defp ip_family(%{addressFamily: family, ipAddressChoice: choice}) do
    with {:ok, afi, safi} <- address_family(family),
         {:ok, resources, encoded} <- ip_choice(choice, afi) do
      {:ok, %{afi: afi, safi: safi, resources: resources, encoded: encoded}}
    end
  end

  # RFC 3779 §2.2.3.3: a two-octet AFI, optionally followed by a SAFI octet.
  defp address_family(<<afi::16>>), do: {:ok, afi_name(afi), nil}
  defp address_family(<<afi::16, safi>>), do: {:ok, afi_name(afi), safi}
  defp address_family(other), do: {:error, {:invalid_address_family, other}}

  defp afi_name(1), do: :ipv4
  defp afi_name(2), do: :ipv6
  defp afi_name(n), do: {:unknown, n}

  defp ip_choice({:inherit, :NULL}, _afi), do: {:ok, :inherit, :inherit}

  defp ip_choice({:addressesOrRanges, entries}, afi) do
    with {:ok, resources} <- entries |> Enum.map(&ip_entry(&1, afi)) |> collect() do
      {:ok, resources, entries}
    end
  end

  # Unknown AFI: the address width is unknown, so keep the bit strings.
  defp ip_entry({:addressPrefix, bits}, {:unknown, _}), do: {:ok, {:raw_prefix, bits}}

  defp ip_entry({:addressRange, %{min: min, max: max}}, {:unknown, _}),
    do: {:ok, {:raw_range, min, max}}

  defp ip_entry({:addressPrefix, bits}, afi), do: prefix(bits, afi)

  defp ip_entry({:addressRange, %{min: min, max: max}}, afi) do
    width = @widths[afi]

    if bit_size(min) <= width and bit_size(max) <= width,
      do: {:ok, {:range, pad(min, width, 0), pad(max, width, 1)}},
      else: {:error, {:range_too_long, afi, bit_size(min), bit_size(max)}}
  end

  # Expands a bit string to `width` bits, filling with `fill` (0 or 1), as
  # an integer.
  defp pad(bits, width, fill) do
    n = bit_size(bits)
    <<value::size(^n)>> = bits
    missing = width - n
    value <<< missing ||| if(fill == 1, do: (1 <<< missing) - 1, else: 0)
  end

  defp as_choice(nil), do: nil
  defp as_choice({:inherit, :NULL}), do: :inherit

  defp as_choice({:asIdsOrRanges, entries}) do
    Enum.map(entries, fn
      {:id, id} -> {:id, id}
      {:range, %{min: min, max: max}} -> {:range, min, max}
    end)
  end

  defp collect(results) do
    Enum.reduce_while(results, {:ok, []}, fn
      {:ok, value}, {:ok, acc} -> {:cont, {:ok, acc ++ [value]}}
      {:error, _} = error, _ -> {:halt, error}
    end)
  end

  @doc """
  Converts a prefix BIT STRING (RFC 3779 §2.1.1, also used by ROAs, RFC 9582
  §4.3.2.1) into `{:prefix, address, length}`.

  ## Examples

      iex> Lumina.Resources.prefix(<<10, 5, 0::7>>, :ipv4)
      {:ok, {:prefix, 0x0A050000, 23}}

      iex> Lumina.Resources.prefix(<<1, 2, 3, 4, 5>>, :ipv4)
      {:error, {:prefix_too_long, :ipv4, 40}}

  """
  @spec prefix(bitstring(), :ipv4 | :ipv6) :: {:ok, ip_resource()} | {:error, term()}
  def prefix(bits, afi) do
    width = @widths[afi]

    if bit_size(bits) <= width,
      do: {:ok, {:prefix, pad(bits, width, 0), bit_size(bits)}},
      else: {:error, {:prefix_too_long, afi, bit_size(bits)}}
  end

  @doc "The address width of a family: 32 or 128."
  @spec width(:ipv4 | :ipv6) :: 32 | 128
  def width(afi), do: @widths[afi]

  @doc """
  The lowest and highest address a resource covers, as integers.

  ## Examples

      iex> Lumina.Resources.bounds({:prefix, 0x0A000000, 8}, :ipv4)
      {0x0A000000, 0x0AFFFFFF}

  """
  @spec bounds(ip_resource(), :ipv4 | :ipv6) :: {non_neg_integer(), non_neg_integer()}
  def bounds({:prefix, address, length}, afi),
    do: {address, address ||| (1 <<< (@widths[afi] - length)) - 1}

  def bounds({:range, min, max}, _afi), do: {min, max}

  @doc """
  Checks the canonical-form rules of RFC 3779 §2.2.3 on decoded IP address
  blocks and returns every violation found, or `[]`.
  """
  @spec ip_issues([ip_family()]) :: [issue()]
  def ip_issues(families) do
    family_order(families) ++ Enum.flat_map(families, &family_issues/1)
  end

  # §2.2.3.3: ascending addressFamily, unique, no-SAFI before SAFI.
  defp family_order(families) do
    keys = Enum.map(families, &family_key/1)

    cond do
      length(Enum.uniq(keys)) != length(keys) ->
        [
          issue(
            :duplicate_family,
            "3779#2.2.3.3",
            "more than one IPAddressFamily for the same AFI/SAFI"
          )
        ]

      keys != Enum.sort(keys) ->
        [
          issue(
            :family_order,
            "3779#2.2.3.3",
            "IPAddressFamily entries are not in ascending order"
          )
        ]

      true ->
        []
    end
  end

  # The addressFamily octets, compared as unsigned octets; a shorter
  # (SAFI-less) value sorts first.
  defp family_key(%{afi: afi, safi: safi}) do
    n =
      case afi do
        :ipv4 -> 1
        :ipv6 -> 2
        {:unknown, n} -> n
      end

    if safi, do: <<n::16, safi>>, else: <<n::16>>
  end

  defp family_issues(%{resources: :inherit}), do: []
  defp family_issues(%{afi: {:unknown, _}}), do: []

  defp family_issues(%{afi: afi, resources: resources, encoded: encoded}) do
    name = format_family(afi)

    encoding =
      encoded
      |> Enum.zip(resources)
      |> Enum.flat_map(fn {raw, resource} -> encoding_issues(raw, resource, afi, name) end)

    blocks = Enum.map(resources, &bounds(&1, afi))

    order =
      if blocks == Enum.sort(blocks),
        do: [],
        else: [
          issue(:block_order, "3779#2.2.3.6", "#{name} blocks are not sorted by lowest address")
        ]

    pairs =
      blocks
      |> Enum.sort()
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.flat_map(fn [{_, max1} = a, {min2, _} = b] ->
        cond do
          min2 <= max1 ->
            [
              issue(
                :overlap,
                "3779#2.2.3.6",
                "#{name} blocks #{format_bounds(a, afi)} and #{format_bounds(b, afi)} overlap"
              )
            ]

          min2 == max1 + 1 ->
            [
              issue(
                :adjacent,
                "3779#2.2.3.6",
                "#{name} blocks #{format_bounds(a, afi)} and #{format_bounds(b, afi)} are contiguous and must be combined"
              )
            ]

          true ->
            []
        end
      end)

    encoding ++ order ++ pairs
  end

  defp encoding_issues({:addressPrefix, _}, _resource, _afi, _name), do: []

  defp encoding_issues(
         {:addressRange, %{min: min_bits, max: max_bits}},
         {:range, min, max} = range,
         afi,
         name
       ) do
    shown = format_bounds({min, max}, afi)

    [
      if(ends_with?(min_bits, 0),
        do:
          issue(
            :range_min_not_minimal,
            "3779#2.2.3.9",
            "#{name} range #{shown}: min keeps trailing zero bits"
          )
      ),
      if(ends_with?(max_bits, 1),
        do:
          issue(
            :range_max_not_minimal,
            "3779#2.2.3.9",
            "#{name} range #{shown}: max keeps trailing one bits"
          )
      ),
      if(min > max,
        do: issue(:range_inverted, "3779#2.2.3.9", "#{name} range #{shown}: min is above max")
      ),
      if(min <= max and prefix_shaped?(range, afi),
        do:
          issue(
            :range_is_prefix,
            "3779#2.2.3.7",
            "#{name} range #{shown} must be encoded as a prefix"
          )
      )
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp ends_with?(bits, bit) do
    n = bit_size(bits)
    n > 0 and match?(<<_::size(^n - 1), ^bit::1>>, bits)
  end

  # §2.2.3.7: a range whose ends differ only in a block of trailing bits
  # that are all zero in min and all one in max is a prefix.
  defp prefix_shaped?({:range, min, max}, afi) do
    width = @widths[afi]

    Enum.any?(0..width, fn length ->
      bounds({:prefix, min, length}, afi) == {min, max} and
        (min &&& (1 <<< (width - length)) - 1) == 0
    end)
  end

  @doc """
  Checks the rules of RFC 3779 §3.2.3 on decoded AS identifiers and returns
  every violation found, or `[]`. Equal range ends are reported per
  erratum 7653 (held for document update).
  """
  @spec as_issues(%{asnum: as_resources(), rdi: as_resources()}) :: [issue()]
  def as_issues(%{asnum: asnum, rdi: rdi}),
    do: as_list_issues(asnum, "asnum") ++ as_list_issues(rdi, "rdi")

  defp as_list_issues(list, name) when is_list(list) do
    blocks =
      Enum.map(list, fn
        {:id, id} -> {id, id}
        {:range, min, max} -> {min, max}
      end)

    ranges =
      Enum.flat_map(list, fn
        {:range, min, max} when min > max ->
          [
            issue(
              :range_inverted,
              "3779#3.2.3.8",
              "#{name} range #{min}-#{max}: min is above max"
            )
          ]

        {:range, id, id} ->
          [
            issue(
              :range_single,
              "3779#3.2.3.8",
              "#{name} range #{id}-#{id} has equal ends; use an id (erratum 7653)"
            )
          ]

        _ ->
          []
      end)

    order =
      if blocks == Enum.sort(blocks),
        do: [],
        else: [
          issue(
            :id_order,
            "3779#3.2.3.4",
            "#{name} identifiers are not sorted by increasing value"
          )
        ]

    pairs =
      blocks
      |> Enum.sort()
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.flat_map(fn [{_, max1}, {min2, _}] ->
        cond do
          min2 <= max1 ->
            [issue(:overlap, "3779#3.2.3.4", "#{name} identifiers overlap at #{min2}")]

          min2 == max1 + 1 ->
            [
              issue(
                :adjacent,
                "3779#3.2.3.4",
                "#{name} identifiers #{max1} and #{min2} are contiguous and must be combined"
              )
            ]

          true ->
            []
        end
      end)

    ranges ++ order ++ pairs
  end

  defp as_list_issues(_absent_or_inherit, _name), do: []

  @doc """
  Formats an IP resource in the usual notation.

  ## Examples

      iex> Lumina.Resources.format_ip({:prefix, 0x0A002000, 20}, :ipv4)
      "10.0.32.0/20"

      iex> Lumina.Resources.format_ip({:prefix, 0x20010000000200000000000000000000, 48}, :ipv6)
      "2001:0:2::/48"

      iex> Lumina.Resources.format_ip({:range, 0x0A023000, 0x0A0240FF}, :ipv4)
      "10.2.48.0-10.2.64.255"

  """
  @spec format_ip(ip_resource(), :ipv4 | :ipv6) :: String.t()
  def format_ip({:prefix, address, length}, afi), do: "#{format_address(address, afi)}/#{length}"
  def format_ip({:range, min, max}, afi), do: format_bounds({min, max}, afi)

  @doc """
  Formats AS resources: `AS135`, `AS3000-AS3999`.

  ## Examples

      iex> Lumina.Resources.format_as({:range, 3000, 3999})
      "AS3000-AS3999"

  """
  @spec format_as({:id, non_neg_integer()} | {:range, non_neg_integer(), non_neg_integer()}) ::
          String.t()
  def format_as({:id, id}), do: "AS#{id}"
  def format_as({:range, min, max}), do: "AS#{min}-AS#{max}"

  defp format_bounds({min, max}, afi),
    do: "#{format_address(min, afi)}-#{format_address(max, afi)}"

  defp format_address(address, :ipv4),
    do: <<address::32>> |> :binary.bin_to_list() |> List.to_tuple() |> :inet.ntoa() |> to_string()

  defp format_address(address, :ipv6) do
    words = for <<(word::16 <- <<address::128>>)>>, do: word
    words |> List.to_tuple() |> :inet.ntoa() |> to_string()
  end

  defp format_family(:ipv4), do: "IPv4"
  defp format_family(:ipv6), do: "IPv6"

  defp issue(rule, rfc, message), do: %{rule: rule, rfc: rfc, message: message}
end
