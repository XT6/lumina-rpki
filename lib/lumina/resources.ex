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

  `effective/2` gives a certificate's effective resources, with `inherit`
  resolved from its issuer's (RFC 3779 §2.2.3.5, §3.2.3.3; #153).

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
  @type as_resource :: {:id, non_neg_integer()} | {:range, non_neg_integer(), non_neg_integer()}
  @type issue :: %{rule: atom(), rfc: String.t(), message: String.t()}

  @typedoc """
  The resources a certificate holds, `inherit` resolved: IPv4 and IPv6
  prefixes and ranges, and AS numbers (`asnum`). An empty list holds
  nothing of that kind.
  """
  @type effective :: %{ipv4: [ip_resource()], ipv6: [ip_resource()], as: [as_resource()]}

  @widths %{ipv4: 32, ipv6: 128}

  @doc """
  The effective resources of `cert`, given its issuer's (`nil` for a TA).

  RFC 3779 §2.2.3.5 (per address family) and §3.2.3.3 (AS numbers): with
  `inherit`, the set "is taken from the issuer's certificate, or from the
  issuer's issuer's certificate, recursively, until a certificate
  containing [explicit resources] is located". Effective resources are
  built top-down from the TA, so an inherited kind takes the issuer's
  effective set and the recursion is one step per certificate.

  A kind the certificate doesn't list is empty, and so is an inherited
  kind the issuer holds none of (D-026): the certificate holds nothing of
  it. RFC 9286 §5.1 requires a manifest's EE certificate to inherit its
  resources, every kind, so under a CA without IPv6, say, the manifest
  inherits IPv6 from nothing. A TA can't inherit (RFC 8630 §2.3, checked
  with its TAL); there `inherit` resolves to nothing too. Address
  families with an unknown AFI, and RDIs, aren't resources a certificate
  can hold in the RPKI (RFC 6487 §4.8.10, §4.8.11; the profile rejects
  them) and are left out.
  """
  @spec effective(Lumina.Certificate.t(), effective() | nil) :: effective()
  def effective(%Lumina.Certificate{} = cert, issuer) do
    ip = Lumina.Certificate.extension_value(cert, :ip_resources)
    as = Lumina.Certificate.extension_value(cert, :as_resources)

    %{
      ipv4: resolve(ip_choice_of(ip, :ipv4), issuer, :ipv4),
      ipv6: resolve(ip_choice_of(ip, :ipv6), issuer, :ipv6),
      as: resolve(as_choice_of(as), issuer, :as)
    }
  end

  # The explicit list, :inherit or nil (not present) for one family. A
  # family listed twice is a profile problem; its lists are joined.
  defp ip_choice_of(families, afi) when is_list(families) do
    case for(%{afi: ^afi, resources: r} <- families, do: r) do
      [] -> nil
      choices -> if :inherit in choices, do: :inherit, else: Enum.concat(choices)
    end
  end

  defp ip_choice_of(_absent_or_malformed, _afi), do: nil

  defp as_choice_of(%{asnum: asnum}), do: asnum
  defp as_choice_of(_absent_or_malformed), do: nil

  defp resolve(nil, _issuer, _kind), do: []
  defp resolve(:inherit, nil, _kind), do: []
  defp resolve(:inherit, issuer, kind), do: Map.fetch!(issuer, kind)
  defp resolve(list, _issuer, _kind) when is_list(list), do: list

  @typedoc """
  One kind of resources as a set: sorted, inclusive integer intervals
  that neither overlap nor touch.
  """
  @type intervals :: [{non_neg_integer(), non_neg_integer()}]

  @doc """
  The resources of one kind (`:ipv4`, `:ipv6` or `:as`) as a set of
  intervals: prefixes, ranges and AS ids become intervals, and
  overlapping or adjacent ones merge. A range whose min is above its max
  covers nothing (the profile rejects it, RFC 3779 §2.2.3.9, §3.2.3.8).

  ## Examples

      iex> Lumina.Resources.intervals([{:prefix, 0x0A000000, 8}, {:range, 0x0B000000, 0x0B0000FF}], :ipv4)
      [{0x0A000000, 0x0B0000FF}]

      iex> Lumina.Resources.intervals([{:id, 7}, {:range, 1, 5}, {:id, 6}], :as)
      [{1, 7}]

  """
  @spec intervals([ip_resource()] | [as_resource()], :ipv4 | :ipv6 | :as) :: intervals()
  def intervals(resources, kind) do
    resources
    |> Enum.map(&interval(&1, kind))
    |> Enum.reject(fn {min, max} -> min > max end)
    |> Enum.sort()
    |> merge([])
  end

  defp interval({:id, id}, :as), do: {id, id}
  defp interval({:range, min, max}, :as), do: {min, max}
  defp interval(resource, afi), do: bounds(resource, afi)

  defp merge([], acc), do: Enum.reverse(acc)

  defp merge([{min, max} | rest], [{lo, hi} | acc]) when min <= hi + 1,
    do: merge(rest, [{lo, max(hi, max)} | acc])

  defp merge([interval | rest], acc), do: merge(rest, [interval | acc])

  @doc """
  Whether `x` encompasses `y` (RFC 6487 §7.1; "subsumed by" in RFC 3779
  §2.3 and §3.3): every IPv4 address, IPv6 address and AS number `y`
  holds, `x` holds too. Both are `t:effective/0` sets.

  The kinds are compared separately (erratum 5188 to RFC 6487 §7.1), and
  as sets (D-027): a range of `y` spanning two adjacent ranges of `x` is
  encompassed, although §7.1 read literally wants a single range of `x`
  to cover it (F-034). The empty set is encompassed by anything.
  """
  @spec encompasses?(effective(), effective()) :: boolean()
  def encompasses?(x, y), do: outside(y, x) == %{ipv4: [], ipv6: [], as: []}

  @doc """
  The part of `y` that `x` doesn't hold, per kind, as resources that
  `format/2` shows: a prefix wherever an interval is one, else a range
  (an id for a single AS number). Empty lists when `x` encompasses `y`.

  ## Examples

      iex> Lumina.Resources.outside(
      ...>   %{ipv4: [{:prefix, 0x0A000000, 8}], ipv6: [], as: [{:range, 64496, 64511}]},
      ...>   %{ipv4: [{:prefix, 0x0A000000, 9}], ipv6: [], as: [{:range, 64496, 64510}]}
      ...> )
      %{ipv4: [{:prefix, 0x0A800000, 9}], ipv6: [], as: [{:id, 64511}]}

  """
  @spec outside(effective(), effective()) :: effective()
  def outside(y, x) do
    Map.new([:ipv4, :ipv6, :as], fn kind ->
      left =
        subtract(intervals(Map.get(y, kind, []), kind), intervals(Map.get(x, kind, []), kind))

      {kind, Enum.map(left, &resource(&1, kind))}
    end)
  end

  # Set difference of two interval sets, both sorted and merged.
  defp subtract([], _x), do: []
  defp subtract(y, []), do: y

  defp subtract([{ymin, ymax} | yrest] = y, [{xmin, xmax} | xrest] = x) do
    cond do
      xmax < ymin -> subtract(y, xrest)
      xmin > ymax -> [{ymin, ymax} | subtract(yrest, x)]
      xmin > ymin -> [{ymin, xmin - 1} | subtract([{xmin, ymax} | yrest], x)]
      xmax >= ymax -> subtract(yrest, x)
      true -> subtract([{xmax + 1, ymax} | yrest], xrest)
    end
  end

  defp resource({id, id}, :as), do: {:id, id}
  defp resource({min, max}, :as), do: {:range, min, max}

  defp resource({min, max}, afi) do
    size = max - min + 1

    if (size &&& size - 1) == 0 and (min &&& size - 1) == 0,
      do: {:prefix, min, @widths[afi] - length(Integer.digits(size, 2)) + 1},
      else: {:range, min, max}
  end

  @doc """
  Formats a resource of the given kind with `format_ip/2` or
  `format_as/1`.

  ## Examples

      iex> Lumina.Resources.format({:prefix, 0x0A000000, 8}, :ipv4)
      "10.0.0.0/8"

      iex> Lumina.Resources.format({:id, 64496}, :as)
      "AS64496"

  """
  @spec format(ip_resource() | as_resource(), :ipv4 | :ipv6 | :as) :: String.t()
  def format(resource, :as), do: format_as(resource)
  def format(resource, afi), do: format_ip(resource, afi)

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
