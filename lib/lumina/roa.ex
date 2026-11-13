defmodule Lumina.ROA do
  @moduledoc """
  Decodes Route Origin Authorizations (RFC 9582): the `RouteOriginAttestation`
  eContent of a signed object.

  A ROA is `%Lumina.ROA{version:, as_id:, families:}`, where each family is
  `%{afi: :ipv4 | :ipv6, addresses: [%{prefix: {:prefix, address, length},
  max_length: integer | nil}]}`. `object` holds the decoded envelope
  (`Lumina.SignedObject`) when the ROA came from a full signed object.

  Decoding is structural. The version, maxLength bounds, containment in the
  EE certificate's resources and the other RFC 9582 §4 and §5 rules are
  checked in M7. The canonical-form recommendations of RFC 9582 §4.3.3, and
  the other encoding rules of §4.3, are reported by `issues/1`, not
  enforced: the RFC makes them SHOULDs and expects RPs to grow stricter
  over time (F-018 in doc/rfc-findings.md).

  Some rules fail at decoding, because RFC 9582's ASN.1 module expresses
  them as constraints (F-012): address families other than IPv4 and IPv6,
  and a prefix or maxLength longer than the family's address width (32 or
  128). A maxLength below the prefix length decodes and is reported by
  `issues/1`.
  """

  alias Lumina.{DER, Resources, SignedObject}

  defstruct [:object, :version, :as_id, :families]

  @type address :: %{prefix: Resources.ip_resource(), max_length: non_neg_integer() | nil}
  @type family :: %{afi: :ipv4 | :ipv6, addresses: [address()]}
  @type t :: %__MODULE__{
          object: SignedObject.t() | nil,
          version: non_neg_integer(),
          as_id: non_neg_integer(),
          families: [family()]
        }
  @type vrp :: %{
          asn: non_neg_integer(),
          afi: :ipv4 | :ipv6,
          address: non_neg_integer(),
          length: non_neg_integer(),
          max_length: non_neg_integer()
        }

  @doc """
  Decodes a complete ROA signed object (CMS envelope plus eContent).
  Returns `{:error, {:not_roa, content_type}}` if the object holds
  something else.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, term()}
  def decode(der) do
    with {:ok, object} <- SignedObject.decode(der), do: from_signed_object(object)
  end

  @doc "Decodes the ROA eContent of an already decoded signed object."
  @spec from_signed_object(SignedObject.t()) :: {:ok, t()} | {:error, term()}
  def from_signed_object(%SignedObject{} = object) do
    case SignedObject.content_type(object) do
      :roa ->
        with {:ok, value} <- SignedObject.decode_econtent(object),
             {:ok, roa} <- from_asn1(value),
             do: {:ok, %{roa | object: object}}

      other ->
        {:error, {:not_roa, other}}
    end
  end

  @doc """
  Decodes a bare `RouteOriginAttestation` eContent (no envelope), for
  example the payload in RFC 9582 Appendix A.
  """
  @spec decode_econtent(binary()) :: {:ok, t()} | {:error, term()}
  def decode_econtent(der) do
    with :ok <- der_check(DER.check(der)),
         {:ok, value} <- Lumina.ASN1.decode(:roa, :RouteOriginAttestation, der),
         :ok <- der_check(DER.check_canonical(:roa, :RouteOriginAttestation, der)),
         do: from_asn1(value)
  end

  defp from_asn1(value) do
    with {:ok, families} <- value.ipAddrBlocks |> Enum.map(&family/1) |> collect() do
      {:ok,
       %__MODULE__{version: Map.get(value, :version, 0), as_id: value.asID, families: families}}
    end
  end

  defp family(%{addressFamily: afi_octets, addresses: addresses}) do
    with {:ok, afi} <- afi(afi_octets),
         {:ok, list} <- addresses |> Enum.map(&address(&1, afi)) |> collect() do
      {:ok, %{afi: afi, addresses: list}}
    end
  end

  defp afi(<<0, 1>>), do: {:ok, :ipv4}
  defp afi(<<0, 2>>), do: {:ok, :ipv6}
  defp afi(other), do: {:error, {:invalid_address_family, other}}

  defp address(%{address: bits} = entry, afi) do
    with {:ok, prefix} <- Resources.prefix(bits, afi) do
      {:ok, %{prefix: prefix, max_length: Map.get(entry, :maxLength)}}
    end
  end

  @doc """
  The VRPs the ROA asserts, one per address: the AS, the prefix, and the
  maximum length, which is the prefix length when maxLength is absent
  (RFC 9582 §4.3.2.2). The ROA's validity is not checked here.
  """
  @spec vrps(t()) :: [vrp()]
  def vrps(%__MODULE__{as_id: asn, families: families}) do
    for %{afi: afi, addresses: addresses} <- families,
        %{prefix: {:prefix, address, length}, max_length: max} <- addresses do
      %{asn: asn, afi: afi, address: address, length: length, max_length: max || length}
    end
  end

  @doc """
  Formats a VRP as `prefix-maxLength => ASn` (the `-maxLength` part only
  when it differs from the prefix length).

  ## Examples

      iex> Lumina.ROA.format_vrp(%{asn: 64496, afi: :ipv4, address: 0x01010000, length: 16, max_length: 24})
      "1.1.0.0/16-24 => AS64496"

  """
  @spec format_vrp(vrp()) :: String.t()
  def format_vrp(%{asn: asn, afi: afi, address: address, length: length, max_length: max}) do
    prefix = Resources.format_ip({:prefix, address, length}, afi)
    "#{prefix}#{if max != length, do: "-#{max}"} => AS#{asn}"
  end

  @doc """
  Reports encodings that RFC 9582 §4.3 forbids or discourages, without
  rejecting the ROA. Returns `[]` for a ROA in canonical form.

  MUSTs: one ROAIPAddressFamily per AFI (§4.3.1), no IPv4-mapped IPv6
  prefixes (§4.3.1), maxLength within [prefix length, address width]
  (§4.3.2.2). SHOULDs: no superfluous maxLength (§4.3.2.2), elements
  sorted and unique (§4.3.3).
  """
  @spec issues(t()) :: [%{rule: atom(), rfc: String.t(), message: String.t()}]
  def issues(%__MODULE__{families: families} = roa) do
    afis = Enum.map(families, & &1.afi)

    duplicate_families =
      if length(Enum.uniq(afis)) != length(afis),
        do: [
          issue(
            :duplicate_family,
            "9582#4.3.1",
            "more than one ROAIPAddressFamily for the same AFI"
          )
        ],
        else: []

    per_address =
      for %{afi: afi, addresses: addresses} <- families,
          %{prefix: {:prefix, address, length} = prefix, max_length: max} <- addresses,
          issue <- address_issues(afi, address, length, max, Resources.format_ip(prefix, afi)),
          do: issue

    duplicate_families ++ per_address ++ order_issues(roa)
  end

  defp address_issues(afi, address, length, max, shown) do
    width = Resources.width(afi)

    [
      if(afi == :ipv6 and length >= 96 and Bitwise.bsr(address, 32) == 0xFFFF,
        do: issue(:ipv4_mapped, "9582#4.3.1", "#{shown} is an IPv4-mapped IPv6 prefix")
      ),
      if(max != nil and (max < length or max > width),
        do:
          issue(
            :max_length_out_of_range,
            "9582#4.3.2.2",
            "#{shown}: maxLength #{max} is outside #{length}..#{width}"
          )
      ),
      if(max != nil and max == length,
        do:
          issue(
            :superfluous_max_length,
            "9582#4.3.2.2",
            "#{shown}: maxLength equals the prefix length"
          )
      )
    ]
    |> Enum.reject(&is_nil/1)
  end

  # §4.3.3: the (afi, addr, plen, mlen) tuples must be ascending and unique.
  defp order_issues(%__MODULE__{families: families}) do
    keys =
      for %{afi: afi, addresses: addresses} <- families,
          %{prefix: {:prefix, address, length}, max_length: max} <- addresses do
        {if(afi == :ipv4, do: 1, else: 2), address, length, max || length}
      end

    cond do
      length(Enum.uniq(keys)) != length(keys) ->
        [issue(:duplicate_address, "9582#4.3.3.1", "ipAddrBlocks holds duplicate elements")]

      keys != Enum.sort(keys) ->
        [
          issue(
            :not_canonical_order,
            "9582#4.3.3.1",
            "ipAddrBlocks is not in canonical (sorted) order"
          )
        ]

      true ->
        []
    end
  end

  defp issue(rule, rfc, message), do: %{rule: rule, rfc: rfc, message: message}

  defp der_check(:ok), do: :ok
  defp der_check({:error, %{rule: _} = error}), do: {:error, {:der, error}}
  defp der_check({:error, _} = error), do: error

  defp collect(results) do
    Enum.reduce_while(results, {:ok, []}, fn
      {:ok, value}, {:ok, acc} -> {:cont, {:ok, acc ++ [value]}}
      {:error, _} = error, _ -> {:halt, error}
    end)
  end
end
