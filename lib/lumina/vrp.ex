defmodule Lumina.VRP do
  @moduledoc """
  VRP output (#165): the order, the distinct VRPs, and the CSV that
  `lumina vrps` writes.

  A VRP is a `t:Lumina.Validate.vrp/0`: AS, prefix, maxLength, the trust
  anchor's name and the URI of the ROA it comes from (#164). There is no
  RFC for VRP output (`doc/rfc/README.md`); the CSV has the columns and
  value forms of Routinator's CSV output (D-032):

      ASN,IP Prefix,Max Length,Trust Anchor
      AS13335,1.0.0.0/24,24,apnic

  with one row per distinct (AS, prefix, maxLength, trust anchor), however
  many ROAs state it (D-033). IPv6 prefixes are in RFC 5952 form, as
  `Lumina.Resources.format_ip/2` writes them. Lines end in LF.
  """

  alias Lumina.Resources

  @header "ASN,IP Prefix,Max Length,Trust Anchor\n"

  @doc """
  Sorts VRPs: IPv4 first, then by address, prefix length, maxLength, AS,
  trust anchor and URI.
  """
  @spec sort([Lumina.Validate.vrp()]) :: [Lumina.Validate.vrp()]
  def sort(vrps) do
    Enum.sort_by(
      vrps,
      &{if(&1.afi == :ipv4, do: 0, else: 1), &1.address, &1.length, &1.max_length, &1.asn, &1.ta,
       &1.uri}
    )
  end

  @doc """
  One VRP per distinct (AS, prefix, maxLength, trust anchor), the first of
  each in `vrps`' order (D-033).
  """
  @spec distinct([Lumina.Validate.vrp()]) :: [Lumina.Validate.vrp()]
  def distinct(vrps),
    do: Enum.uniq_by(vrps, &Map.take(&1, [:asn, :afi, :address, :length, :max_length, :ta]))

  @doc """
  The CSV of `vrps`, header first, one row per distinct VRP (`distinct/1`)
  in the order given.

  ## Examples

      iex> IO.iodata_to_binary(Lumina.VRP.csv([
      ...>   %{asn: 13335, afi: :ipv4, address: 0x01000000, length: 24, max_length: 24, ta: "apnic", uri: "rsync://a/1.roa"},
      ...>   %{asn: 13335, afi: :ipv4, address: 0x01000000, length: 24, max_length: 24, ta: "apnic", uri: "rsync://a/2.roa"},
      ...>   %{asn: 64496, afi: :ipv6, address: 0x20010DB8000000000000000000000000, length: 32, max_length: 48, ta: "lacnic", uri: "rsync://b/3.roa"}
      ...> ]))
      "ASN,IP Prefix,Max Length,Trust Anchor\\nAS13335,1.0.0.0/24,24,apnic\\nAS64496,2001:db8::/32,48,lacnic\\n"

  """
  @spec csv([Lumina.Validate.vrp()]) :: iolist()
  def csv(vrps) do
    rows =
      for v <- distinct(vrps) do
        [
          "AS#{v.asn},",
          Resources.format_ip({:prefix, v.address, v.length}, v.afi),
          ",#{v.max_length},",
          field(v.ta || ""),
          "\n"
        ]
      end

    [@header | rows]
  end

  # A field holding a comma, a double quote or a line break is quoted, its
  # quotes doubled, as CSV readers expect. Only a trust anchor name, taken
  # from a TAL file name, can hold one.
  defp field(text) do
    if String.contains?(text, [",", "\"", "\n", "\r"]),
      do: ["\"", String.replace(text, "\"", "\"\""), "\""],
      else: text
  end
end
