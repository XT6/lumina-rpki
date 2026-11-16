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
  many ROAs state it (D-033). The wide form (`lumina vrps --wide`, #166),
  for debugging, adds the rsync URI of the ROA and has one row per VRP
  and ROA, so duplicates show:

      ASN,IP Prefix,Max Length,Trust Anchor,URI
      AS13335,1.0.0.0/24,24,apnic,rsync://example.net/repo/a.roa

  IPv6 prefixes are in RFC 5952 form, as `Lumina.Resources.format_ip/2`
  writes them. Lines end in LF.

  JSON (`lumina vrps --format json`, #167) is Lumina's own format
  (D-032), RFC 8259, described in `doc/output.md`: an object with
  `metadata` and `roas`, the same rows as the CSV in the same order.
  """

  alias Lumina.Resources

  @header "ASN,IP Prefix,Max Length,Trust Anchor"
  @version Mix.Project.config()[:version]

  @typedoc """
  What `json/3` says about the run: when the output was made, the time
  validated at, and each TAL's trust anchor name, file and outcome.
  """
  @type metadata :: %{
          generated: DateTime.t(),
          now: DateTime.t(),
          trust_anchors: [%{name: String.t(), tal: String.t(), status: String.t()}]
        }

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
  in the order given. With `wide: true`, a URI column too, and one row
  per VRP and ROA: every entry of `vrps`, duplicates included (D-033).

  ## Examples

      iex> IO.iodata_to_binary(Lumina.VRP.csv([
      ...>   %{asn: 13335, afi: :ipv4, address: 0x01000000, length: 24, max_length: 24, ta: "apnic", uri: "rsync://a/1.roa"},
      ...>   %{asn: 13335, afi: :ipv4, address: 0x01000000, length: 24, max_length: 24, ta: "apnic", uri: "rsync://a/2.roa"},
      ...>   %{asn: 64496, afi: :ipv6, address: 0x20010DB8000000000000000000000000, length: 32, max_length: 48, ta: "lacnic", uri: "rsync://b/3.roa"}
      ...> ]))
      "ASN,IP Prefix,Max Length,Trust Anchor\\nAS13335,1.0.0.0/24,24,apnic\\nAS64496,2001:db8::/32,48,lacnic\\n"

      iex> IO.iodata_to_binary(Lumina.VRP.csv([
      ...>   %{asn: 13335, afi: :ipv4, address: 0x01000000, length: 24, max_length: 24, ta: "apnic", uri: "rsync://a/1.roa"},
      ...>   %{asn: 13335, afi: :ipv4, address: 0x01000000, length: 24, max_length: 24, ta: "apnic", uri: "rsync://a/2.roa"}
      ...> ], wide: true))
      "ASN,IP Prefix,Max Length,Trust Anchor,URI\\nAS13335,1.0.0.0/24,24,apnic,rsync://a/1.roa\\nAS13335,1.0.0.0/24,24,apnic,rsync://a/2.roa\\n"

  """
  @spec csv([Lumina.Validate.vrp()], keyword()) :: iolist()
  def csv(vrps, opts \\ []) do
    wide? = Keyword.get(opts, :wide, false)

    rows =
      for v <- if(wide?, do: vrps, else: distinct(vrps)) do
        [
          "AS#{v.asn},",
          Resources.format_ip({:prefix, v.address, v.length}, v.afi),
          ",#{v.max_length},",
          field(v.ta || ""),
          if(wide?, do: [",", field(v.uri)], else: []),
          "\n"
        ]
      end

    [@header, if(wide?, do: ",URI\n", else: "\n") | rows]
  end

  # A field holding a comma, a double quote or a line break is quoted, its
  # quotes doubled, as CSV readers expect: a trust anchor name, taken from
  # a TAL file name, or a URI (Lumina.URI allows a comma in a path).
  defp field(text) do
    if String.contains?(text, [",", "\"", "\n", "\r"]),
      do: ["\"", String.replace(text, "\"", "\"\""), "\""],
      else: text
  end

  @doc """
  The JSON of `vrps` (#167): an object with `metadata` (the time made,
  the time validated at, Lumina's version, each trust anchor with the
  number of its rows, and the total) and `roas`, one object per row of
  `csv/2` with the same `opts`, in the same order. `--wide` adds `"uri"`.

  Encoded with OTP's `:json`, so strings are escaped as RFC 8259 §7 says
  and the output is UTF-8; a byte that isn't UTF-8, possible in a TAL
  file's name, becomes U+FFFD. Members keep a fixed order, and each ROA
  is on a line of its own, so the output is the same for the same cache
  and time apart from `generated`.

  ## Examples

      iex> IO.iodata_to_binary(Lumina.VRP.json(
      ...>   [%{asn: 13335, afi: :ipv4, address: 0x01000000, length: 24, max_length: 24, ta: "apnic", uri: "rsync://a/1.roa"}],
      ...>   %{generated: ~U[2026-11-15 12:00:00Z], now: ~U[2026-11-15 12:00:00Z],
      ...>     trust_anchors: [%{name: "apnic", tal: "tals/apnic.tal", status: "ok"}]}))
      ~s({
        "metadata": {
          "generated": "2026-11-15T12:00:00Z",
          "validationTime": "2026-11-15T12:00:00Z",
          "lumina": "#{Mix.Project.config()[:version]}",
          "trustAnchors": [
            {"name":"apnic","tal":"tals/apnic.tal","status":"ok","vrps":1}
          ],
          "vrps": 1
        },
        "roas": [
          {"asn":"AS13335","prefix":"1.0.0.0/24","maxLength":24,"ta":"apnic"}
        ]
      }
      )

  """
  @spec json([Lumina.Validate.vrp()], metadata(), keyword()) :: iolist()
  def json(vrps, metadata, opts \\ []) do
    wide? = Keyword.get(opts, :wide, false)
    rows = if wide?, do: vrps, else: distinct(vrps)
    counts = Enum.frequencies_by(rows, & &1.ta)

    trust_anchors =
      for ta <- metadata.trust_anchors do
        object(name: ta.name, tal: ta.tal, status: ta.status, vrps: Map.get(counts, ta.name, 0))
      end

    roas =
      for v <- rows do
        object(
          [
            asn: "AS#{v.asn}",
            prefix: Resources.format_ip({:prefix, v.address, v.length}, v.afi),
            maxLength: v.max_length,
            ta: v.ta || ""
          ] ++ if(wide?, do: [uri: v.uri], else: [])
        )
      end

    [
      "{\n",
      ~s(  "metadata": {\n),
      ~s(    "generated": ),
      time(metadata.generated),
      ",\n",
      ~s(    "validationTime": ),
      time(metadata.now),
      ",\n",
      ~s(    "lumina": ),
      string(@version),
      ",\n",
      ~s(    "trustAnchors": ),
      array(trust_anchors, "    "),
      ",\n",
      ~s(    "vrps": ),
      Integer.to_string(length(rows)),
      "\n",
      "  },\n",
      ~s(  "roas": ),
      array(roas, "  "),
      "\n",
      "}\n"
    ]
  end

  # An object on one line, members in the order given.
  defp object(members) do
    [
      "{",
      Enum.map_intersperse(members, ",", fn {key, value} ->
        [string(Atom.to_string(key)), ":", value(value)]
      end),
      "}"
    ]
  end

  defp value(value) when is_integer(value), do: Integer.to_string(value)
  defp value(value) when is_binary(value), do: string(value)

  defp string(text), do: :json.encode(String.replace_invalid(text))

  # ISO 8601 in UTC, to the second.
  defp time(time),
    do:
      string(
        time
        |> DateTime.shift_zone!("Etc/UTC")
        |> DateTime.truncate(:second)
        |> DateTime.to_iso8601()
      )

  # One element per line, indented under `indent`; [] when empty.
  defp array([], _indent), do: "[]"

  defp array(elements, indent) do
    ["[\n", Enum.map_intersperse(elements, ",\n", &[indent, "  ", &1]), "\n", indent, "]"]
  end
end
