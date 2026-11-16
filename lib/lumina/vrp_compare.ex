defmodule Lumina.VRPCompare do
  @moduledoc """
  Compares two VRP lists in the CSV of `lumina vrps` (D-032), Lumina's
  and a reference's, per trust anchor (#168, D-035).

  The reference is the CSV Routinator publishes for all trust anchors,
  <https://routinator.labs.lacnic.net/csv>, downloaded when the
  comparison runs (`fetch/2`) so that both describe the repositories at
  nearly the same time. Only that published output is used, as a sanity
  check, never another validator's code. Some differences are expected:
  the repositories change between the two runs.

  Both sides are parsed into sets of `{asn, afi, address, length,
  max_length}` per trust anchor, so the textual form doesn't matter (an
  IPv6 prefix written in another valid way is the same VRP), and
  duplicate rows count once. Lumina names a trust anchor after its TAL
  file (D-032); `compare/2` maps those names to the reference's (see
  `reference_name/1`).
  """

  import Bitwise

  alias Lumina.{HTTPS, Resources}

  @url "https://routinator.labs.lacnic.net/csv"
  @header ["ASN", "IP Prefix", "Max Length", "Trust Anchor"]
  @wide_header @header ++ ["URI"]

  # Lumina's TAL file names (tals/) whose trust anchor the reference names
  # otherwise; the rest are the same.
  @names %{"ripe-ncc" => "ripe", "apnic-rfc7730-https" => "apnic"}

  @typedoc "A VRP as compared: AS, address family, address, prefix length, maxLength."
  @type vrp :: {non_neg_integer(), :ipv4 | :ipv6, non_neg_integer(), 0..128, 0..128}

  @typedoc """
  A parsed CSV: the VRPs per trust anchor, and each line that isn't a VRP,
  with its number and why.
  """
  @type parsed :: %{
          vrps: %{String.t() => MapSet.t(vrp())},
          malformed: [{pos_integer(), String.t(), String.t()}]
        }

  @typedoc """
  One trust anchor's comparison: the number of distinct VRPs on each side
  (`nil` when that side doesn't have the trust anchor at all) and the VRPs
  only one side has, sorted as `lumina vrps` sorts them.
  """
  @type result :: %{
          ta: String.t(),
          lumina: non_neg_integer() | nil,
          reference: non_neg_integer() | nil,
          only_lumina: [vrp()],
          only_reference: [vrp()]
        }

  @doc "The reference CSV's URL (D-035)."
  @spec url() :: String.t()
  def url, do: @url

  @doc """
  The reference's name for a trust anchor Lumina named after its TAL file.

      iex> Lumina.VRPCompare.reference_name("ripe-ncc")
      "ripe"
      iex> Lumina.VRPCompare.reference_name("apnic-rfc7730-https")
      "apnic"
      iex> Lumina.VRPCompare.reference_name("lacnic")
      "lacnic"
  """
  @spec reference_name(String.t()) :: String.t()
  def reference_name(name), do: Map.get(@names, name, name)

  @doc """
  Downloads the reference CSV with `Lumina.HTTPS.fetch/2`. The whole file
  is about 34 MB (2026-11-15), so `:max_size` defaults to 128 MiB; other
  options go to `fetch/2`.
  """
  @spec fetch(String.t(), keyword()) ::
          {:ok, binary()} | {:error, HTTPS.error() | Lumina.URI.error()}
  def fetch(url \\ @url, opts \\ []) do
    with {:ok, uri} <- Lumina.URI.parse(url),
         {:ok, %{body: body}} <-
           HTTPS.fetch(uri, Keyword.merge([max_size: 128 * 1024 * 1024], opts)) do
      {:ok, body}
    end
  end

  @doc """
  Parses a CSV in `lumina vrps`' columns (D-032), with or without the URI
  column of `--wide`, which is ignored. A missing or different header is
  an error; a line that isn't a VRP is listed in `malformed` and skipped.

      iex> csv = "ASN,IP Prefix,Max Length,Trust Anchor\\nAS1,10.0.0.0/8,16,ta\\nAS2,10.0.0.1/8,8,ta\\n"
      iex> {:ok, parsed} = Lumina.VRPCompare.parse(csv)
      iex> parsed.vrps
      %{"ta" => MapSet.new([{1, :ipv4, 0x0A000000, 8, 16}])}
      iex> parsed.malformed
      [{3, "AS2,10.0.0.1/8,8,ta", "10.0.0.1/8 has bits set past its length"}]
  """
  @spec parse(binary()) :: {:ok, parsed()} | {:error, String.t()}
  def parse(text) do
    [first | rest] = text |> String.split("\n") |> Enum.map(&String.trim_trailing(&1, "\r"))

    case fields(first) do
      {:ok, header} when header in [@header, @wide_header] ->
        {vrps, malformed} =
          rest
          |> Enum.with_index(2)
          |> Enum.reduce({%{}, []}, fn
            {"", _number}, acc ->
              acc

            {line, number}, {vrps, malformed} ->
              case row(line) do
                {:ok, ta, vrp} ->
                  {Map.update(vrps, ta, MapSet.new([vrp]), &MapSet.put(&1, vrp)), malformed}

                {:error, reason} ->
                  {vrps, [{number, line, reason} | malformed]}
              end
          end)

        {:ok, %{vrps: vrps, malformed: Enum.reverse(malformed)}}

      _ ->
        {:error, "line 1 is not the header #{Enum.join(@header, ",")}"}
    end
  end

  defp row(line) do
    with {:ok, [asn, prefix, max_length, ta | uri]} when length(uri) <= 1 <- fields(line),
         {:ok, asn} <- asn(asn),
         {:ok, {afi, address, length}} <- prefix(prefix),
         {:ok, max_length} <- max_length(max_length, afi, length) do
      {:ok, ta, {asn, afi, address, length, max_length}}
    else
      {:ok, _fields} -> {:error, "expected 4 fields (5 with a URI)"}
      {:error, _} = error -> error
    end
  end

  defp asn("AS" <> digits) do
    case Integer.parse(digits) do
      {asn, ""} when asn in 0..0xFFFFFFFF -> {:ok, asn}
      _ -> {:error, "AS#{digits} is not an AS number"}
    end
  end

  defp asn(text), do: {:error, "#{text} is not an AS number (AS and digits)"}

  defp prefix(text) do
    with [address, length] <- String.split(text, "/"),
         {:ok, ip} <- :inet.parse_strict_address(String.to_charlist(address)),
         {length, ""} <- Integer.parse(length),
         {afi, bits, value} = integer(ip),
         true <- length in 0..bits do
      if (value &&& (1 <<< (bits - length)) - 1) == 0,
        do: {:ok, {afi, value, length}},
        else: {:error, "#{text} has bits set past its length"}
    else
      _ -> {:error, "#{text} is not a prefix"}
    end
  end

  defp integer({_, _, _, _} = ip),
    do: {:ipv4, 32, ip |> Tuple.to_list() |> Enum.reduce(0, &(&2 <<< 8 ||| &1))}

  defp integer(ip), do: {:ipv6, 128, ip |> Tuple.to_list() |> Enum.reduce(0, &(&2 <<< 16 ||| &1))}

  defp max_length(text, afi, length) do
    bits = if afi == :ipv4, do: 32, else: 128

    case Integer.parse(text) do
      {max, ""} when max in length..bits//1 -> {:ok, max}
      _ -> {:error, "#{text} is not a maxLength from #{length} to #{bits}"}
    end
  end

  # CSV fields, double-quoted ones with doubled quotes inside, as
  # Lumina.VRP writes them.
  defp fields(line), do: fields(line, [], [])

  defp fields("", field, acc), do: {:ok, Enum.reverse([done(field) | acc])}
  defp fields("," <> rest, field, acc), do: fields(rest, [], [done(field) | acc])

  defp fields("\"" <> rest, [], acc) do
    case quoted(rest, []) do
      {:ok, value, ""} -> {:ok, Enum.reverse([value | acc])}
      {:ok, value, "," <> rest} -> fields(rest, [], [value | acc])
      _ -> :error
    end
  end

  defp fields(<<c::utf8, rest::binary>>, field, acc), do: fields(rest, [<<c::utf8>> | field], acc)
  defp fields(_invalid, _field, _acc), do: :error

  defp quoted("\"\"" <> rest, value), do: quoted(rest, ["\"" | value])
  defp quoted("\"" <> rest, value), do: {:ok, done(value), rest}
  defp quoted(<<c::utf8, rest::binary>>, value), do: quoted(rest, [<<c::utf8>> | value])
  defp quoted(_, _value), do: :error

  defp done(field), do: field |> Enum.reverse() |> IO.iodata_to_binary()

  @doc """
  Compares Lumina's VRPs with the reference's, per trust anchor, after
  mapping Lumina's trust anchor names (`reference_name/1`). Every trust
  anchor on either side has a result, sorted by name.
  """
  @spec compare(parsed(), parsed()) :: [result()]
  def compare(%{vrps: lumina}, %{vrps: reference}) do
    lumina = Map.new(lumina, fn {ta, set} -> {reference_name(ta), set} end)

    for ta <- Enum.sort(Enum.uniq(Map.keys(lumina) ++ Map.keys(reference))) do
      ours = Map.get(lumina, ta)
      theirs = Map.get(reference, ta)

      %{
        ta: ta,
        lumina: ours && MapSet.size(ours),
        reference: theirs && MapSet.size(theirs),
        only_lumina: only(ours, theirs),
        only_reference: only(theirs, ours)
      }
    end
  end

  defp only(nil, _other), do: []
  defp only(set, nil), do: sort(MapSet.to_list(set))
  defp only(set, other), do: sort(MapSet.to_list(MapSet.difference(set, other)))

  defp sort(vrps) do
    Enum.sort_by(vrps, fn {asn, afi, address, length, max} ->
      {if(afi == :ipv4, do: 0, else: 1), address, length, max, asn}
    end)
  end

  @doc """
  A VRP as `lumina vrps` writes it, without the trust anchor.

      iex> Lumina.VRPCompare.format({13335, :ipv4, 0x01000000, 24, 24})
      "AS13335,1.0.0.0/24,24"
  """
  @spec format(vrp()) :: String.t()
  def format({asn, afi, address, length, max}),
    do: "AS#{asn},#{Resources.format_ip({:prefix, address, length}, afi)},#{max}"

  @doc """
  The comparison as text: per trust anchor, the counts and the VRPs only
  one side has, at most `limit` of each. A trust anchor only one side has
  is shown as missing from the other, without listing its VRPs.
  """
  @spec report([result()], pos_integer()) :: String.t()
  def report(results, limit) do
    IO.iodata_to_binary(
      for r <- results do
        case {r.lumina, r.reference} do
          {nil, n} ->
            "#{r.ta}: not in Lumina's output (reference: #{n} VRPs)\n"

          {n, nil} ->
            "#{r.ta}: not in the reference (Lumina: #{n} VRPs)\n"

          {ours, theirs} ->
            [
              "#{r.ta}: Lumina #{ours}, reference #{theirs}, " <>
                "only in Lumina #{length(r.only_lumina)}, " <>
                "only in the reference #{length(r.only_reference)}\n",
              listed("only in Lumina", r.only_lumina, limit),
              listed("only in the reference", r.only_reference, limit)
            ]
        end
      end
    )
  end

  defp listed(_label, [], _limit), do: []

  defp listed(label, vrps, limit) do
    {shown, rest} = Enum.split(vrps, limit)

    [
      "  #{label}:\n",
      Enum.map(shown, &["    ", format(&1), "\n"]),
      if(rest == [], do: [], else: "    ... and #{length(rest)} more\n")
    ]
  end
end
