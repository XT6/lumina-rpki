defmodule Lumina.Name do
  @moduledoc """
  X.501 names and X.509 GeneralNames as decoded from certificates, CRLs and
  signed objects.

  A name is a list of RDNs; each RDN is a list of attributes
  `%{type: oid, value: value}`. A value is a string when its encoding is
  one of the string types, and `{:raw, der}` otherwise. RPKI names are
  usually one RDN holding commonName and maybe serialNumber
  (RFC 6487 §4.4, §4.5).
  """

  @type attribute :: %{type: tuple(), value: String.t() | {:raw, binary()}}
  @type t :: [[attribute()]]

  # Attribute types shown by short name in to_string/1.
  @short %{
    {2, 5, 4, 3} => "CN",
    {2, 5, 4, 5} => "serialNumber",
    {2, 5, 4, 6} => "C",
    {2, 5, 4, 7} => "L",
    {2, 5, 4, 8} => "ST",
    {2, 5, 4, 10} => "O",
    {2, 5, 4, 11} => "OU"
  }

  @doc """
  Converts a decoded `Name` (`{:rdnSequence, rdns}`).
  """
  @spec from_asn1(term()) :: t()
  def from_asn1({:rdnSequence, rdns}) do
    for rdn <- rdns do
      for %{type: type, value: value} <- rdn, do: %{type: type, value: attribute_value(value)}
    end
  end

  # An AttributeValue is an open type: the DER of the actual value.
  defp attribute_value(<<tag, rest::binary>> = der) do
    with {:ok, contents} <- contents(rest),
         {:ok, string} <- string(tag, contents) do
      string
    else
      _ -> {:raw, der}
    end
  end

  defp attribute_value(der), do: {:raw, der}

  defp contents(<<n, contents::binary-size(n)>>) when n < 128, do: {:ok, contents}

  defp contents(<<0x81, n, contents::binary-size(n)>>), do: {:ok, contents}
  defp contents(<<0x82, n::16, contents::binary-size(n)>>), do: {:ok, contents}
  defp contents(_), do: :error

  # PrintableString, UTF8String, IA5String, TeletexString, VisibleString:
  # bytes as given. BMPString is UCS-2 big endian; UniversalString UCS-4.
  defp string(tag, contents) when tag in [0x13, 0x0C, 0x16, 0x14, 0x1A], do: {:ok, contents}
  defp string(0x1E, contents), do: unicode(contents, {:utf16, :big})
  defp string(0x1C, contents), do: unicode(contents, {:utf32, :big})
  defp string(_tag, _contents), do: :error

  defp unicode(contents, encoding) do
    case :unicode.characters_to_binary(contents, encoding) do
      string when is_binary(string) -> {:ok, string}
      _ -> :error
    end
  end

  @doc """
  Formats a name for display, for example `CN=ca1`.

  ## Examples

      iex> Lumina.Name.to_string([[%{type: {2, 5, 4, 3}, value: "ca1"}, %{type: {2, 5, 4, 5}, value: "42"}]])
      "CN=ca1+serialNumber=42"

  """
  @spec to_string(t()) :: String.t()
  def to_string(rdns) do
    Enum.map_join(rdns, ",", fn rdn ->
      Enum.map_join(rdn, "+", fn %{type: type, value: value} ->
        key = Map.get(@short, type, type |> Tuple.to_list() |> Enum.join("."))

        shown =
          case value do
            {:raw, der} -> "#" <> Base.encode16(der, case: :lower)
            string -> string
          end

        "#{key}=#{shown}"
      end)
    end)
  end

  @type general_name ::
          {:uri, String.t()}
          | {:dns, String.t()}
          | {:email, String.t()}
          | {:directory_name, t()}
          | {:ip, binary()}
          | {:other, atom(), term()}

  @doc """
  Converts a decoded GeneralName CHOICE.
  """
  @spec general_name(term()) :: general_name()
  def general_name({:uniformResourceIdentifier, uri}), do: {:uri, Kernel.to_string(uri)}
  def general_name({:dNSName, name}), do: {:dns, Kernel.to_string(name)}
  def general_name({:rfc822Name, name}), do: {:email, Kernel.to_string(name)}
  def general_name({:directoryName, name}), do: {:directory_name, from_asn1(name)}
  def general_name({:iPAddress, address}), do: {:ip, address}
  def general_name({kind, value}), do: {:other, kind, value}
end
