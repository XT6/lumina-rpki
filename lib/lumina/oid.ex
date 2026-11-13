defmodule Lumina.OID do
  @moduledoc """
  Names for the object identifiers that appear in RPKI objects, for
  display. Unknown OIDs are shown in dotted form only.
  """

  @names %{
    # Algorithms (RFC 7935, RFC 4055, RFC 5754)
    {1, 2, 840, 113_549, 1, 1, 1} => "rsaEncryption",
    {1, 2, 840, 113_549, 1, 1, 11} => "sha256WithRSAEncryption",
    {2, 16, 840, 1, 101, 3, 4, 2, 1} => "sha256",
    # CMS content types (RFC 5652) and RPKI eContent types
    {1, 2, 840, 113_549, 1, 7, 1} => "data",
    {1, 2, 840, 113_549, 1, 7, 2} => "signedData",
    {1, 2, 840, 113_549, 1, 9, 16, 1, 24} => "routeOriginAuthz",
    {1, 2, 840, 113_549, 1, 9, 16, 1, 26} => "rpkiManifest",
    {1, 2, 840, 113_549, 1, 9, 16, 1, 35} => "rpkiGhostbusters",
    {1, 2, 840, 113_549, 1, 9, 16, 1, 48} => "signedChecklist",
    {1, 2, 840, 113_549, 1, 9, 16, 1, 50} => "signedTAL",
    # CMS signed attributes
    {1, 2, 840, 113_549, 1, 9, 3} => "contentType",
    {1, 2, 840, 113_549, 1, 9, 4} => "messageDigest",
    {1, 2, 840, 113_549, 1, 9, 5} => "signingTime",
    {1, 2, 840, 113_549, 1, 9, 16, 2, 46} => "binarySigningTime",
    # Certificate policies (RFC 6484, RFC 8360)
    {1, 3, 6, 1, 5, 5, 7, 14, 2} => "id-cp-ipAddr-asNumber",
    {1, 3, 6, 1, 5, 5, 7, 14, 3} => "id-cp-ipAddr-asNumber-v2",
    # Name attributes (RFC 5280)
    {2, 5, 4, 3} => "commonName",
    {2, 5, 4, 5} => "serialNumber"
  }

  @doc """
  The name of an OID, or `nil`.

  ## Examples

      iex> Lumina.OID.name({1, 2, 840, 113549, 1, 1, 11})
      "sha256WithRSAEncryption"

  """
  @spec name(tuple()) :: String.t() | nil
  def name(oid), do: Map.get(@names, oid)

  @doc """
  The dotted form of an OID.

  ## Examples

      iex> Lumina.OID.dotted({1, 3, 6, 1})
      "1.3.6.1"

  """
  @spec dotted(tuple()) :: String.t()
  def dotted(oid), do: oid |> Tuple.to_list() |> Enum.join(".")

  @doc """
  `name (dotted)` when the name is known, otherwise the dotted form.

  ## Examples

      iex> Lumina.OID.format({2, 16, 840, 1, 101, 3, 4, 2, 1})
      "sha256 (2.16.840.1.101.3.4.2.1)"

      iex> Lumina.OID.format({1, 2, 3})
      "1.2.3"

  """
  @spec format(tuple()) :: String.t()
  def format(oid) do
    case name(oid) do
      nil -> dotted(oid)
      name -> "#{name} (#{dotted(oid)})"
    end
  end
end
