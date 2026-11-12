defmodule Lumina do
  @moduledoc """
  Lumina is an RPKI relying party (validator) built from the RFC texts in
  `doc/rfc/`.
  """

  @doc """
  Returns the application version.

  ## Examples

      iex> Lumina.version() =~ ~r/^\\d+\\.\\d+\\.\\d+/
      true

  """
  @spec version() :: String.t()
  def version do
    :lumina |> Application.spec(:vsn) |> to_string()
  end
end
