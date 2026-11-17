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

  @doc """
  The line `lumina` writes to stderr when it starts (D-045, #213): the
  version, the runtimes and the start time `at`, in UTC.

  ## Examples

      iex> Lumina.banner(~U[2026-11-17 12:00:00.123Z]) =~
      ...>   ~r/^lumina \\d+\\.\\d+\\.\\d+ · RPKI relying party · Erlang\\/OTP \\S+ · Elixir \\S+ · 2026-11-17T12:00:00Z$/
      true

  """
  @spec banner(DateTime.t()) :: String.t()
  def banner(%DateTime{} = at) do
    Enum.join(
      [
        "lumina #{version()}",
        "RPKI relying party",
        "Erlang/OTP #{otp_version()}",
        "Elixir #{System.version()}",
        at |> DateTime.truncate(:second) |> DateTime.to_iso8601()
      ],
      " · "
    )
  end

  # The full OTP version (29.1.2) from the runtime's OTP_VERSION file, or
  # the release number (29) if it can't be read.
  defp otp_version do
    release = to_string(:erlang.system_info(:otp_release))
    file = Path.join([to_string(:code.root_dir()), "releases", release, "OTP_VERSION"])

    case File.read(file) do
      {:ok, text} -> String.trim(text)
      {:error, _} -> release
    end
  end
end
