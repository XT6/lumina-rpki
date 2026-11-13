defmodule Lumina.Time do
  @moduledoc """
  Converts the ASN.1 time values used in certificates, CRLs and RPKI signed
  objects into `DateTime`, keeping the original encoding so validation can
  check which form was used (RFC 5280 §4.1.2.5).
  """

  @type t :: %{at: DateTime.t(), format: :utc_time | :generalized_time, raw: String.t()}

  @doc """
  Parses a decoded `Time` CHOICE (`{:utcTime, chars}` or
  `{:generalTime, chars}`) or a bare GeneralizedTime string.

  UTCTime years follow RFC 5280 §4.1.2.5.1: YY of 50 or more is 19YY, below
  50 is 20YY.

  ## Examples

      iex> {:ok, t} = Lumina.Time.parse({:utcTime, ~c"260101000000Z"})
      iex> {t.at, t.format}
      {~U[2026-01-01 00:00:00Z], :utc_time}

      iex> {:ok, t} = Lumina.Time.parse({:utcTime, ~c"500101000000Z"})
      iex> t.at.year
      1950

      iex> {:ok, t} = Lumina.Time.parse(~c"20360101000000Z")
      iex> {t.at, t.format}
      {~U[2036-01-01 00:00:00Z], :generalized_time}

  """
  @spec parse(term()) :: {:ok, t()} | {:error, {:invalid_time, term()}}
  def parse({:utcTime, chars}), do: utc(to_string(chars))
  def parse({:generalTime, chars}), do: generalized(to_string(chars))
  def parse(chars) when is_list(chars) or is_binary(chars), do: generalized(to_string(chars))
  def parse(other), do: {:error, {:invalid_time, other}}

  defp utc(<<yy::binary-2, rest::binary-10, "Z">> = raw) do
    with {year, ""} <- Integer.parse(yy),
         {:ok, at} <- datetime(if(year >= 50, do: 1900 + year, else: 2000 + year), rest, "") do
      {:ok, %{at: at, format: :utc_time, raw: raw}}
    else
      _ -> {:error, {:invalid_time, raw}}
    end
  end

  defp utc(raw), do: {:error, {:invalid_time, raw}}

  defp generalized(<<yyyy::binary-4, rest::binary-10, tail::binary>> = raw) do
    with {year, ""} <- Integer.parse(yyyy),
         {:ok, fraction} <- fraction(tail),
         {:ok, at} <- datetime(year, rest, fraction) do
      {:ok, %{at: at, format: :generalized_time, raw: raw}}
    else
      _ -> {:error, {:invalid_time, raw}}
    end
  end

  defp generalized(raw), do: {:error, {:invalid_time, raw}}

  # What follows the seconds: "Z", or ".digits" then "Z".
  defp fraction("Z"), do: {:ok, ""}

  defp fraction("." <> rest) do
    case Integer.parse(rest) do
      {_, "Z"} -> {:ok, String.trim_trailing(rest, "Z")}
      _ -> :error
    end
  end

  defp fraction(_tail), do: :error

  # `rest` is MMDDHHMMSS; `fraction` the digits after the decimal point.
  defp datetime(
         year,
         <<mm::binary-2, dd::binary-2, hh::binary-2, mi::binary-2, ss::binary-2>>,
         fraction
       ) do
    with [month, day, hour, minute, second] <- ints([mm, dd, hh, mi, ss]),
         {:ok, date} <- Date.new(year, month, day),
         {:ok, time} <- Time.new(hour, minute, second, microseconds(fraction)) do
      DateTime.new(date, time, "Etc/UTC")
    else
      _ -> :error
    end
  end

  defp ints(parts) do
    Enum.reduce_while(parts, [], fn part, acc ->
      case Integer.parse(part) do
        {n, ""} -> {:cont, acc ++ [n]}
        _ -> {:halt, :error}
      end
    end)
  end

  defp microseconds(""), do: {0, 0}

  defp microseconds(digits) do
    six = digits |> String.pad_trailing(6, "0") |> binary_part(0, 6) |> String.to_integer()
    {six, min(String.length(digits), 6)}
  end
end
