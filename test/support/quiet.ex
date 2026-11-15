defmodule Lumina.Test.Quiet do
  @moduledoc """
  Progress is on by default (D-036), so `lumina sync`, `validate` and
  `vrps` write progress lines to stderr. Tests that check stderr for
  something else run them with `--quiet`, unless the test passes
  `--progress` or `--quiet` itself; `Lumina.ProgressTest` covers the
  default.
  """

  @long_running ~w(sync validate vrps)

  @doc """
  `args` with `--quiet` added for a long-running command.

  ## Examples

      iex> Lumina.Test.Quiet.args(["vrps", "--tal", "x.tal"])
      ["vrps", "--tal", "x.tal", "--quiet"]

      iex> Lumina.Test.Quiet.args(["sync", "--progress"])
      ["sync", "--progress"]

      iex> Lumina.Test.Quiet.args(["print", "a.cer"])
      ["print", "a.cer"]

  """
  @spec args([String.t()]) :: [String.t()]
  def args([command | rest] = args) when command in @long_running do
    if Enum.any?(rest, &(&1 in ["--progress", "--quiet", "--help", "-h"])),
      do: args,
      else: args ++ ["--quiet"]
  end

  def args(args), do: args
end
