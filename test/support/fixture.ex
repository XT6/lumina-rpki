defmodule Lumina.Test.Fixture do
  @moduledoc """
  Loads Barry fixtures for tests. See `doc/testing.md`.

      fixture = Lumina.Test.Fixture.load!("m0-minimal-valid")
      fixture.tal_path    # path to case.tal
      fixture.rsync_root  # local copy of the rsync tree

  The result also holds the fixture's metadata (`:id`, `:title`,
  `:rationale`, `:rfc`, `:expected`, ...).
  """

  alias Mix.Lumina.Fixtures

  @type t :: %{
          required(:id) => String.t(),
          required(:dir) => Path.t(),
          required(:tal_path) => Path.t(),
          required(:rsync_root) => Path.t(),
          required(:rrdp_root) => Path.t(),
          optional(atom()) => term()
        }

  @doc """
  Loads the fixture with `id`. Raises if it doesn't exist or fails its
  metadata check.
  """
  @spec load!(String.t()) :: t()
  def load!(id) do
    case_dir = Path.join(Fixtures.dir(), id)

    unless File.dir?(case_dir) do
      raise ArgumentError, "no fixture #{inspect(id)} in #{Fixtures.dir()}"
    end

    case Fixtures.load(case_dir) do
      {:ok, fixture} ->
        Map.merge(fixture, %{
          tal_path: Path.join(case_dir, "case.tal"),
          rsync_root: Path.join(case_dir, "rsync"),
          rrdp_root: Path.join(case_dir, "rrdp")
        })

      {:error, problems} ->
        raise ArgumentError,
              "fixture #{inspect(id)} fails its metadata check:\n" <>
                Enum.map_join(problems, "\n", &"  #{&1.message}")
    end
  end
end
