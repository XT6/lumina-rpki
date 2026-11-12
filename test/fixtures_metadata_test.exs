defmodule Lumina.FixturesMetadataTest do
  @moduledoc """
  Enforces that every Barry fixture documents why it exists, which RFC
  sections it checks and what a validator must conclude from it, and that
  its generated output is present. See doc/testing.md.
  """
  use ExUnit.Case, async: true

  alias Mix.Lumina.Fixtures

  test "every fixture has complete metadata and generated output" do
    {_fixtures, problems} = Fixtures.load_all()

    assert problems == [],
           "fixture problems:\n" <> Enum.map_join(problems, "\n", &"  #{&1.file}: #{&1.message}")
  end
end
