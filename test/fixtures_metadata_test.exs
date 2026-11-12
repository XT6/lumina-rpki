defmodule Lumina.FixturesMetadataTest do
  # Every Barry fixture must document why it exists, which RFC sections it
  # checks and what a validator must conclude from it. See doc/testing.md.
  use ExUnit.Case, async: true

  alias Mix.Lumina.Fixtures

  test "every fixture has complete metadata and generated output" do
    {_fixtures, problems} = Fixtures.load_all()

    assert problems == [],
           "fixture problems:\n" <> Enum.map_join(problems, "\n", &"  #{&1.file}: #{&1.message}")
  end
end
