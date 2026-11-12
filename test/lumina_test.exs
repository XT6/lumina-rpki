defmodule LuminaTest do
  use ExUnit.Case, async: true
  doctest Lumina

  test "version/0 matches the version in mix.exs" do
    assert Lumina.version() == Mix.Project.config()[:version]
  end
end
