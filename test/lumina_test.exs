defmodule LuminaTest do
  @moduledoc """
  Smoke test for the application module: the project builds and reports
  its version.
  """
  use ExUnit.Case, async: true
  doctest Lumina

  test "version/0 matches the version in mix.exs" do
    assert Lumina.version() == Mix.Project.config()[:version]
  end
end
