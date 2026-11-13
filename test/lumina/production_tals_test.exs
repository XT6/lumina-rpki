defmodule Lumina.ProductionTALsTest do
  @moduledoc """
  The production TALs in `tals/` (D-004, #67). They must be byte-exact
  copies of the reviewed RIR TALs in `test/fixtures/tals/rir/`, which
  `Lumina.TALRIRTest` checks in detail, so production never uses a TAL
  that wasn't approved and tested. They must also parse cleanly where they
  are, under the strict grammar (D-002).
  """
  use ExUnit.Case, async: true

  alias Lumina.TAL

  @production "tals"
  @reviewed "test/fixtures/tals/rir"

  defp names(dir), do: dir |> Path.join("*.tal") |> Path.wildcard() |> Enum.map(&Path.basename/1)

  @tag doc: "Adding or removing a TAL in one folder and not the other fails."
  test "tals/ holds the same five TAL files as the reviewed RIR TALs" do
    assert names(@production) == names(@reviewed)

    assert names(@production) == [
             "afrinic.tal",
             "apnic-rfc7730-https.tal",
             "arin.tal",
             "lacnic.tal",
             "ripe-ncc.tal"
           ]
  end

  @tag doc: "Byte for byte: a changed key, URI, line ending or comment in either copy fails."
  test "every production TAL is byte-identical to its reviewed copy" do
    for name <- names(@production) do
      assert File.read!(Path.join(@production, name)) == File.read!(Path.join(@reviewed, name)),
             "#{name} differs from #{@reviewed}/#{name}"
    end
  end

  @tag rfc: "8630#2.2"
  test "every production TAL parses with no warnings" do
    for name <- names(@production) do
      assert {:ok, %TAL{warnings: []}} = TAL.decode_file(Path.join(@production, name)), name
    end
  end
end
