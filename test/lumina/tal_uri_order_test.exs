defmodule Lumina.TALURIOrderTest do
  @moduledoc """
  Tests the order in which a TAL's URIs are tried (D-003, #57): HTTPS first
  in TAL order, then rsync in TAL order. RFC 8630 §3 leaves the rule to each
  relying party and §4 recommends HTTPS; the fetcher in M3 follows this
  order and moves to the next URI on failure or key mismatch.
  """
  use ExUnit.Case, async: true

  alias Lumina.TAL

  defp order(uris), do: TAL.uris_by_preference(%TAL{uris: uris})

  @tag rfc: ["8630#3", "8630#4"]
  test "HTTPS URIs come before rsync URIs, whatever their order in the TAL" do
    assert order(["rsync://a/ta.cer", "https://b/ta.cer"]) == [
             "https://b/ta.cer",
             "rsync://a/ta.cer"
           ]

    assert order(["https://b/ta.cer", "rsync://a/ta.cer"]) == [
             "https://b/ta.cer",
             "rsync://a/ta.cer"
           ]
  end

  @tag rfc: "8630#3",
       doc: "Within a scheme the TAL's own order is the operator's preference, so it is kept."
  test "TAL order is kept within each scheme" do
    tal_order = [
      "rsync://r1/ta.cer",
      "https://h1/ta.cer",
      "rsync://r2/ta.cer",
      "https://h2/ta.cer",
      "rsync://r3/ta.cer"
    ]

    assert order(tal_order) == [
             "https://h1/ta.cer",
             "https://h2/ta.cer",
             "rsync://r1/ta.cer",
             "rsync://r2/ta.cer",
             "rsync://r3/ta.cer"
           ]
  end

  test "a TAL with a single scheme keeps its order" do
    assert order(["rsync://r2/ta.cer", "rsync://r1/ta.cer"]) == [
             "rsync://r2/ta.cer",
             "rsync://r1/ta.cer"
           ]

    assert order(["https://h2/ta.cer", "https://h1/ta.cer"]) == [
             "https://h2/ta.cer",
             "https://h1/ta.cer"
           ]
  end

  @tag rfc: "3986#3.1", doc: "Schemes are case-insensitive, so HTTPS:// counts as HTTPS."
  test "scheme case doesn't matter" do
    assert order(["rsync://a/ta.cer", "HTTPS://b/ta.cer"]) == [
             "HTTPS://b/ta.cer",
             "rsync://a/ta.cer"
           ]
  end

  @tag rfc: ["8630#3", "8630#2.4"]
  test "the RFC 8630 example and every Barry TAL list HTTPS first" do
    tals = [
      "test/fixtures/tals/cases/valid-rfc-8630-example/case.tal"
      | Path.wildcard("test/fixtures/barry/*/case.tal")
    ]

    for path <- tals do
      {:ok, tal} = TAL.decode_file(path)

      assert [<<"https://", _::binary>>, <<"rsync://", _::binary>>] = TAL.uris_by_preference(tal),
             path

      assert Enum.sort(TAL.uris_by_preference(tal)) == Enum.sort(tal.uris)
    end
  end
end
