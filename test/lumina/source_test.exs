defmodule Lumina.SourceTest do
  @moduledoc """
  `Lumina.Source` (#206): where each CA's publication point was last read
  from while accepted, its RRDP store or the rsync tree. A sync can read a
  point over RRDP one run and from rsync the next (D-040), so offline
  validation (#207) needs the record; one that can't be trusted must read
  as no record at all.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Source, URI}

  @moduletag :tmp_dir
  @key "rsync://localhost:8873/rpki/ta/ta.mft"
  @at ~U[2030-01-01 00:00:00Z]

  defp uri!(text) do
    {:ok, uri} = URI.parse(text)
    uri
  end

  test "a saved source loads back, for RRDP and for rsync", %{tmp_dir: dir} do
    notify = uri!("https://localhost:8443/rrdp/notification.xml")
    module = uri!("rsync://localhost:8873/rpki")

    assert :ok = Source.save(dir, @key, {:rrdp, notify}, @at)
    assert Source.load(dir, @key) == %{source: {:rrdp, notify}, at: @at}

    assert :ok = Source.save(dir, @key, {:rsync, module}, @at)
    assert Source.load(dir, @key) == %{source: {:rsync, module}, at: @at}
  end

  test "a point never recorded, or a file that can't be trusted, loads as nil", %{tmp_dir: dir} do
    assert Source.load(dir, @key) == nil

    File.mkdir_p!(Path.dirname(Source.file(dir, @key)))
    File.write!(Source.file(dir, @key), "not json")
    assert Source.load(dir, @key) == nil

    File.write!(
      Source.file(dir, @key),
      ~s({"point": "rsync://other/x.mft", "transport": "rrdp", "uri": "https://a/n.xml", "at": "2030-01-01T00:00:00Z"})
    )

    assert Source.load(dir, @key) == nil
  end
end
