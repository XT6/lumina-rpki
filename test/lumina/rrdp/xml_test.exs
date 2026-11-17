defmodule Lumina.RRDP.XMLTest do
  @moduledoc """
  Tests the strict streaming XML parser for RRDP files
  (`Lumina.RRDP.XML`, D-041, #198).

  RFC 8182 §3.5 requires every RRDP file to be well-formed XML, and
  snapshots reach hundreds of megabytes, so the parser reads chunks and
  must give the same events wherever a chunk ends. It accepts exactly
  what RRDP needs, comments included (D-041 as changed), and rejects the
  rest with a rule: a parser that accepted a DOCTYPE could be made to
  expand entities without bound, and one that misread a tag or reference
  would hand the RRDP layer a different object than the server sent.
  The shapes live servers send are covered by copies of their
  notification files (`test/fixtures/rrdp/xml/live/`).
  """
  use ExUnit.Case, async: true

  alias Lumina.RRDP.XML

  @live "test/fixtures/rrdp/xml/live"

  defp collect(event, acc), do: {:cont, [event | acc]}

  defp events(xml, opts \\ []) do
    case XML.parse(xml, &collect/2, [], opts) do
      {:ok, events} -> {:ok, Enum.reverse(events)}
      other -> other
    end
  end

  defp rule(xml, opts \\ []) do
    {:error, %{rule: rule}} = events(xml, opts)
    rule
  end

  # Feeds the given chunks, then finishes.
  defp chunked(chunks, opts \\ []) do
    result =
      Enum.reduce_while(chunks, {:ok, XML.new(opts), []}, fn chunk, {:ok, state, acc} ->
        case XML.feed(state, chunk, &collect/2, acc) do
          {:ok, _, _} = ok -> {:cont, ok}
          other -> {:halt, other}
        end
      end)

    case result do
      {:ok, state, acc} ->
        case XML.finish(state, &collect/2, acc) do
          {:ok, events} -> {:ok, Enum.reverse(events)}
          other -> other
        end

      other ->
        other
    end
  end

  # A document that touches every accepted construct.
  @sample ~s(<?xml version='1.0' encoding="us-ascii" standalone="yes"?>\r\n) <>
            ~s(<!-- before -->\n<snapshot xmlns="http://www.ripe.net/rpki/rrdp" version="1"\n) <>
            ~s(  session_id="9df4b597-af9e-4dca-bdda-719cce2c4e28" serial='2'>\r\n) <>
            ~s(  <publish uri="rsync://h.example/a&amp;b/c.cer">\r\n    ZXhh<!-- inside -->bXBs\r\n) <>
            ~s(    ZTE=&#10;&#x41;&lt;&gt;&quot;&apos;\n  </publish>\n  <withdraw uri="x" hash="ab"/>\n) <>
            ~s(</snapshot>\n<!-- after -->\n)

  describe "accepted documents" do
    @tag rfc: "8182#3.5.1.3"
    test "the live notification files parse, whatever their attribute order and layout" do
      for {file, root_attrs} <- [
            {"declaration.xml", 4},
            {"one-line.xml", 4},
            {"lacnic.xml", 4}
          ] do
        assert {:ok, [{:start, "notification", attrs} | rest]} =
                 events(File.read!(Path.join(@live, file))),
               file

        assert map_size(attrs) == root_attrs, file
        assert attrs["xmlns"] == "http://www.ripe.net/rpki/rrdp"
        assert {:end, "notification"} = List.last(rest)

        assert Enum.any?(rest, &match?({:start, "snapshot", %{"uri" => _, "hash" => _}}, &1)),
               file
      end
    end

    @tag doc: """
         Comments are skipped (D-041, changed before any code): text on both
         sides of one is a single text node, and comments may stand before
         and after the root.
         """
    test "a document with every accepted construct gives the expected events" do
      assert {:ok, events} = events(@sample)

      assert events == [
               {:start, "snapshot",
                %{
                  "xmlns" => "http://www.ripe.net/rpki/rrdp",
                  "version" => "1",
                  "session_id" => "9df4b597-af9e-4dca-bdda-719cce2c4e28",
                  "serial" => "2"
                }},
               {:text, "\n  "},
               {:start, "publish", %{"uri" => "rsync://h.example/a&b/c.cer"}},
               {:text, "\n    ZXhhbXBs\n    ZTE=\nA<>\"'\n  "},
               {:end, "publish"},
               {:text, "\n  "},
               {:start, "withdraw", %{"uri" => "x", "hash" => "ab"}},
               {:end, "withdraw"},
               {:text, "\n"},
               {:end, "snapshot"}
             ]
    end

    test "comments are skipped before and after the root, between elements and inside text" do
      plain = "<a><b>xy</b><c/></a>"
      commented = "<!--1--><a><!--2--><b>x<!--3-->y</b><!---->\n<c/><!--4--></a><!--5-->"

      assert {:ok, events} = events(plain)
      assert {:ok, ^events} = events(commented |> String.replace("\n", ""))
    end

    test "the five predefined entities and character references decode in text and attribute values" do
      assert {:ok, [{:start, "a", %{"v" => "&<>\"' A\t"}}, {:text, "&<>\"'AA"}, {:end, "a"}]} =
               events(
                 ~s(<a v="&amp;&lt;&gt;&quot;&apos; &#65;&#x9;">&amp;&lt;&gt;&quot;&apos;&#65;&#x41;</a>)
               )
    end

    test "line ends become LF, and whitespace in attribute values becomes spaces" do
      assert {:ok, [{:start, "a", %{"v" => "a b c d"}}, {:text, "1\n2\n3"}, {:end, "a"}]} =
               events("<a v=\"a\tb\r\nc\nd\">1\r\n2\r3</a>")
    end

    test "an empty element gives a start and an end, and may be the root" do
      assert {:ok, [{:start, "a", %{"x" => "1"}}, {:end, "a"}]} = events(~s(<a x="1" />))
    end
  end

  describe "rejected documents" do
    @describetag rfc: "8182#3.5.1.3"

    @tag doc: "Entity declarations live in a DOCTYPE; rejecting it shuts out entity expansion."
    test "a DOCTYPE is rejected" do
      assert rule(~s(<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>)) == :doctype
    end

    test "an entity other than the five predefined ones is rejected" do
      assert rule("<a>&nbsp;</a>") == :entity
      assert rule(~s(<a v="&x;"/>)) == :entity
    end

    test "a malformed reference is rejected" do
      for xml <- [
            "<a>&amp</a>",
            "<a>& b</a>",
            "<a>&#;</a>",
            "<a>&#xZZ;</a>",
            "<a>&#0;</a>",
            "<a>&#xD800;</a>"
          ] do
        assert rule(xml) == :bad_reference, xml
      end
    end

    test "processing instructions, and a declaration not at the very start, are rejected" do
      assert rule(~s(<?pi data?><a/>)) == :processing_instruction
      assert rule(~s( <?xml version="1.0"?><a/>)) == :processing_instruction
      assert rule(~s(<a><?xml version="1.0"?></a>)) == :processing_instruction
    end

    test "a declaration with another encoding, another version or malformed is rejected" do
      assert rule(~s(<?xml version="1.0" encoding="UTF-8"?><a/>)) == :encoding
      assert rule(~s(<?xml version="2.0"?><a/>)) == :bad_declaration
      assert rule(~s(<?xml encoding="US-ASCII" version="1.0"?><a/>)) == :bad_declaration
      assert rule(~s(<?xml version="1.0" standalone="maybe"?><a/>)) == :bad_declaration
    end

    test "a CDATA section is rejected" do
      assert rule("<a><![CDATA[x]]></a>") == :cdata
    end

    test "a comment containing -- or ending in - is rejected" do
      assert rule("<a><!-- a -- b --></a>") == :comment_dashes
      assert rule("<a><!-- a ---></a>") == :comment_dashes
      assert rule("<a><!- x --></a>") == :bad_comment
    end

    @tag doc:
           "RRDP files are US-ASCII (RFC 8182 §3.5.1.3); XML allows no control characters but tab, LF and CR."
    test "a byte outside US-ASCII, or a control character, is rejected with its offset" do
      assert {:error, %{rule: :non_ascii, offset: 3}} = events("<a>é</a>")
      assert {:error, %{rule: :non_ascii, offset: 6}} = events(~s(<a v="é"/>))
      assert {:error, %{rule: :invalid_char, offset: 3}} = events("<a>\x01</a>")
      assert {:error, %{rule: :invalid_char}} = events("<a>\x7f</a>")
    end

    test "mismatched tags, a duplicate attribute and an unquoted value are rejected" do
      assert rule("<a><b></a></b>") == :mismatched_tag
      assert rule(~s(<a x="1" x="2"/>)) == :duplicate_attribute
      assert rule("<a x=1/>") == :unquoted_attribute
      assert rule(~s(<a x="1"y="2"/>)) == :missing_whitespace
      assert rule("<a x/>") == :bad_attribute
      assert rule(~s(<a x="<"/>)) == :lt_in_attribute
    end

    test "two roots, text outside the root and a missing root are rejected" do
      assert rule("<a/><b/>") == :multiple_roots
      assert rule("x<a/>") == :text_before_root
      assert rule("<a/>x") == :text_after_root
      assert rule("  \n") == :no_root
      assert rule("") == :no_root
    end

    test "a truncated document is rejected" do
      for xml <- ["<a>", "<a><b/>", "<a>text", "<a x=\"1", "<a><!-- c", "<a></a"] do
        assert rule(xml) == :truncated, xml
      end
    end

    test "]]> in text is rejected" do
      assert rule("<a>x]]>y</a>") == :cdata_end
    end

    test "namespace prefixes are rejected" do
      assert rule(~s(<r:a xmlns:r="urn:x"/>)) == :namespace_prefix
      assert rule(~s(<a xmlns:r="urn:x"/>)) == :namespace_prefix
      assert rule(~s(<a xml:lang="en"/>)) == :namespace_prefix
    end

    test "names that don't start with a letter or _ are rejected" do
      assert rule("<1a/>") == :bad_name
      assert rule("< a/>") == :bad_name
    end
  end

  describe "limits" do
    test "a text node, a tag, the nesting depth and the attribute count are bounded" do
      assert rule("<a>" <> String.duplicate("x", 101) <> "</a>", max_text: 100) == :text_too_long
      assert {:ok, _} = events("<a>" <> String.duplicate("x", 100) <> "</a>", max_text: 100)

      assert rule(~s(<a v=") <> String.duplicate("x", 200) <> ~s("/>), max_tag: 100) ==
               :tag_too_long

      assert rule("<a><a><a></a></a></a>", max_depth: 2) == :too_deep
      assert rule(~s(<a x="1" y="2" z="3"/>), max_attributes: 2) == :too_many_attributes
    end

    @tag doc: "Text split across many chunks counts as one node toward :max_text."
    test "the text limit holds across chunks" do
      chunks = ["<a>"] ++ List.duplicate(String.duplicate("x", 40), 3) ++ ["</a>"]
      assert {:error, %{rule: :text_too_long}} = chunked(chunks, max_text: 100)
      assert {:ok, _} = chunked(chunks, max_text: 120)
    end
  end

  describe "streaming" do
    @tag doc: """
         Splits the sample document (declaration, comments, references, CRLF,
         attributes in both quote styles) at every byte offset, and feeds it
         one byte at a time: the events never change.
         """
    test "chunk boundaries anywhere give the same events" do
      {:ok, expected} = events(@sample)

      for i <- 0..byte_size(@sample) do
        <<first::binary-size(^i), second::binary>> = @sample
        assert chunked([first, second]) == {:ok, expected}, "split at #{i}"
      end

      bytes = for <<b <- @sample>>, do: <<b>>
      assert chunked(bytes) == {:ok, expected}
    end

    test "errors found in a later chunk carry the offset in the whole document" do
      assert {:error, %{rule: :entity, offset: 9}} = chunked(["<a>12", "3456&x;</a>"])
    end

    test "parse_file reads a file in chunks and gives the same events as parse", %{} do
      path = Path.join(@live, "one-line.xml")
      expected = events(File.read!(path))
      assert {:ok, events} = XML.parse_file(path, &collect/2, [])
      assert {:ok, Enum.reverse(events)} == expected
      assert {:error, {:file, :enoent}} = XML.parse_file("no/such/file.xml", &collect/2, [])
    end

    test "the callback can stop the parse" do
      stop = fn
        {:start, "b", _}, acc -> {:halt, [:stopped | acc]}
        event, acc -> {:cont, [event | acc]}
      end

      assert {:halted, [:stopped, {:start, "a", %{}}]} = XML.parse("<a><b/><c/></a>", stop, [])
    end
  end

  describe "a large document" do
    @describetag :large
    @describetag timeout: :timer.minutes(30)

    @tag doc: """
         Run by hand: mix test --only large. Streams a generated 1 GB snapshot
         of 2 KB publish elements through feed/4, about 66 KB at a time,
         without writing it to disk, and checks that the VM's memory stays
         within 100 MB of where it started. Prints the peak and the
         throughput.
         """
    test "a 1 GB document parses in constant memory" do
      # About 2 KB of base64 per object, like most RPKI objects.
      element =
        ~s(<publish uri="rsync://h.example/r/o.cer">\n) <>
          String.duplicate("QUJD", 500) <> "\n</publish>\n"

      count = div(1_000_000_000, byte_size(element))
      chunk = String.duplicate(element, 32)
      :erlang.garbage_collect()
      baseline = :erlang.memory(:total)
      started = System.monotonic_time(:millisecond)

      count_text = fn
        {:text, t}, {n, peak} when byte_size(t) > 1000 ->
          peak =
            if rem(n, 1000) == 0, do: max(peak, :erlang.memory(:total) - baseline), else: peak

          {:cont, {n + 1, peak}}

        _, acc ->
          {:cont, acc}
      end

      {:ok, state, acc} = XML.feed(XML.new(), "<snapshot>\n", count_text, {0, 0})

      {state, acc} =
        Enum.reduce(1..div(count, 32), {state, acc}, fn _, {state, acc} ->
          {:ok, state, acc} = XML.feed(state, chunk, count_text, acc)
          {state, acc}
        end)

      {:ok, state, acc} = XML.feed(state, "</snapshot>\n", count_text, acc)
      {:ok, {n, peak}} = XML.finish(state, count_text, acc)
      seconds = (System.monotonic_time(:millisecond) - started) / 1000
      bytes = div(count, 32) * byte_size(chunk)

      IO.puts(
        "\n#{n} elements, #{div(bytes, 1_000_000)} MB in #{seconds} s " <>
          "(#{round(bytes / 1_000_000 / seconds)} MB/s), peak memory above the baseline #{div(peak, 1_000_000)} MB"
      )

      assert n == div(count, 32) * 32
      assert peak < 100_000_000
    end
  end
end
