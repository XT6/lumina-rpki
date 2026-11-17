defmodule Lumina.RRDP.FilesTest do
  @moduledoc """
  Tests the decoding of the three RRDP files (#199):
  `Lumina.RRDP.Notification` (RFC 8182 §3.5.1.3, RFC 9674 §3.2),
  `Lumina.RRDP.Snapshot` (§3.5.2.3) and `Lumina.RRDP.Delta` (§3.5.3.3),
  against the §3.5.4 schema, with D-042 for the session_id.

  Each rule a server can break has a hand-written file in
  `test/fixtures/rrdp/cases/`, with its expected outcome in `cases.exs`.
  A decoder that let one through would hand the RRDP layer a file the RFC
  says MUST be rejected: a snapshot from another session, a delta out of
  sequence, a reference to another server (RFC 9674), or an object under
  a URI that escapes the cache. Barry's RRDP output is decoded too, to
  show the snapshot carries the same objects as the rsync tree.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  doctest Lumina.RRDP

  alias Lumina.RRDP.{Delta, Notification, Snapshot}
  alias Lumina.Test.Fixture
  alias Mix.Lumina.RFC

  @cases "test/fixtures/rrdp/cases"
  @session "9df4b597-af9e-4dca-bdda-719cce2c4e28"
  @expected %{session_id: @session, serial: 3}

  defp uri!(text) do
    {:ok, uri} = Lumina.URI.parse(text)
    uri
  end

  defp cases do
    {cases, _} = Code.eval_file(Path.join(@cases, "cases.exs"))
    cases
  end

  defp collect(element, acc), do: {:cont, [element | acc]}

  # Decodes a case's file as its kind; {:ok, warnings} or {:error, rule}.
  defp outcome(%{id: id, kind: kind}) do
    xml = File.read!(Path.join(@cases, id <> ".xml"))

    result =
      case kind do
        :notification ->
          with {:ok, n} <-
                 Notification.decode(xml, uri!("https://rrdp.example.net/notification.xml")),
               do: {:ok, n.warnings}

        :snapshot ->
          with {:ok, _} <- Snapshot.parse(xml, @expected, &collect/2, []), do: {:ok, []}

        :delta ->
          with {:ok, _} <- Delta.parse(xml, @expected, &collect/2, []), do: {:ok, []}
      end

    case result do
      {:ok, []} -> :ok
      {:ok, [%{rule: rule}]} -> {:warning, rule}
      {:error, %{rule: rule}} -> {:error, rule}
    end
  end

  describe "the cases" do
    test "every case has metadata, a file and valid RFC references" do
      cases = cases()
      library = RFC.load_library()
      files = for f <- File.ls!(@cases), Path.extname(f) == ".xml", do: Path.rootname(f)

      assert Enum.sort(files) == Enum.sort(Enum.map(cases, & &1.id))

      for c <- cases do
        assert c.kind in [:notification, :snapshot, :delta], c.id
        assert is_binary(c.rationale) and String.trim(c.rationale) != "", c.id
        assert [_ | _] = c.rfc

        for ref <- c.rfc,
            do: assert(match?({:ok, _}, RFC.validate(ref, library)), "#{c.id}: #{ref}")

        assert c.expected == :ok or
                 match?(
                   {kind, rule} when kind in [:warning, :error] and is_atom(rule),
                   c.expected
                 ),
               c.id
      end
    end

    @tag rfc: ["8182#3.5.1.3", "8182#3.5.2.3", "8182#3.5.3.3", "8182#3.5.4", "9674#3.2"],
         doc:
           "Driven by cases.exs: each file is accepted, warned about or rejected for its stated rule."
    test "every case gives the outcome its metadata states" do
      capture_log(fn ->
        for c <- cases() do
          assert outcome(c) == c.expected, "#{c.id}: #{c.rationale}"
        end
      end)
    end
  end

  describe "notification" do
    @tag rfc: "8182#3.5.1.3"
    test "a notification decodes to its session, serial, snapshot and deltas sorted by serial" do
      xml = File.read!(Path.join(@cases, "notification-valid.xml"))

      assert {:ok, n} =
               Notification.decode(xml, uri!("https://rrdp.example.net/notification.xml"))

      assert %{session_id: @session, serial: 3, warnings: []} = n
      assert to_string(n.snapshot.uri) == "https://rrdp.example.net/#{@session}/3/snapshot.xml"
      assert n.snapshot.hash == :binary.copy(<<0xAA>>, 32)
      assert Enum.map(n.deltas, & &1.serial) == [2, 3]
      assert to_string(hd(n.deltas).uri) == "https://rrdp.example.net/#{@session}/2/delta.xml"
    end

    @tag rfc: "9674#3.2",
         doc:
           "RFC 9674 §3.2: implementations SHOULD log a message when cross-origin referrals are detected."
    test "a cross-origin reference is logged" do
      xml = File.read!(Path.join(@cases, "notification-cross-origin-host.xml"))

      log =
        capture_log(fn ->
          assert {:error, %{rule: :cross_origin}} =
                   Notification.decode(xml, uri!("https://rrdp.example.net/notification.xml"))
        end)

      assert log =~ "https://other.example.net/s.xml"
      assert log =~ "RFC 9674"
    end

    @tag rfc: "9674#3.2",
         doc:
           "The origin is the notification URI's: the same file fetched from another host is cross-origin."
    test "the same notification is cross-origin when fetched from another host" do
      xml = File.read!(Path.join(@cases, "notification-valid.xml"))

      capture_log(fn ->
        assert {:error, %{rule: :cross_origin}} =
                 Notification.decode(xml, uri!("https://mirror.example.net/notification.xml"))
      end)
    end
  end

  describe "snapshot and delta" do
    @tag rfc: "8182#3.5.2.3"
    test "a snapshot's objects come out with their rsync URIs and decoded bytes" do
      xml = File.read!(Path.join(@cases, "snapshot-valid.xml"))
      assert {:ok, elements} = Snapshot.parse(xml, @expected, &collect/2, [])

      assert [
               {:publish, %{path: ["repo", "ca", "one.cer"]}, "object one"},
               {:publish, %{path: ["repo", "ca", "two.roa"]}, two}
             ] = Enum.reverse(elements)

      assert two == String.duplicate("z", 300)
    end

    @tag rfc: "8182#3.5.3.3"
    test "a delta's elements come out as new, replaced and withdrawn objects" do
      xml = File.read!(Path.join(@cases, "delta-valid.xml"))
      hash = :binary.copy(<<0xAA>>, 32)
      assert {:ok, elements} = Delta.parse(xml, @expected, &collect/2, [])

      assert [
               {:publish, %{path: ["repo", "ca", "new.roa"]}, "object one"},
               {:publish, %{path: ["repo", "ca", "ca.mft"]}, "object one", ^hash},
               {:withdraw, %{path: ["repo", "ca", "old.roa"]}, ^hash}
             ] = Enum.reverse(elements)
    end

    @tag rfc: "8182#3.5.4", doc: "D-043: each published object at most 20 MiB, as for rsync."
    test "an object over 20 MiB is rejected, and one of exactly 20 MiB isn't" do
      snapshot = fn size ->
        ~s(<snapshot xmlns="http://www.ripe.net/rpki/rrdp" version="1" session_id="#{@session}" serial="3">) <>
          ~s(<publish uri="rsync://h.example/r/big.cer">) <>
          Base.encode64(:binary.copy(<<0>>, size)) <> "</publish></snapshot>"
      end

      limit = 20 * 1024 * 1024

      assert {:error, %{rule: :object_too_large}} =
               Snapshot.parse(snapshot.(limit + 1), @expected, &collect/2, [])

      assert {:ok, [{:publish, _, bytes}]} =
               Snapshot.parse(snapshot.(limit), @expected, &collect/2, [])

      assert byte_size(bytes) == limit
    end

    test "a snapshot streams from a file as it parses from memory, and the callback can stop it",
         %{} do
      path = Path.join(@cases, "snapshot-valid.xml")

      assert Snapshot.stream(path, @expected, &collect/2, []) ==
               Snapshot.parse(File.read!(path), @expected, &collect/2, [])

      stop = fn element, acc -> {:halt, [element | acc]} end
      assert {:halted, [{:publish, _, "object one"}]} = Snapshot.stream(path, @expected, stop, [])
    end
  end

  describe "Barry's RRDP output" do
    @tag rfc: ["8182#3.5.1.3", "8182#3.5.2.3", "8182#4.1"],
         doc: """
         Barry writes session_id="1" (F-038), which D-042 rejects. With a
         UUID in its place, the notification and snapshot decode, and the
         snapshot publishes exactly the fixture's rsync tree below the TA,
         byte for byte.
         """
    test "a fixture's notification and snapshot decode once the session is a UUID, and carry its rsync objects" do
      fixture = Fixture.load!("m0-minimal-valid")
      rrdp = Path.join(Path.dirname(fixture.tal_path), "rrdp")
      notification = File.read!(Path.join(rrdp, "notification.xml"))
      snapshot = File.read!(Path.join(rrdp, "snapshot.xml"))
      notify = uri!("https://localhost:8443/rrdp/notification.xml")

      assert {:error, %{rule: :session_id}} = Notification.decode(notification, notify)

      uuid = ~s(session_id="#{@session}")

      assert {:ok, n} =
               Notification.decode(String.replace(notification, ~s(session_id="1"), uuid), notify)

      assert n.snapshot.hash == :crypto.hash(:sha256, snapshot)

      assert {:ok, objects} =
               snapshot
               |> String.replace(~s(session_id="1"), uuid)
               |> Snapshot.parse(%{session_id: @session, serial: n.serial}, &collect/2, [])

      published =
        Map.new(objects, fn {:publish, uri, bytes} -> {Enum.join(tl(uri.path), "/"), bytes} end)

      tree =
        for path <- Path.wildcard(Path.join(fixture.rsync_root, "**/*")),
            File.regular?(path),
            relative = Path.relative_to(path, fixture.rsync_root),
            relative != "ta.cer",
            into: %{},
            do: {relative, File.read!(path)}

      assert published == tree
    end
  end
end
