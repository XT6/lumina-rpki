defmodule Lumina.TALRIRTest do
  @moduledoc """
  Real-world TALs: the five RIRs' published TALs in
  `test/fixtures/tals/rir/` (#58), byte-exact copies approved by the
  maintainer. Each must parse under the strict grammar (D-002) with no
  warnings, list the URIs the RIR published, and carry an RSA 2048-bit key
  (RFC 7935 §3). The Subject Key Identifier pins the key itself: if an RIR
  rolls its key, refreshing the file fails here until the change is
  reviewed. The SHA-256 in the README must match each file, so the
  recorded provenance stays true.
  """
  use ExUnit.Case, async: true

  alias Lumina.TAL

  @dir "test/fixtures/tals/rir"

  defp parse!(file) do
    assert {:ok, %TAL{warnings: []} = tal} = TAL.decode_file(Path.join(@dir, file))
    tal
  end

  defp assert_rsa_2048(tal) do
    assert tal.public_key_info.algorithm == {1, 2, 840, 113_549, 1, 1, 1}
    assert TAL.key_bits(tal) == 2048
  end

  defp hex(bytes),
    do:
      bytes
      |> Base.encode16(case: :lower)
      |> String.graphemes()
      |> Enum.chunk_every(2)
      |> Enum.map_join(":", &Enum.join/1)

  @tag rfc: "8630#2.2"
  @tag doc: "AFRINIC's TAL lists rsync first; D-003 still tries HTTPS first."
  test "the AFRINIC TAL parses cleanly, with its published URIs and an RSA 2048 key" do
    tal = parse!("afrinic.tal")

    assert length(tal.comments) == 0

    assert tal.uris == [
             "rsync://rpki.afrinic.net/repository/AfriNIC.cer",
             "https://rpki.afrinic.net/repository/AfriNIC.cer"
           ]

    assert_rsa_2048(tal)

    assert hex(TAL.subject_key_identifier(tal)) ==
             "eb:68:0f:38:f5:d6:c7:1b:b4:b1:06:b8:bd:06:58:50:12:da:31:b6"
  end

  @tag rfc: "8630#2.2"
  @tag doc:
         "The HTTPS-first variant from APNIC's TAL archive (maintainer's choice; the current apnic.tal is rsync only)."
  test "the APNIC TAL parses cleanly, with its published URIs and an RSA 2048 key" do
    tal = parse!("apnic-rfc7730-https.tal")

    assert length(tal.comments) == 0

    assert tal.uris == [
             "https://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
             "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer"
           ]

    assert_rsa_2048(tal)

    assert hex(TAL.subject_key_identifier(tal)) ==
             "0b:9c:ca:90:dd:0d:7a:8a:37:66:6b:19:21:7f:e0:d8:40:37:b7:a2"
  end

  @tag rfc: "8630#2.2"
  @tag doc:
         "ARIN's TAL starts with an 11-line disclaimer, so it exercises the comment rules on a real file."
  test "the ARIN TAL parses cleanly, with its published URIs and an RSA 2048 key" do
    tal = parse!("arin.tal")

    assert length(tal.comments) == 11

    assert tal.uris == [
             "rsync://rpki.arin.net/repository/arin-rpki-ta.cer",
             "https://rrdp.arin.net/arin-rpki-ta.cer"
           ]

    assert_rsa_2048(tal)

    assert hex(TAL.subject_key_identifier(tal)) ==
             "13:d4:f2:4f:9a:9f:cd:98:db:36:f9:30:63:18:08:c8:8f:39:74:bc"
  end

  @tag rfc: "8630#2.2"
  @tag doc: "LACNIC's TAL has no final newline, which RFC 8630 §2.2 doesn't require."
  test "the LACNIC TAL parses cleanly, with its published URIs and an RSA 2048 key" do
    tal = parse!("lacnic.tal")

    assert length(tal.comments) == 0

    assert tal.uris == [
             "https://rrdp.lacnic.net/ta/rta-lacnic-rpki.cer",
             "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer"
           ]

    assert_rsa_2048(tal)

    assert hex(TAL.subject_key_identifier(tal)) ==
             "fc:8a:9c:b3:ed:18:4e:17:d3:0e:ea:1e:0f:a7:61:5c:e4:b1:af:47"
  end

  @tag rfc: "8630#2.2"
  @tag doc: "RIPE NCC's preferred TAL file."
  test "the RIPE NCC TAL parses cleanly, with its published URIs and an RSA 2048 key" do
    tal = parse!("ripe-ncc.tal")

    assert length(tal.comments) == 0

    assert tal.uris == [
             "https://rpki.ripe.net/ta/ripe-ncc-ta.cer",
             "rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer"
           ]

    assert_rsa_2048(tal)

    assert hex(TAL.subject_key_identifier(tal)) ==
             "e8:55:2b:1f:d6:d1:a4:f7:e4:04:c6:d8:e5:68:0d:1e:bc:16:3f:c3"
  end

  @tag rfc: "7935#3"
  test "all five RIR TALs carry RSA 2048-bit keys" do
    for file <- Path.wildcard(Path.join(@dir, "*.tal")) do
      {:ok, tal} = TAL.decode_file(file)
      assert TAL.key_bits(tal) == 2048, file
    end
  end

  @tag doc: "The README records each file's source and SHA-256; a changed file must update it."
  test "every TAL in the folder is listed in the README with its SHA-256" do
    readme = File.read!(Path.join(@dir, "README.md"))
    files = @dir |> Path.join("*.tal") |> Path.wildcard()

    assert length(files) == 5

    for file <- files do
      sha = :crypto.hash(:sha256, File.read!(file)) |> Base.encode16(case: :lower)
      assert readme =~ "| `#{Path.basename(file)}` |", file
      assert readme =~ "`#{sha}`", "SHA-256 of #{file} isn't in the README"
    end
  end
end
