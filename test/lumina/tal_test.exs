defmodule Lumina.TALTest do
  @moduledoc """
  Tests the TAL parser (RFC 8630 §2.2, strict grammar per D-002). The test
  TAL corpus (#55) fixes the exact outcome, rule and line for every case.
  Barry's TALs must parse, and must carry exactly their TA certificate's
  key, because everything the validator trusts starts from this key.
  """
  use ExUnit.Case, async: true
  doctest Lumina.TAL

  alias Lumina.{Certificate, TAL}
  alias Mix.Lumina.{Fixtures, TALCases}

  defp outcome(text) do
    case TAL.parse(text) do
      {:ok, %TAL{warnings: []}} ->
        :valid

      {:ok, %TAL{warnings: warnings}} ->
        {:valid, warnings: Enum.map(warnings, &Map.take(&1, [:line, :rule]))}

      {:error, finding} ->
        {:invalid, Map.take(finding, [:line, :rule])}
    end
  end

  @tag rfc: ["8630#2.2", "8630#2.4", "4648#4", "3986#3"],
       doc:
         "The corpus states each case's expected outcome; any difference, including the line, fails."
  test "every case in the test TAL corpus gives exactly its expected outcome" do
    {cases, []} = TALCases.load_all()

    mismatches =
      for tal_case <- cases, (got = outcome(tal_case.tal)) != tal_case.expected do
        "#{tal_case.id}: expected #{inspect(tal_case.expected)}, got #{inspect(got)}"
      end

    assert mismatches == [], Enum.join(mismatches, "\n")
    assert length(cases) >= 25
  end

  @tag rfc: ["8630#2.2", "8630#2.3"],
       doc:
         "Barry writes one TAL per repository; its key must be exactly the TA certificate's SPKI."
  test "every Barry TAL parses and carries its TA certificate's key" do
    for dir <- Fixtures.case_dirs() do
      assert {:ok, %TAL{warnings: []} = tal} = TAL.decode_file(Path.join(dir, "case.tal")), dir
      {:ok, ta} = Certificate.decode(File.read!(Path.join([dir, "rsync", "ta.cer"])))

      assert tal.public_key == ta.public_key.der, dir

      assert TAL.subject_key_identifier(tal) ==
               Certificate.extension_value(ta, :subject_key_identifier)

      assert [_rsync, _https] = tal.uris
    end
  end

  @tag rfc: ["8630#2.4", "8630#2.2"]
  test "the RFC 8630 example parses into its comments, two URIs and an RSA 2048 key" do
    {:ok, tal} = TAL.decode_file("test/fixtures/tals/cases/valid-rfc-8630-example/case.tal")

    assert tal.comments == [
             "# This TAL is intended for documentation purposes only.",
             "# Do not attempt to use this in a production setting."
           ]

    assert tal.uris == [
             "rsync://rpki.example.org/rpki/hedgehog/root.cer",
             "https://rpki.example.org/rpki/hedgehog/root.cer"
           ]

    assert tal.public_key_info.algorithm == {1, 2, 840, 113_549, 1, 1, 1}
    assert TAL.key_bits(tal) == 2048
    assert byte_size(TAL.subject_key_identifier(tal)) == 20
  end

  @tag rfc: "8630#2.2"
  test "CRLF and LF line ends give the same result" do
    lf = File.read!("test/fixtures/tals/cases/valid-rfc-8630-example/case.tal")
    crlf = String.replace(lf, "\n", "\r\n")
    assert TAL.parse(crlf) == TAL.parse(lf)
  end

  @tag rfc: "8630#2.2", doc: "D-002: trailing whitespace is ignored, with one warning per line."
  test "trailing whitespace is ignored and warned about, giving the same TAL" do
    clean =
      "rsync://x.example/ta.cer\n\n" <>
        Base.encode64(File.read!("test/fixtures/barry/m0-minimal-valid/rsync/ta.cer") |> spki())

    spaced = String.replace(clean, "ta.cer\n", "ta.cer  \n")

    {:ok, a} = TAL.parse(clean)
    {:ok, b} = TAL.parse(spaced)

    assert %{a | warnings: []} == %{b | warnings: []}
    assert [%{line: 1, rule: :trailing_whitespace, rfc: "8630#2.2"}] = b.warnings
  end

  test "errors carry a line, a rule, an RFC reference and a message" do
    assert {:error, %{line: 1, rule: :unsupported_scheme, rfc: "8630#2.2", message: message}} =
             TAL.parse("http://x.example/ta.cer\n\nAAAA\n")

    assert message =~ "\"http\" is not rsync or https"
  end

  test "a missing file is an error" do
    assert TAL.decode_file("/nonexistent.tal") == {:error, :enoent}
  end

  defp spki(cert_der) do
    {:ok, cert} = Certificate.decode(cert_der)
    cert.public_key.der
  end
end
