defmodule Lumina.PrintTest do
  @moduledoc """
  Tests the human-readable rendering behind `lumina print` (#34), full and
  `--brief` (D-001 in doc/decisions.md). Expected
  values come from the decoded structs, not hard-coded bytes, so
  regenerating a fixture (fresh keys) doesn't break the tests. The output
  must be stable: the same file always prints the same text.
  """
  use ExUnit.Case, async: true
  doctest Lumina.OID

  alias Lumina.{Certificate, Name, Object, Print, TAL}
  alias Lumina.Test.Fixture

  defp object!(fixture_id, file) do
    {:ok, object} = Object.decode_file(Path.join(Fixture.load!(fixture_id).rsync_root, file))
    object
  end

  defp hex(bytes),
    do:
      bytes
      |> Base.encode16(case: :lower)
      |> String.graphemes()
      |> Enum.chunk_every(2)
      |> Enum.map_join(":", &Enum.join/1)

  test "a CA certificate prints its fields, extensions and resources" do
    object = object!("m0-minimal-valid", "ta/ca1.cer")
    cert = object.value
    text = Print.render(object)

    assert text =~ "type: certificate (CA)\n"
    assert text =~ "version: 3\nserial: #{cert.serial}\n"
    assert text =~ "signature algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)\n"
    assert text =~ "subject: #{Name.to_string(cert.subject)}\n"
    assert text =~ "  not before: 2026-01-01T00:00:00Z\n  not after: 2036-01-01T00:00:00Z\n"
    assert text =~ "subject public key: rsaEncryption (1.2.840.113549.1.1.1), 2048-bit modulus\n"

    assert text =~
             "  subject key identifier: #{hex(Certificate.extension_value(cert, :subject_key_identifier))}\n"

    assert text =~ "  key usage (critical): keyCertSign, cRLSign\n"
    assert text =~ "    rpki manifest: rsync://localhost:8873/rpki/ca1/ca1.mft\n"
    assert text =~ "    policy: id-cp-ipAddr-asNumber (1.3.6.1.5.5.7.14.2)\n"
    assert text =~ "    IPv4: 1.0.0.0/8\n    IPv6: 100::/8\n"
    assert text =~ "    asnum: AS16777216-AS33554431\n"
    assert text =~ "signature: 256 bytes\n"
  end

  test "the TA certificate is marked self-issued" do
    assert Print.render(object!("m0-minimal-valid", "ta.cer")) =~
             "type: certificate (CA, self-issued)\n"
  end

  test "printing the same file twice gives identical text" do
    object = object!("m0-minimal-valid", "ca1/roa1.roa")
    assert Print.render(object) == Print.render(object)
  end

  test "a ROA prints its envelope, EE certificate and prefixes with max lengths" do
    text = Print.render(object!("m1-roa-prefixes", "ca1/roa1.roa"))

    assert text =~
             "type: roa (signed object)\ncontent type: routeOriginAuthz (1.2.840.113549.1.9.16.1.24)\n"

    assert text =~ "    signing time: 2026-01-01T00:00:00Z\n"
    assert text =~ "ee certificate:\n  type: certificate (EE)\n"
    assert text =~ "roa:\n  version: 0\n  as id: AS64496\n  prefixes:\n"

    assert text =~
             "    prefix: 1.1.0.0/17 max length 24\n    prefix: 1.1.128.0/24\n    prefix: 101::/16 max length 48\n"
  end

  test "a manifest prints its number, times and each file with its hash" do
    object = object!("m0-minimal-valid", "ca1/ca1.mft")
    text = Print.render(object)

    assert text =~ "manifest:\n  version: 0\n  manifest number: 1\n"
    assert text =~ "  file hash algorithm: sha256 (2.16.840.1.101.3.4.2.1)\n"

    for %{name: name, hash: hash} <- object.value.files do
      assert text =~ "    #{name}: #{hex(hash)}\n"
    end
  end

  test "a CRL prints its dates, revocations and CRL number" do
    text = Print.render(object!("m0-minimal-valid", "ca1/ca1.crl"))
    assert text =~ "type: crl\nversion: 2\n"

    assert text =~
             "this update: 2026-01-01T00:00:00Z\nnext update: 2036-01-01T00:00:00Z\nrevoked: none\n"

    assert text =~ "  crl number: 1\n"
  end

  @tag rfc: "6487#4.8"
  test "an unknown extension prints its OID, criticality and hex" do
    text = Print.render(object!("m1-cert-unknown-critical-extension", "ta/ca1.cer"))

    assert text =~
             ~r/  1\.3\.6\.1\.4\.1\.99999\.1 \(critical\): unknown extension, \d+ bytes: [0-9a-f:]+\n/
  end

  test "inherited resources print as inherit" do
    text = Print.render(object!("m1-resources-inherit", "ca1/ca2.cer"))
    assert text =~ "    IPv4: inherit\n    IPv6: inherit\n"
    assert text =~ "    asnum: inherit\n"
  end

  test "profile violations print like anything else" do
    assert Print.render(object!("m1-cert-version-2", "ta/ca1.cer")) =~ "version: 2\n"
    assert Print.render(object!("m1-roa-version-2", "ca1/roa1.roa")) =~ "roa:\n  version: 2\n"
  end

  test "a signed object whose eContent isn't decoded yet prints its envelope and size" do
    object = object!("m0-minimal-valid", "ca1/roa1.roa")
    gbr = %Object{object | type: :ghostbusters, value: object.value.object}
    assert Print.render(gbr) =~ ~r/econtent: \d+ bytes, not decoded yet \(M9\)\n/
  end

  describe "brief" do
    test "a brief certificate keeps names, validity, URIs and resources, and drops crypto detail" do
      object = object!("m0-minimal-valid", "ta/ca1.cer")
      text = Print.render(object, brief: true)

      assert text =~ "type: certificate (CA)\nversion: 3\nserial: #{object.value.serial}\n"
      assert text =~ "  not before: 2026-01-01T00:00:00Z\n"
      assert text =~ "    rpki manifest: rsync://localhost:8873/rpki/ca1/ca1.mft\n"
      assert text =~ "    IPv4: 1.0.0.0/8\n"

      for crypto <- [
            "signature",
            "public key",
            "key identifier",
            "key usage",
            "policy",
            "basic constraints"
          ] do
        refute text =~ crypto, "brief output contains #{crypto}"
      end
    end

    test "a brief manifest lists file names without hashes" do
      object = object!("m0-minimal-valid", "ca1/ca1.mft")
      text = Print.render(object, brief: true)

      assert text =~ "  manifest number: 1\n"

      for %{name: name, hash: hash} <- object.value.files do
        assert text =~ "    file: #{name}\n"
        refute text =~ hex(hash)
      end

      refute text =~ "file hash algorithm"
      refute text =~ "message digest"
    end

    test "a brief ROA keeps the signing time, EE validity and prefixes" do
      text = Print.render(object!("m1-roa-prefixes", "ca1/roa1.roa"), brief: true)

      assert text =~
               "type: roa (signed object)\nsigning time: 2026-01-01T00:00:00Z\nee certificate validity:\n"

      assert text =~ "    prefix: 1.1.0.0/17 max length 24\n"
      refute text =~ "signer"
    end

    test "a brief CRL keeps issuer, dates, number and revocations" do
      text = Print.render(object!("m0-minimal-valid", "ca1/ca1.crl"), brief: true)

      assert text =~
               "this update: 2026-01-01T00:00:00Z\nnext update: 2036-01-01T00:00:00Z\ncrl number: 1\nrevoked: none\n"

      refute text =~ "authority key identifier"
    end

    @tag rfc: "6487#4.8"
    test "brief still shows unknown extensions, without their bytes" do
      text =
        Print.render(object!("m1-cert-unknown-critical-extension", "ta/ca1.cer"), brief: true)

      assert text =~ "  1.3.6.1.4.1.99999.1 (critical): unknown extension\n"
    end

    test "inherit is kept in brief output" do
      assert Print.render(object!("m1-resources-inherit", "ca1/ca2.cer"), brief: true) =~
               "    IPv4: inherit\n"
    end
  end

  describe "TALs (#59)" do
    @rfc_example "test/fixtures/tals/cases/valid-rfc-8630-example/case.tal"

    @tag rfc: "8630#2.3"
    @tag doc: """
         The printed SKI is the one `check_ta/2` compares, so it must match the
         TA certificate Barry generated for the same key (RFC 6487 §4.8.2).
         """
    test "a Barry TAL prints its URIs and the SKI its TA certificate actually carries" do
      fixture = Fixture.load!("m0-minimal-valid")
      {:ok, tal} = TAL.decode_file(fixture.tal_path)
      {:ok, ta} = Object.decode_file(Path.join(fixture.rsync_root, "ta.cer"))
      text = Print.render(tal)

      for uri <- tal.uris, do: assert(text =~ "  uri: #{uri}\n")

      assert text =~
               "expected ta subject key identifier: #{hex(Certificate.extension_value(ta.value, :subject_key_identifier))}\n"
    end

    @tag rfc: "8630#2.4"
    @tag doc: """
         The whole printout is pinned, so a change to the layout is deliberate.
         The preference order follows D-003: HTTPS first, though the TAL lists
         rsync first.
         """
    test "the RFC 8630 example prints in full" do
      {:ok, tal} = TAL.decode_file(@rfc_example)

      assert Print.render(tal) == """
             type: tal
             comments:
               comment: # This TAL is intended for documentation purposes only.
               comment: # Do not attempt to use this in a production setting.
             uris:
               uri: rsync://rpki.example.org/rpki/hedgehog/root.cer
               uri: https://rpki.example.org/rpki/hedgehog/root.cer
             preference order:
               1: https://rpki.example.org/rpki/hedgehog/root.cer
               2: rsync://rpki.example.org/rpki/hedgehog/root.cer
             subject public key: rsaEncryption (1.2.840.113549.1.1.1), 2048-bit modulus
             expected ta subject key identifier: #{hex(TAL.subject_key_identifier(tal))}
             warnings: none
             """
    end

    @tag rfc: "8630#2.4"
    test "brief leaves out the key and keeps the comments, URIs and SKI" do
      {:ok, tal} = TAL.decode_file(@rfc_example)
      brief = Print.render(tal, brief: true)

      assert brief == String.replace(Print.render(tal), ~r/^subject public key: .*\n/m, "")
      assert brief =~ "comment: # This TAL is intended"
      assert brief =~ "expected ta subject key identifier: "
    end

    @tag rfc: "8630#2.2"
    @tag doc: "Warnings (D-002) are kept in brief output: they say the file isn't clean."
    test "parser warnings print with their line numbers" do
      {:ok, tal} =
        TAL.decode_file("test/fixtures/tals/cases/warning-trailing-whitespace/case.tal")

      assert Print.render(tal, brief: true) =~
               "warnings:\n  line 1: trailing whitespace ignored (trailing_whitespace)\n" <>
                 "  line 2: trailing whitespace ignored (trailing_whitespace)\n" <>
                 "  line 4: trailing whitespace ignored (trailing_whitespace)\n"
    end

    @tag rfc: "8630#2.2"
    test "a TAL parse error names the line, the rule and the RFC section" do
      {:error, finding} =
        TAL.decode_file("test/fixtures/tals/cases/invalid-two-blank-lines/case.tal")

      assert Print.error(finding, "case.tal") ==
               "TAL line 3: #{finding.message} (extra_blank_line, RFC 8630 §2.2)"
    end
  end

  describe "error/2" do
    test "names the layer for each kind of failure" do
      assert Print.error(
               {:der,
                %{
                  rule: :trailing_bytes,
                  clause: "X.690 8.1.1",
                  offset: 7,
                  message: "1 byte(s) after the encoding"
                }},
               "a.cer"
             ) ==
               "DER layer: 1 byte(s) after the encoding (trailing_bytes, X.690 8.1.1, byte offset 7)"

      assert Print.error({:asn1, :bad}, "a.cer") =~ "ASN.1 layer:"

      assert Print.error({:invalid_time, "x"}, "a.cer") =~
               "ASN.1 layer: \"x\" is not a valid time"

      assert Print.error({:envelope, :bad}, "a.roa") =~ "envelope layer:"
      assert Print.error({:econtent, :bad}, "a.roa") =~ "eContent layer:"

      assert Print.error(
               {:content_type_mismatch, %{extension: :roa, content_type: :manifest}},
               "a.roa"
             ) ==
               "type: the file extension says roa, but the eContent type is manifest"

      assert Print.error(:unknown_type, "a.txt") ==
               "type: \".txt\" is not a registered RPKI file extension"

      assert Print.error(:enoent, "a.cer") == "file: no such file or directory"
    end
  end
end
