defmodule Lumina.DERTest do
  @moduledoc """
  Tests strict DER checking. RPKI requires DER (RFC 6488 §3 (l), RFC 6481
  §2.2), but OTP's decoders accept BER, so every DER rule is checked here:
  for each one, a minimal hand-built violation must be rejected with the
  right rule and X.690 clause, and its valid counterpart accepted. X.690
  isn't in doc/rfc, so its clauses are cited in each test's doc tag.
  """
  use ExUnit.Case, async: true
  doctest Lumina.DER

  alias Lumina.DER
  alias Lumina.Test.Fixture

  @fixture Fixture.load!("m0-minimal-valid")

  defp assert_rule(der, rule, clause) do
    assert {:error, %{rule: ^rule, clause: ^clause, offset: offset, message: message}} =
             DER.check(der)

    assert is_integer(offset) and is_binary(message)
    offset
  end

  # A DER SEQUENCE around `contents`.
  defp seq(contents), do: <<0x30>> <> der_length(byte_size(contents)) <> contents
  defp der_length(n) when n < 128, do: <<n>>

  defp der_length(n),
    do: (bytes = :binary.encode_unsigned(n)) && <<0x80 + byte_size(bytes)>> <> bytes

  describe "length octets" do
    @tag doc: "X.690 10.1: DER uses the definite form only."
    test "rejects indefinite length" do
      assert DER.check(<<0x30, 0x03, 0x02, 0x01, 0x05>>) == :ok
      assert_rule(<<0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00>>, :indefinite_length, "X.690 10.1")
    end

    @tag doc: "X.690 10.1: lengths below 128 must use the one-octet short form."
    test "rejects the long form for a short length" do
      assert_rule(<<0x02, 0x81, 0x01, 0x05>>, :non_minimal_length, "X.690 10.1")
    end

    @tag doc: "X.690 10.1: minimum number of octets, so no leading zero length octet."
    test "rejects a long-form length with a leading zero octet" do
      long = :binary.copy(<<0x41>>, 200)
      assert DER.check(<<0x04, 0x81, 200>> <> long) == :ok
      assert_rule(<<0x04, 0x82, 0x00, 200>> <> long, :non_minimal_length, "X.690 10.1")
    end

    @tag doc: "X.690 8.1.3.5: the first length octet 0xFF is reserved."
    test "rejects the reserved length octet" do
      assert_rule(<<0x04, 0xFF>>, :invalid_length, "X.690 8.1.3.5")
    end

    test "rejects truncated input at every layer" do
      assert_rule(<<>>, :truncated, "X.690 8.1.2")
      assert_rule(<<0x02>>, :truncated, "X.690 8.1.3")
      assert_rule(<<0x04, 0x82, 0x01>>, :truncated, "X.690 8.1.3")
      assert_rule(<<0x04, 0x05, 0x41, 0x41>>, :truncated, "X.690 8.1.3")
      assert_rule(<<0x1F, 0x81>>, :truncated, "X.690 8.1.2.4")
    end
  end

  describe "identifier octets" do
    @tag doc: "X.690 8.1.2.2: tag numbers 0-30 use the single-octet form."
    test "rejects the high-tag-number form for a low tag number" do
      assert DER.check(<<0x9F, 0x1F, 0x00>>) == :ok
      assert_rule(<<0x9F, 0x05, 0x00>>, :non_minimal_tag, "X.690 8.1.2.2")
    end

    @tag doc: "X.690 8.1.2.4.2: the first subsequent tag octet must not be 0x80."
    test "rejects a high tag number with a leading 0x80 octet" do
      assert_rule(<<0x9F, 0x80, 0x1F, 0x00>>, :non_minimal_tag, "X.690 8.1.2.4.2")
    end

    @tag doc:
           "X.690 8.1.5: end-of-contents octets only close indefinite lengths, which DER forbids."
    test "rejects end-of-contents octets" do
      assert_rule(<<0x00, 0x00>>, :end_of_contents, "X.690 10.1")
    end
  end

  describe "primitive and constructed forms" do
    @tag doc: "X.690 10.2: BIT STRING, OCTET STRING and character strings must be primitive."
    test "rejects a constructed OCTET STRING" do
      assert DER.check(<<0x04, 0x02, 0x41, 0x42>>) == :ok
      assert_rule(<<0x24, 0x04, 0x04, 0x02, 0x41, 0x42>>, :constructed_form, "X.690 10.2")
    end

    @tag doc: "X.690 8.9.1 and 8.11.1: SEQUENCE and SET encodings are constructed."
    test "rejects a primitive SEQUENCE" do
      assert_rule(<<0x10, 0x00>>, :primitive_form, "X.690 8.9.1, 8.11.1")
    end
  end

  describe "universal types" do
    @tag doc: "X.690 11.1: TRUE is 0xFF; X.690 8.2.1: exactly one contents octet."
    test "BOOLEAN" do
      assert DER.check(<<0x01, 0x01, 0xFF>>) == :ok
      assert DER.check(<<0x01, 0x01, 0x00>>) == :ok
      assert_rule(<<0x01, 0x01, 0x01>>, :boolean_value, "X.690 11.1")
      assert_rule(<<0x01, 0x02, 0xFF, 0xFF>>, :boolean_length, "X.690 8.2.1")
    end

    @tag doc: "X.690 8.3.1 and 8.3.2: at least one octet, minimal two's complement."
    test "INTEGER" do
      for ok <- [<<0x02, 0x01, 0x00>>, <<0x02, 0x02, 0x00, 0x80>>, <<0x02, 0x02, 0xFF, 0x7F>>] do
        assert DER.check(ok) == :ok
      end

      assert_rule(<<0x02, 0x00>>, :empty_integer, "X.690 8.3.1")
      assert_rule(<<0x02, 0x02, 0x00, 0x7F>>, :non_minimal_integer, "X.690 8.3.2")
      assert_rule(<<0x02, 0x02, 0xFF, 0x80>>, :non_minimal_integer, "X.690 8.3.2")
    end

    @tag doc:
           "X.690 8.6.2.2-8.6.2.3: unused-bits octet 0-7, and 0 when empty; X.690 11.2.1: unused bits are zero."
    test "BIT STRING" do
      assert DER.check(<<0x03, 0x01, 0x00>>) == :ok
      assert DER.check(<<0x03, 0x02, 0x04, 0xF0>>) == :ok
      assert_rule(<<0x03, 0x00>>, :empty_bit_string, "X.690 8.6.2")
      assert_rule(<<0x03, 0x02, 0x08, 0x00>>, :bit_string_unused, "X.690 8.6.2.2")
      assert_rule(<<0x03, 0x01, 0x03>>, :bit_string_unused, "X.690 8.6.2.3")
      assert_rule(<<0x03, 0x02, 0x04, 0xF1>>, :bit_string_padding, "X.690 11.2.1")
    end

    @tag doc: "X.690 8.8.2: NULL has no contents."
    test "NULL" do
      assert DER.check(<<0x05, 0x00>>) == :ok
      assert_rule(<<0x05, 0x01, 0x00>>, :null_length, "X.690 8.8.2")
    end

    @tag doc:
           "X.690 8.19.2: subidentifiers are minimal (no leading 0x80) and the last one terminates."
    test "OBJECT IDENTIFIER" do
      # 1.2.840.113549
      assert DER.check(<<0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D>>) == :ok
      assert_rule(<<0x06, 0x00>>, :empty_oid, "X.690 8.19.2")
      assert_rule(<<0x06, 0x02, 0x2A, 0x86>>, :truncated_oid, "X.690 8.19.2")
      assert_rule(<<0x06, 0x03, 0x2A, 0x80, 0x01>>, :non_minimal_oid, "X.690 8.19.2")
    end

    @tag doc: "X.690 11.8: UTCTime is YYMMDDHHMMSSZ, seconds present, Z, no offset."
    test "UTCTime" do
      assert DER.check(<<0x17, 13>> <> "260101000000Z") == :ok

      for bad <- ["2601010000Z", "260101000000", "260101000000+0100", "26010100000aZ"] do
        assert_rule(<<0x17, byte_size(bad)>> <> bad, :utc_time_format, "X.690 11.8")
      end
    end

    @tag doc:
           "X.690 11.7: GeneralizedTime ends in Z with seconds; fractional seconds don't end in 0."
    test "GeneralizedTime" do
      for ok <- ["20360101000000Z", "20360101000000.5Z"] do
        assert DER.check(<<0x18, byte_size(ok)>> <> ok) == :ok
      end

      for bad <- ["203601010000Z", "20360101000000", "20360101000000.Z"] do
        assert_rule(<<0x18, byte_size(bad)>> <> bad, :generalized_time_format, "X.690 11.7")
      end

      bad = "20360101000000.50Z"
      assert_rule(<<0x18, byte_size(bad)>> <> bad, :generalized_time_fraction, "X.690 11.7.3")
    end

    @tag doc: "X.690 11.6: SET OF elements in ascending order of their encodings."
    test "SET OF must be sorted" do
      assert DER.check(<<0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02>>) == :ok

      offset =
        assert_rule(
          <<0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01>>,
          :set_of_order,
          "X.690 11.6"
        )

      assert offset == 5
    end
  end

  describe "structure" do
    @tag doc: """
         X.690 8.1.1: an encoding is one TLV. RFC 6481 §2.2 and RFC 6488 §3 don't
         say what follows it; Lumina rejects anything (F-010 in doc/rfc-findings.md).
         """
    test "rejects trailing bytes after the encoding" do
      offset = assert_rule(<<0x02, 0x01, 0x05, 0x00>>, :trailing_bytes, "X.690 8.1.1")
      assert offset == 3
    end

    test "checks inside constructed values of any class, and reports the inner offset" do
      inner_bad = <<0xA0, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01>>
      offset = assert_rule(seq(inner_bad), :boolean_value, "X.690 11.1")
      assert offset == 2 + 5 + 2
    end
  end

  @tag doc: """
       Seeded, so the inputs are the same every run. Repository content is
       untrusted, so the checker must return an error, never raise. This
       test found a crash on an empty BIT STRING.
       """
  test "never raises on random bytes or random mutations of a real object" do
    :rand.seed(:exsss, {25, 25, 25})
    ta = File.read!(Path.join(@fixture.rsync_root, "ta.cer"))

    for _ <- 1..3000 do
      random = :rand.bytes(:rand.uniform(48))
      position = :rand.uniform(byte_size(ta)) - 1
      <<before::binary-size(^position), _, rest::binary>> = ta
      mutated = before <> <<:rand.uniform(256) - 1>> <> rest

      for input <- [random, mutated] do
        assert DER.check(input) in [:ok] or match?({:error, %{rule: _}}, DER.check(input))
      end
    end
  end

  describe "fixtures" do
    @tag rfc: ["6488#3", "6481#2.2"]
    test "every object in m0-minimal-valid is DER" do
      for path <- Path.wildcard(Path.join(@fixture.rsync_root, "**/*.{cer,crl,mft,roa}")) do
        assert DER.check(File.read!(path)) == :ok, path
      end
    end

    @tag rfc: ["6488#3", "6481#2.2"]
    test "certificates and CRLs re-encode to identical bytes" do
      for {file, type} <- [
            {"ta.cer", :Certificate},
            {"ta/ca1.cer", :Certificate},
            {"ta/ta.crl", :CertificateList}
          ] do
        assert DER.check_canonical(:pkix, type, File.read!(Path.join(@fixture.rsync_root, file))) ==
                 :ok,
               file
      end
    end
  end

  describe "check_canonical/3" do
    @tag rfc: "9286#A",
         doc: """
         X.690 11.5: a component equal to its DEFAULT is not encoded. A manifest
         with an explicit `version [0] INTEGER 0` passes the TLV walk, since every
         TLV is well formed, but isn't DER. Only re-encoding catches it.
         """
    test "rejects an encoded DEFAULT value that a TLV walk can't see" do
      {:ok, %{content: signed_data}} =
        Lumina.ASN1.decode(
          :cms,
          :ContentInfo,
          File.read!(Path.join(@fixture.rsync_root, "ca1/ca1.mft"))
        )

      {:ok, %{encapContentInfo: %{eContent: econtent}}} =
        Lumina.ASN1.decode(:cms, :SignedData, signed_data)

      assert DER.check_canonical(:manifest, :Manifest, econtent) == :ok

      contents = strip_header(econtent)
      with_default = seq(<<0xA0, 0x03, 0x02, 0x01, 0x00>> <> contents)

      assert DER.check(with_default) == :ok

      assert {:error, %{rule: :not_canonical}} =
               DER.check_canonical(:manifest, :Manifest, with_default)
    end

    test "passes on decoding errors from the ASN.1 layer" do
      assert {:error, {:asn1, _}} = DER.check_canonical(:pkix, :Certificate, <<0x30, 0x00>>)
    end
  end

  defp strip_header(<<0x30, n, rest::binary>>) when n < 128, do: rest
  defp strip_header(<<0x30, 0x81, _, rest::binary>>), do: rest
  defp strip_header(<<0x30, 0x82, _, _, rest::binary>>), do: rest
end
