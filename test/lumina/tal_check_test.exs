defmodule Lumina.TALCheckTest do
  @moduledoc """
  Tests checking a trust anchor certificate against its TAL (RFC 8630
  §2.3, §3; #56). Everything the validator trusts hangs off the TA, so a
  certificate must be refused if its key isn't the TAL's, if it isn't a
  self-signed CA, or if its resources are missing, empty or inherited.
  Signature and validity checks are M4.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, TAL}
  alias Mix.Lumina.Fixtures

  @root "test/fixtures/barry"

  defp tal!(id), do: elem(TAL.decode_file(Path.join([@root, id, "case.tal"])), 1)

  defp cert!(id, file \\ "ta.cer"),
    do: elem(Certificate.decode(File.read!(Path.join([@root, id, "rsync", file]))), 1)

  defp rules(tal, cert) do
    case TAL.check_ta(tal, cert) do
      :ok -> []
      {:error, problems} -> Enum.map(problems, & &1.rule)
    end
  end

  # A TAL carrying `cert`'s own key, so only the other checks can fail.
  defp tal_for(cert) do
    {:ok, tal} =
      TAL.parse("rsync://x.example/ta.cer\n\n" <> Base.encode64(cert.public_key.der) <> "\n")

    tal
  end

  # The m0 TA certificate, re-encoded with its extensions changed.
  defp ta_with(fun) do
    {:ok, raw} =
      Lumina.ASN1.decode(
        :pkix,
        :Certificate,
        File.read!(Path.join(@root, "m0-minimal-valid/rsync/ta.cer"))
      )

    {:ok, der} =
      Lumina.ASN1.encode(:pkix, :Certificate, update_in(raw.tbsCertificate.extensions, fun))

    {:ok, cert} = Certificate.decode(der)
    cert
  end

  defp replace_ext(exts, oid, value),
    do: Enum.map(exts, fn e -> if e.extnID == oid, do: %{e | extnValue: value}, else: e end)

  @ip {1, 3, 6, 1, 5, 5, 7, 1, 7}
  @as {1, 3, 6, 1, 5, 5, 7, 1, 8}

  @tag rfc: ["8630#2.3", "8630#3"]
  test "every Barry TA passes against its own TAL, except the ones built to fail" do
    for dir <- Fixtures.case_dirs(),
        id = Path.basename(dir),
        not String.starts_with?(id, "m2-ta-") do
      assert TAL.check_ta(tal!(id), cert!(id)) == :ok, id
    end
  end

  @tag rfc: ["8630#2.3", "3779#2.2.3.5", "6487#4.8.1"]
  test "the TA fixtures built to fail give exactly their problem" do
    assert rules(tal!("m2-ta-inherit"), cert!("m2-ta-inherit")) == [:inherit_resources]
    assert rules(tal!("m2-ta-empty-ip"), cert!("m2-ta-empty-ip")) == [:empty_resources]
    assert rules(tal!("m2-ta-not-ca"), cert!("m2-ta-not-ca")) == [:not_ca]
  end

  @tag rfc: ["8630#2.3", "8630#3"],
       doc:
         "Two well-formed TAs from different fixtures: only the key ties a certificate to its TAL."
  test "a TA certificate whose key isn't the TAL's is rejected" do
    assert rules(tal!("m0-minimal-valid"), cert!("m1-roa-prefixes")) == [:key_mismatch]
  end

  @tag rfc: ["8630#2.3", "6487#4.8.3"]
  test "a CA certificate that isn't self-issued can't be a TA, even with a matching TAL" do
    ca = cert!("m0-minimal-valid", "ta/ca1.cer")
    assert rules(tal_for(ca), ca) == [:not_self_issued, :aki_mismatch]
  end

  @tag rfc: ["8630#2.3", "6487#4.8.1"]
  test "an EE certificate can't be a TA" do
    {:ok, roa} =
      Lumina.ROA.decode(File.read!(Path.join(@root, "m0-minimal-valid/rsync/ca1/roa1.roa")))

    ee = Lumina.SignedObject.ee_certificate(roa.object)
    assert :not_ca in rules(tal_for(ee), ee)
    assert :not_self_issued in rules(tal_for(ee), ee)
  end

  describe "resources" do
    @tag rfc: "8630#2.3"
    test "an inherited AS number set is rejected" do
      {:ok, asn} = Lumina.ASN1.encode(:resources, :ASIdentifiers, %{asnum: {:inherit, :NULL}})
      ta = ta_with(&replace_ext(&1, @as, asn))
      assert rules(tal_for(ta), ta) == [:inherit_resources]
    end

    @tag rfc: "8630#2.3",
         doc:
           "Each present resource extension must hold resources (F-023); an empty AS extension fails even with IP resources."
    test "an AS extension with no identifiers is rejected" do
      {:ok, asn} = Lumina.ASN1.encode(:resources, :ASIdentifiers, %{})
      ta = ta_with(&replace_ext(&1, @as, asn))
      assert rules(tal_for(ta), ta) == [:empty_resources]
    end

    @tag rfc: ["8630#2.3", "6487#4.8.10", "6487#4.8.11"]
    test "a TA with no resource extensions at all is rejected" do
      ta = ta_with(fn exts -> Enum.reject(exts, &(&1.extnID in [@ip, @as])) end)
      assert rules(tal_for(ta), ta) == [:no_resources]
    end

    test "a resource extension that doesn't decode is reported, not ignored" do
      ta = ta_with(&replace_ext(&1, @ip, <<0x30, 0x03, 0x02, 0x01, 0x05>>))
      assert rules(tal_for(ta), ta) == [:malformed_resources]
    end
  end

  test "each problem names its rule, RFC section and reason" do
    {:error, [problem]} = TAL.check_ta(tal!("m2-ta-not-ca"), cert!("m2-ta-not-ca"))
    assert %{rule: :not_ca, rfc: "8630#2.3", message: message} = problem
    assert message =~ "not a CA certificate"
  end
end
