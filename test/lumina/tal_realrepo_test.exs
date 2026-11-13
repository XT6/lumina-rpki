defmodule Lumina.TALRealRepoTest do
  @moduledoc """
  Checks the LACNIC TAL against the LACNIC TA certificate in the
  maintainer's local copy of the LACNIC repository, `test/realrepos/`
  (#58). That copy is git-ignored and only current until its objects
  expire. These tests are tagged `:realrepo` and excluded when the copy
  isn't present (`test/test_helper.exs`). `check_ta/2` doesn't look at
  validity dates (M4), so the check stays meaningful after expiry.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, TAL}

  @moduletag :realrepo

  @ta_cert "test/realrepos/repo-lacnic/lacnic/rta-lacnic-rpki.cer"

  defp tal!(file) do
    {:ok, tal} = TAL.decode_file(Path.join("test/fixtures/tals/rir", file))
    tal
  end

  defp ta_cert! do
    {:ok, cert} = Certificate.decode(File.read!(@ta_cert))
    cert
  end

  @tag rfc: "8630#2.3"
  @tag doc: "The real LACNIC TA certificate, fetched by rsync, matches LACNIC's published TAL."
  test "the LACNIC TA certificate matches the LACNIC TAL" do
    assert TAL.check_ta(tal!("lacnic.tal"), ta_cert!()) == :ok
  end

  @tag rfc: "8630#2.3"
  @tag doc: "A real TA certificate against another RIR's TAL: the key check must catch it."
  test "the LACNIC TA certificate doesn't match the ARIN TAL" do
    assert {:error, problems} = TAL.check_ta(tal!("arin.tal"), ta_cert!())
    assert Enum.map(problems, & &1.rule) == [:key_mismatch]
  end
end
